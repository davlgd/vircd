module server

import crypto.scram
import encoding.base64
import ircmsg
import store

// max_sasl_bytes bounds the decoded size of one SASL message.
const max_sasl_bytes = 8192
// max_sasl_failures is how many failed attempts a connection gets.
const max_sasl_failures = 5
// max_auth_queue bounds the PLAIN checks waiting for a worker.
const max_auth_queue = 256

// AuthBinding is the account whose verifier an exchange checks: its permanent
// id and the exact credentials record. The login is granted to that record
// only, and only if it is still current when the exchange succeeds.
@[heap]
struct AuthBinding {
mut:
	id          int
	name        string
	credentials string
}

// AuthJob is a PLAIN password check waiting for a worker.
struct AuthJob {
	id          int
	account     string
	account_id  int
	credentials scram.Credentials
	password    string
}

fn (mut s Server) cmd_authenticate(mut c Client, msg ircmsg.Message) {
	arg := msg.param(0)
	if arg == '' {
		s.numeric(mut c, err_needmoreparams, 'AUTHENTICATE', 'Not enough parameters')
		return
	}
	if c.account != '' {
		s.numeric(mut c, err_saslalready, 'You have already authenticated using SASL')
		return
	}
	if arg == '*' {
		if c.sasl_mech != '' {
			s.sasl_reset(mut c)
			s.numeric(mut c, err_saslaborted, 'SASL authentication aborted')
		} else {
			s.numeric(mut c, err_saslfail, 'SASL authentication failed')
		}
		return
	}
	if c.sasl_mech == '' {
		mech := arg.to_upper()
		if mech !in ['PLAIN', 'SCRAM-SHA-256'] {
			s.numeric(mut c, rpl_saslmechs, sasl_mechanisms, 'are available SASL mechanisms')
			s.numeric(mut c, err_saslfail, 'SASL authentication failed')
			return
		}
		c.sasl_mech = mech
		c.sasl_buffer = ''
		s.send(mut c, ircmsg.Message{
			source:  s.cfg.name
			command: 'AUTHENTICATE'
			params:  ['+']
		})
		return
	}
	if arg.len > 400 {
		s.sasl_reset(mut c)
		s.numeric(mut c, err_sasltoolong, 'SASL message too long')
		return
	}
	if arg != '+' {
		c.sasl_buffer += arg
		if c.sasl_buffer.len > max_sasl_bytes * 4 / 3 + 4 {
			// ERR_SASLTOOLONG is for one oversized line; a payload that keeps
			// growing is a failed attempt.
			s.sasl_failed(mut c)
			return
		}
		if arg.len == 400 {
			// More chunks follow.
			return
		}
	}
	encoded := c.sasl_buffer
	c.sasl_buffer = ''
	data := if encoded == '' {
		''
	} else {
		decode_base64(encoded) or {
			s.sasl_failed(mut c)
			return
		}
	}
	match c.sasl_mech {
		'PLAIN' { s.sasl_plain(mut c, data) }
		else { s.sasl_scram_step(mut c, data) }
	}
}

// decode_base64 decodes strict, padded base64.
fn decode_base64(s string) !string {
	if s.len % 4 != 0 {
		return error('bad base64 length')
	}
	for ch in s {
		if !(ch.is_letter() || ch.is_digit() || ch in [`+`, `/`, `=`]) {
			return error('bad base64')
		}
	}
	decoded := base64.decode_str(s)
	if base64.encode_str(decoded) != s {
		return error('non-canonical base64')
	}
	return decoded
}

fn (mut s Server) sasl_reset(mut c Client) {
	c.sasl_mech = ''
	c.sasl_buffer = ''
	c.sasl_scram = unsafe { nil }
	c.sasl_binding = unsafe { nil }
}

fn (mut s Server) sasl_failed(mut c Client) {
	s.sasl_reset(mut c)
	s.numeric(mut c, err_saslfail, 'SASL authentication failed')
	c.sasl_failures++
	if c.sasl_failures >= max_sasl_failures {
		s.kill(mut c, 'Too many failed SASL attempts')
	}
}

// sasl_plain checks `authzid NUL authcid NUL password` (RFC 4616). The password
// check runs in a worker thread; the client's later lines wait for its result.
fn (mut s Server) sasl_plain(mut c Client, data string) {
	if !c.tls && !s.loopback && !s.cfg.allow_plaintext_auth {
		s.sasl_reset(mut c)
		s.fail(mut c, 'AUTHENTICATE', 'TLS_REQUIRED', 'PLAIN needs a TLS connection')
		s.numeric(mut c, err_saslfail, 'SASL authentication failed')
		return
	}
	parts := data.split('\x00')
	if parts.len != 3 || parts[1] == '' || parts[2] == '' {
		s.sasl_failed(mut c)
		return
	}
	authzid, authcid, password := parts[0], parts[1], parts[2]
	if authzid != '' && s.fold(authzid) != s.fold(authcid) {
		s.sasl_failed(mut c)
		return
	}
	mut job := AuthJob{
		id:          c.id
		credentials: s.db.dummy_credentials(casemapping.fold(authcid))
		password:    password
	}
	if acct := find_login(mut s.db, authcid) {
		job = AuthJob{
			...job
			account:     acct.name
			account_id:  acct.id
			credentials: acct.credentials
		}
	}
	if s.auth_queue.len >= max_auth_queue {
		s.sasl_failed(mut c)
		return
	}
	c.auth_pending = true
	s.auth_queue << job
	s.start_auth_jobs()
}

fn (mut s Server) start_auth_jobs() {
	for s.auth_busy < s.cfg.auth_workers && s.auth_queue.len > 0 {
		job := s.auth_queue[0]
		s.auth_queue.delete(0)
		s.auth_busy++
		spawn auth_worker(job, s.events)
	}
}

fn auth_worker(job AuthJob, events chan Event) {
	ok := store.check_password(job.credentials, job.password) && job.account != ''
	events <- Event{
		kind:        .auth_done
		id:          job.id
		line:        job.account
		auth_ok:     ok
		account_id:  job.account_id
		credentials: job.credentials.encode()
	}
}

// find_login returns the account a SASL username names, if any. Database errors
// count as unknown accounts: the login then fails like a wrong password.
fn find_login(mut db store.Store, username string) ?store.Account {
	if !store.valid_account_name(username) {
		return none
	}
	return db.find_account(casemapping.fold(username)) or { none }
}

// still_current reports whether account `id` still exists with exactly the
// credentials that were verified (no removal, recreation or password change
// happened during the exchange). Database errors count as no.
fn (mut s Server) still_current(id int, credentials string) bool {
	acct := s.db.account_by_id(id) or { return false }
	return acct.credentials.encode() == credentials
}

fn (mut s Server) on_auth_done(ev Event) {
	s.auth_busy--
	s.start_auth_jobs()
	mut c := s.clients[ev.id] or { return }
	c.auth_pending = false
	if !c.dead {
		if ev.auth_ok && s.still_current(ev.account_id, ev.credentials) {
			s.sasl_success(mut c, ev.line, ev.account_id)
		} else {
			s.sasl_failed(mut c)
		}
	}
	// Replay the lines that arrived during the check, in order, until another
	// check starts.
	for c.pending.len > 0 && !c.auth_pending && !c.dead {
		line := c.pending[0]
		c.pending.delete(0)
		s.handle_line(mut c, line)
	}
	s.try_register(mut c)
	s.reap()
}

fn (mut s Server) sasl_success(mut c Client, account string, account_id int) {
	s.sasl_reset(mut c)
	// A registered client takes its account name as nickname; registration
	// does it for the others (settle_nick).
	rename := c.registered && s.cfg.force_nick_account && s.fold(c.nick) != s.fold(account)
	if rename {
		if refusal := s.claim_account_nick(mut c, account, account_id) {
			s.numeric(mut c, err_saslfail, 'SASL authentication failed: ${refusal.text}')
			return
		}
	}
	c.account = account
	c.account_id = account_id
	mask := if c.nick == '' { '*' } else { c.mask() }
	s.numeric(mut c, rpl_loggedin, mask, account, 'You are now logged in as ${account}')
	s.numeric(mut c, rpl_saslsuccess, 'SASL authentication successful')
	if c.registered {
		s.send_to_peers(c, s.user_msg(c, 'ACCOUNT', [account]), false, 'account-notify')
		s.send_stored_markers(mut c)
	}
	if rename {
		s.change_nick(mut c, account)
	}
}

// sasl_scram_step runs one step of SCRAM-SHA-256 (RFC 7677). The server side
// needs no key derivation, so it runs on the dispatcher.
fn (mut s Server) sasl_scram_step(mut c Client, data string) {
	if c.sasl_scram == unsafe { nil } {
		mut db := s.db
		mut binding := &AuthBinding{}
		c.sasl_binding = binding
		c.sasl_scram = scram.new_server(
			mechanism: .sha256
			lookup:    fn [mut db, mut binding] (username string) !scram.Credentials {
				if acct := find_login(mut db, username) {
					binding.id = acct.id
					binding.name = acct.name
					binding.credentials = acct.credentials.encode()
					return acct.credentials
				}
				// Unknown accounts go through the whole exchange and fail at the end,
				// so that they cannot be told from wrong passwords.
				return db.dummy_credentials(casemapping.fold(username))
			}
		) or {
			s.sasl_failed(mut c)
			return
		}
		reply := c.sasl_scram.first(data) or {
			s.sasl_failed(mut c)
			return
		}
		if c.sasl_scram.authzid() != ''
			&& s.fold(c.sasl_scram.authzid()) != s.fold(c.sasl_scram.username()) {
			s.sasl_failed(mut c)
			return
		}
		s.send_authenticate(mut c, reply)
		return
	}
	if !c.sasl_scram.done() {
		reply := c.sasl_scram.final(data) or {
			s.sasl_failed(mut c)
			return
		}
		// The proof matched the credentials the lookup bound: dummy credentials
		// cannot be matched, so the binding names a real account.
		if c.sasl_binding == unsafe { nil } || c.sasl_binding.id == 0 {
			s.sasl_failed(mut c)
			return
		}
		s.send_authenticate(mut c, reply)
		return
	}
	// The client acknowledged the server signature with an empty message.
	b := c.sasl_binding
	if data != '' || b == unsafe { nil } || !s.still_current(b.id, b.credentials) {
		s.sasl_failed(mut c)
		return
	}
	s.sasl_success(mut c, b.name, b.id)
}

// send_authenticate sends a SASL payload in base64, in 400-byte chunks, with a
// final `+` when the last chunk is exactly 400 bytes.
fn (mut s Server) send_authenticate(mut c Client, payload string) {
	encoded := base64.encode_str(payload)
	mut i := 0
	for i < encoded.len {
		end := if i + 400 < encoded.len { i + 400 } else { encoded.len }
		s.send(mut c, ircmsg.Message{
			source:  s.cfg.name
			command: 'AUTHENTICATE'
			params:  [encoded[i..end]]
		})
		i = end
	}
	if encoded.len % 400 == 0 {
		s.send(mut c, ircmsg.Message{
			source:  s.cfg.name
			command: 'AUTHENTICATE'
			params:  ['+']
		})
	}
}
