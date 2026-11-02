module server

import store

// Nickname ownership: an account name is reserved for its account, and with
// `force_nick_account` a logged-in client must use its account name.

// NickRefusal is the numeric reply refusing a nickname.
struct NickRefusal {
	code string
	text string
}

// nick_refusal reports why client `c` may not use `nick`, if it may not. A
// database error refuses the nickname: a reservation that cannot be checked is
// not granted.
fn (mut s Server) nick_refusal(c &Client, nick string) ?NickRefusal {
	if s.cfg.force_nick_account && c.account != '' && s.fold(nick) != s.fold(c.account) {
		return NickRefusal{err_erroneusnickname, 'You must use your account name as your nickname'}
	}
	acct := s.db.find_account(s.fold(nick)) or {
		if err is store.NotFoundError {
			return none
		}
		return NickRefusal{err_nicknameinuse, 'Cannot check the nickname reservation, try again later'}
	}
	if c.account == '' || acct.id != c.account_id {
		return NickRefusal{err_nicknameinuse, 'Nickname is reserved by a different account'}
	}
	return none
}

// set_nick gives `nick` to an unregistered client.
fn (mut s Server) set_nick(mut c Client, nick string) {
	s.release_nick(mut c)
	s.nicks[s.fold(nick)] = c.id
	c.nick = nick
}

// release_nick takes its nickname from an unregistered client.
fn (mut s Server) release_nick(mut c Client) {
	if c.nick != '' {
		key := s.fold(c.nick)
		if s.nicks[key] or { 0 } == c.id {
			s.nicks.delete(key)
		}
	}
	c.nick = ''
}

// change_nick renames a registered client and tells everyone who sees it.
fn (mut s Server) change_nick(mut c Client, nick string) {
	old := c.nick
	old_key := s.fold(old)
	key := s.fold(nick)
	change := s.user_msg(c, 'NICK', [nick])
	s.add_whowas(c)
	if s.nicks[old_key] or { 0 } == c.id {
		s.nicks.delete(old_key)
	}
	s.nicks[key] = c.id
	c.nick = nick
	s.send_to_peers(c, change, true, '')
	if old_key != key {
		s.notify_monitors(old, false, c)
		s.notify_monitors(nick, true, c)
	}
}

// settle_nick applies the nickname rules when an unregistered client is about
// to complete its registration. It reports whether registration may go on: if
// not, the client either was told to choose another nickname or was killed.
fn (mut s Server) settle_nick(mut c Client) bool {
	if s.cfg.force_nick_account && c.account != '' && s.fold(c.nick) != s.fold(c.account) {
		if refusal := s.claim_account_nick(mut c, c.account, c.account_id) {
			// A logged-in client may use no other nickname.
			s.numeric(mut c, refusal.code, c.account, refusal.text)
			s.kill(mut c, refusal.text)
			return false
		}
		s.set_nick(mut c, c.account)
		return true
	}
	if refusal := s.nick_refusal(c, c.nick) {
		nick := c.nick
		s.release_nick(mut c)
		s.numeric(mut c, refusal.code, nick, refusal.text)
		return false
	}
	return true
}

// claim_account_nick makes the name of account `account_id` available to
// client `c`, or reports why it cannot. The account must still exist under
// that name with that id. A client holding the name without being logged in to
// the account (it took the name before the account was created, or has not
// registered yet) loses it; a session of the same account keeps it. Nothing
// changes unless the claim succeeds.
fn (mut s Server) claim_account_nick(mut c Client, account string, account_id int) ?NickRefusal {
	acct := s.db.find_account(s.fold(account)) or {
		if err is store.NotFoundError {
			return NickRefusal{err_nicknameinuse, 'Your account no longer exists'}
		}
		return NickRefusal{err_nicknameinuse, 'Cannot check the nickname reservation, try again later'}
	}
	if acct.id != account_id {
		return NickRefusal{err_nicknameinuse, 'Nickname is reserved by a different account'}
	}
	holder_id := s.nicks[s.fold(account)] or { return none }
	if holder_id == c.id {
		return none
	}
	mut h := s.clients[holder_id] or { return none }
	if h.dead {
		// A killed client waiting to be reaped: remove it now, so that it neither
		// blocks the claim nor reports the name offline after the claim.
		s.quit(mut h, h.quit_reason)
		return none
	}
	if h.account != '' && h.account_id == account_id {
		return NickRefusal{err_nicknameinuse, 'Nickname is in use by another session of your account'}
	}
	if h.registered {
		guest := s.guest_nick() or {
			return NickRefusal{err_nicknameinuse, 'Cannot check the nickname reservation, try again later'}
		}
		s.change_nick(mut h, guest)
	} else {
		nick := h.nick
		s.release_nick(mut h)
		s.numeric(mut h, err_nicknameinuse, nick, 'Nickname is reserved by a different account')
	}
	return none
}

// guest_nick returns a free nickname that is no account name, for a client
// that loses a reserved one. It fails when the reservations cannot be checked.
fn (mut s Server) guest_nick() !string {
	for {
		s.guest_seq++
		nick := 'Guest${s.guest_seq}'
		if s.fold(nick) in s.nicks {
			continue
		}
		s.db.find_account(s.fold(nick)) or {
			if err is store.NotFoundError {
				return nick
			}
			return err
		}
	}
	return error('unreachable')
}
