module server

import crypto.subtle
import ircmsg
import time

// supported_caps lists the capabilities the server implements, in CAP LS order.
const supported_caps = ['account-notify', 'account-tag', 'away-notify', 'batch', 'cap-notify',
	'draft/chathistory', 'draft/read-marker', 'echo-message', 'extended-join', 'extended-monitor',
	'invite-notify', 'labeled-response', 'message-tags', 'multi-prefix', 'sasl', 'server-time',
	'setname', 'userhost-in-names']!

const sasl_mechanisms = 'PLAIN,SCRAM-SHA-256'

fn cap_value(name string) string {
	return match name {
		'sasl' { sasl_mechanisms }
		else { '' }
	}
}

fn (mut s Server) cmd_cap(mut c Client, msg ircmsg.Message) {
	sub := msg.param(0).to_upper()
	match sub {
		'LS' {
			wanted := msg.param(1).int()
			if wanted > c.cap_version {
				c.cap_version = wanted
			}
			if c.cap_version >= 302 {
				c.caps['cap-notify'] = true
			}
			if !c.registered {
				c.negotiating = true
			}
			mut items := []string{}
			for name in supported_caps {
				value := cap_value(name)
				items << if c.cap_version >= 302 && value != '' { '${name}=${value}' } else { name }
			}
			s.send_cap_list(mut c, 'LS', items)
		}
		'LIST' {
			mut items := []string{}
			for name in supported_caps {
				if c.has(name) {
					items << name
				}
			}
			s.send_cap_list(mut c, 'LIST', items)
		}
		'REQ' {
			if !c.registered {
				c.negotiating = true
			}
			requested := msg.param(1).fields()
			mut ok := requested.len > 0
			for r in requested {
				name := r.trim_left('-')
				if name !in supported_caps || (r.starts_with('-') && name == 'cap-notify'
					&& c.cap_version >= 302) {
					ok = false
				}
			}
			if !ok {
				s.send_cap(mut c, 'NAK', msg.param(1))
				return
			}
			for r in requested {
				if r.starts_with('-') {
					c.caps.delete(r[1..])
				} else {
					c.caps[r] = true
				}
			}
			s.send_cap(mut c, 'ACK', msg.param(1))
		}
		'END' {
			if !c.registered {
				c.negotiating = false
				s.try_register(mut c)
			}
		}
		else {
			s.numeric(mut c, err_invalidcapcmd, if sub == '' { '*' } else { sub },
				'Invalid CAP command')
		}
	}
}

fn (mut s Server) send_cap(mut c Client, sub string, arg string) {
	s.send(mut c, ircmsg.Message{
		source:  s.cfg.name
		command: 'CAP'
		params:  [c.target(), sub, arg]
	})
}

// send_cap_list sends a CAP LS or LIST reply, split on several lines with a `*`
// continuation marker (only understood by 302 clients) when it is too long.
fn (mut s Server) send_cap_list(mut c Client, sub string, items []string) {
	mut lines := [][]string{}
	mut cur := []string{}
	mut size := 0
	for item in items {
		if size + item.len + 1 > 400 && cur.len > 0 {
			lines << cur
			cur = []string{}
			size = 0
		}
		cur << item
		size += item.len + 1
	}
	lines << cur
	for i, line in lines {
		mut params := [c.target(), sub]
		if i < lines.len - 1 && c.cap_version >= 302 {
			params << '*'
		}
		params << line.join(' ')
		s.send(mut c, ircmsg.Message{
			source:  s.cfg.name
			command: 'CAP'
			params:  params
		})
	}
}

fn (mut s Server) cmd_pass(mut c Client, msg ircmsg.Message) {
	if c.registered {
		s.numeric(mut c, err_alreadyregistered, 'You may not reregister')
		return
	}
	if !s.has_params(mut c, msg, 1) {
		return
	}
	if s.cfg.password != '' {
		c.pass_ok = secret_equal(msg.params[0], s.cfg.password)
	}
}

fn valid_nick(nick string) bool {
	return ircmsg.valid_nickname(nick, nick_len)
}

fn (mut s Server) cmd_nick(mut c Client, msg ircmsg.Message) {
	nick := msg.param(0)
	if nick == '' {
		s.numeric(mut c, err_nonicknamegiven, 'No nickname given')
		return
	}
	if !valid_nick(nick) {
		s.numeric(mut c, err_erroneusnickname, nick, 'Erroneous nickname')
		return
	}
	key := s.fold(nick)
	if owner := s.nicks[key] {
		if owner != c.id {
			s.numeric(mut c, err_nicknameinuse, nick, 'Nickname is already in use')
			return
		}
		if nick == c.nick {
			return
		}
	}
	if !c.registered {
		// Reservations are checked when registration completes, after SASL.
		s.set_nick(mut c, nick)
		s.try_register(mut c)
		return
	}
	if refusal := s.nick_refusal(c, nick) {
		s.numeric(mut c, refusal.code, nick, refusal.text)
		return
	}
	s.change_nick(mut c, nick)
}

fn (mut s Server) cmd_user(mut c Client, msg ircmsg.Message) {
	if c.registered || c.got_user {
		s.numeric(mut c, err_alreadyregistered, 'You may not reregister')
		return
	}
	if msg.params.len < 4 || msg.params[0] == '' || msg.params[3] == '' {
		s.numeric(mut c, err_needmoreparams, 'USER', 'Not enough parameters')
		return
	}
	mut user := ''
	for ch in msg.params[0] {
		if ch.is_letter() || ch.is_digit() || ch in [`-`, `_`, `.`] {
			user += ch.ascii_str()
		}
	}
	if user == '' {
		user = 'user'
	}
	c.user = '~' + truncate(user, user_len - 1)
	c.real = truncate(msg.params[3], real_len)
	c.got_user = true
	s.try_register(mut c)
}

fn (mut s Server) cmd_ping(mut c Client, msg ircmsg.Message) {
	if !s.has_params(mut c, msg, 1) {
		return
	}
	s.send(mut c, ircmsg.Message{
		source:  s.cfg.name
		command: 'PONG'
		params:  [s.cfg.name, msg.params[0]]
	})
}

// try_register completes the registration once NICK and USER are in, CAP
// negotiation is over and no SASL check is running.
fn (mut s Server) try_register(mut c Client) {
	if c.registered || c.dead || c.gone || c.nick == '' || !c.got_user || c.negotiating
		|| c.auth_pending {
		return
	}
	if !c.pass_ok {
		s.numeric(mut c, err_passwdmismatch, 'Password incorrect')
		s.kill(mut c, 'Bad password')
		return
	}
	if !s.settle_nick(mut c) {
		return
	}
	c.registered = true
	c.last_active = time.now()
	registered := s.clients.values().filter(it.registered).len
	if registered > s.max_seen {
		s.max_seen = registered
	}
	nick := c.nick
	s.numeric(mut c, rpl_welcome, 'Welcome to the ${s.cfg.network} IRC Network ${c.mask()}')
	s.numeric(mut c, rpl_yourhost, 'Your host is ${s.cfg.name}, running version ${version}')
	s.numeric(mut c, rpl_created, 'This server was created ${s.created.http_header_string()}')
	s.numeric(mut c, rpl_myinfo, s.cfg.name, version, 'Biow', 'bklimnostv', 'bklov')
	s.send_isupport(mut c)
	s.send_lusers(mut c)
	s.send_motd(mut c)
	s.notify_monitors(nick, true, c)
	s.send_stored_markers(mut c)
}

fn (s &Server) isupport_tokens() []string {
	return [
		'AWAYLEN=${away_len}',
		'BOT=B',
		'CASEMAPPING=${casemapping}',
		'CHANLIMIT=#:${max_channels}',
		'CHANMODES=b,k,l,imnst',
		'CHANNELLEN=${channel_len}',
		'CHANTYPES=#',
		'CHATHISTORY=${chathistory_max}',
		'ELIST=U',
		'HOSTLEN=${host_len}',
		'KICKLEN=${kick_len}',
		'MAXLIST=b:${max_list_masks}',
		'MODES=${max_modes}',
		'MONITOR=${max_monitor}',
		'MSGREFTYPES=msgid,timestamp',
		'NETWORK=${s.cfg.network}',
		'NICKLEN=${nick_len}',
		'PREFIX=(ov)@+',
		'SAFELIST',
		'STATUSMSG=@+',
		'TARGMAX=JOIN:,KICK:,LIST:,MONITOR:,NAMES:,NOTICE:${max_targets},PART:,PRIVMSG:${max_targets},TAGMSG:${max_targets},WHOIS:1',
		'TOPICLEN=${topic_len}',
		'USERLEN=${user_len}',
		'UTF8ONLY',
		'WHOX',
	]
}

fn (mut s Server) send_isupport(mut c Client) {
	tokens := s.isupport_tokens()
	mut i := 0
	for i < tokens.len {
		end := if i + 12 < tokens.len { i + 12 } else { tokens.len }
		mut params := tokens[i..end].clone()
		params << 'are supported by this server'
		s.numeric(mut c, rpl_isupport, ...params)
		i = end
	}
}

fn (mut s Server) send_lusers(mut c Client) {
	mut users := 0
	mut invisible := 0
	mut opers := 0
	mut unknown := 0
	for _, cl in s.clients {
		if !cl.registered {
			unknown++
			continue
		}
		users++
		if cl.invisible {
			invisible++
		}
		if cl.oper {
			opers++
		}
	}
	s.numeric(mut c, rpl_luserclient, 'There are ${users - invisible} users and ${invisible} invisible on 1 servers')
	s.numeric(mut c, rpl_luserop, opers.str(), 'operator(s) online')
	s.numeric(mut c, rpl_luserunknown, unknown.str(), 'unknown connection(s)')
	s.numeric(mut c, rpl_luserchannels, s.channels.len.str(), 'channels formed')
	s.numeric(mut c, rpl_luserme, 'I have ${users} clients and 0 servers')
	s.numeric(mut c, rpl_localusers, users.str(), s.max_seen.str(), 'Current local users ${users}, max ${s.max_seen}')
	s.numeric(mut c, rpl_globalusers, users.str(), s.max_seen.str(), 'Current global users ${users}, max ${s.max_seen}')
}

fn (mut s Server) send_motd(mut c Client) {
	if s.cfg.motd.len == 0 {
		s.numeric(mut c, err_nomotd, 'MOTD File is missing')
		return
	}
	s.numeric(mut c, rpl_motdstart, '- ${s.cfg.name} Message of the day - ')
	for line in s.cfg.motd {
		s.numeric(mut c, rpl_motd, '- ${line}')
	}
	s.numeric(mut c, rpl_endofmotd, 'End of /MOTD command.')
}

// secret_equal compares a secret with a guess in constant time.
fn secret_equal(a string, b string) bool {
	return subtle.constant_time_compare(a.bytes(), b.bytes()) == 1
}
