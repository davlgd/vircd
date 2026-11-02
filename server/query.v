module server

import ircmsg
import time

struct WhowasEntry {
	nick string
	user string
	host string
	real string
	at   i64
}

fn (mut s Server) add_whowas(c &Client) {
	s.whowas << WhowasEntry{
		nick: c.nick
		user: c.user
		host: c.host
		real: c.real
		at:   time.now().unix()
	}
	if s.whowas.len > whowas_max {
		s.whowas.delete(0)
	}
}

// shares_channel reports whether two clients have a channel in common.
fn (s &Server) shares_channel(a &Client, b &Client) bool {
	for key, _ in a.channels {
		if key in b.channels {
			return true
		}
	}
	return false
}

struct WhoFields {
	whox  bool
	flags string
	token string
}

fn (mut s Server) cmd_who(mut c Client, msg ircmsg.Message) {
	mask := if msg.params.len > 0 && msg.params[0] != '' { msg.params[0] } else { '*' }
	mut fields := WhoFields{}
	if msg.params.len > 1 && msg.params[1].starts_with('%') {
		spec := msg.params[1][1..]
		fields = WhoFields{
			whox:  true
			flags: spec.all_before(',')
			token: if spec.contains(',') { spec.all_after(',') } else { '' }
		}
	}
	if mask.starts_with('#') {
		if ch := s.channels[s.fold(mask)] {
			member := c.id in ch.members
			if member || !ch.secret {
				for id, _ in ch.members {
					peer := s.clients[id] or { continue }
					if !member && peer.invisible {
						continue
					}
					s.who_reply(mut c, peer, ch, fields)
				}
			}
		}
	} else {
		folded := s.fold(mask)
		exact := !mask.contains('*') && !mask.contains('?')
		for _, peer in s.clients {
			if !peer.registered {
				continue
			}
			if exact {
				if s.fold(peer.nick) != folded {
					continue
				}
			} else {
				if peer.id != c.id && peer.invisible && !s.shares_channel(c, peer) {
					continue
				}
				if !wildcard_match(folded, s.fold(peer.nick)) && !wildcard_match(folded, s.fold(peer.user))
					&& !wildcard_match(folded, s.fold(peer.host))
					&& !wildcard_match(folded, s.fold(peer.real)) {
					continue
				}
			}
			s.who_reply(mut c, peer, unsafe { nil }, fields)
		}
	}
	s.numeric(mut c, rpl_endofwho, mask, 'End of WHO list')
}

fn (mut s Server) who_reply(mut c Client, peer &Client, ch &Channel, f WhoFields) {
	mut channel := '*'
	mut prefix := ''
	if ch != unsafe { nil } {
		channel = ch.name
		prefix = ch.prefix(peer.id, c.has('multi-prefix'))
	} else {
		for key, _ in peer.channels {
			pch := s.channels[key] or { continue }
			if !pch.secret || c.id in pch.members {
				channel = pch.name
				prefix = pch.prefix(peer.id, c.has('multi-prefix'))
				break
			}
		}
	}
	mut flags := if peer.away != '' { 'G' } else { 'H' }
	if peer.oper {
		flags += '*'
	}
	if peer.bot {
		flags += 'B'
	}
	flags += prefix
	if !f.whox {
		s.numeric(mut c, rpl_whoreply, channel, peer.user, peer.host, s.cfg.name, peer.nick,
			flags, '0 ${peer.real}')
		return
	}
	mut params := []string{}
	// WHOX fields are sent in a fixed order, whatever the order requested.
	for field in 'tcuihsnfdlaor' {
		if !f.flags.contains(field.ascii_str()) {
			continue
		}
		params << match field {
			`t` {
				if f.token == '' { '0' } else { f.token }
			}
			`c` { channel }
			`u` { peer.user }
			`i` { '255.255.255.255' }
			`h` { peer.host }
			`s` { s.cfg.name }
			`n` { peer.nick }
			`f` { flags }
			`d` { '0' }
			`l` {
				if peer.id == c.id || c.oper { idle_seconds(peer).str() } else { '0' }
			}
			`a` {
				if peer.account == '' { '0' } else { peer.account }
			}
			`o` { '0' }
			`r` { peer.real }
			else { '' }
		}
	}
	if params.len > 0 && params.last() == '' && !f.flags.contains('r') {
		params[params.len - 1] = '*'
	}
	s.numeric(mut c, rpl_whospcrpl, ...params)
}

fn idle_seconds(c &Client) i64 {
	last := if c.last_message.unix() == 0 { c.connected } else { c.last_message }
	return i64((time.now() - last).seconds())
}

fn (mut s Server) cmd_whois(mut c Client, msg ircmsg.Message) {
	if msg.params.len < 1 || msg.params[0] == '' {
		s.numeric(mut c, err_nonicknamegiven, 'No nickname given')
		return
	}
	nick := msg.params[msg.params.len - 1].all_before(',')
	peer := s.find_nick(nick) or {
		s.numeric(mut c, err_nosuchnick, nick, 'No such nick/channel')
		s.numeric(mut c, rpl_endofwhois, nick, 'End of /WHOIS list')
		return
	}
	s.numeric(mut c, rpl_whoisuser, peer.nick, peer.user, peer.host, '*', peer.real)
	if c.id == peer.id || c.oper {
		s.numeric(mut c, rpl_whoishost, peer.nick, 'is connecting from *@${peer.ip} ${peer.ip}')
	}
	mut chans := []string{}
	for key, _ in peer.channels {
		ch := s.channels[key] or { continue }
		if ch.secret && c.id !in ch.members && c.id != peer.id {
			continue
		}
		chans << ch.prefix(peer.id, c.has('multi-prefix')) + ch.name
	}
	s.numeric_list(mut c, rpl_whoischannels, [peer.nick], chans, ' ')
	s.numeric(mut c, rpl_whoisserver, peer.nick, s.cfg.name, s.cfg.description)
	if peer.bot {
		s.numeric(mut c, rpl_whoisbot, peer.nick, 'is a bot')
	}
	if peer.oper {
		s.numeric(mut c, rpl_whoisoperator, peer.nick, 'is an IRC operator')
	}
	if peer.away != '' {
		s.numeric(mut c, rpl_away, peer.nick, peer.away)
	}
	if peer.tls {
		s.numeric(mut c, rpl_whoissecure, peer.nick, 'is using a secure connection')
	}
	if peer.account != '' {
		s.numeric(mut c, rpl_whoisaccount, peer.nick, peer.account, 'is logged in as')
	}
	s.numeric(mut c, rpl_whoisidle, peer.nick, idle_seconds(peer).str(), peer.connected.unix().str(),
		'seconds idle, signon time')
	s.numeric(mut c, rpl_endofwhois, peer.nick, 'End of /WHOIS list')
}

fn (mut s Server) cmd_whowas(mut c Client, msg ircmsg.Message) {
	if msg.params.len < 1 || msg.params[0] == '' {
		s.numeric(mut c, err_nonicknamegiven, 'No nickname given')
		return
	}
	nick := msg.params[0]
	mut limit := msg.param(1).int()
	if limit <= 0 {
		limit = whowas_max
	}
	folded := s.fold(nick)
	mut found := 0
	for i := s.whowas.len - 1; i >= 0 && found < limit; i-- {
		e := s.whowas[i]
		if s.fold(e.nick) != folded {
			continue
		}
		found++
		s.numeric(mut c, rpl_whowasuser, e.nick, e.user, e.host, '*', e.real)
		s.numeric(mut c, rpl_whoisserver, e.nick, s.cfg.name, time.unix(e.at).http_header_string())
	}
	if found == 0 {
		s.numeric(mut c, err_wasnosuchnick, nick, 'There was no such nickname')
	}
	s.numeric(mut c, rpl_endofwhowas, nick, 'End of WHOWAS')
}

fn (mut s Server) cmd_away(mut c Client, msg ircmsg.Message) {
	text := truncate(msg.param(0), away_len)
	c.away = text
	if text == '' {
		s.numeric(mut c, rpl_unaway, 'You are no longer marked as being away')
	} else {
		s.numeric(mut c, rpl_nowaway, 'You have been marked as being away')
	}
	params := if text == '' { []string{} } else { [text] }
	s.send_to_peers(c, s.user_msg(c, 'AWAY', params), false, 'away-notify')
}

fn (mut s Server) cmd_ison(mut c Client, msg ircmsg.Message) {
	if !s.has_params(mut c, msg, 1) {
		return
	}
	mut online := []string{}
	for p in msg.params {
		for nick in p.fields() {
			if peer := s.find_nick(nick) {
				online << peer.nick
			}
		}
	}
	if online.len == 0 {
		s.numeric(mut c, rpl_ison, '')
	}
	s.numeric_list(mut c, rpl_ison, [], online, ' ')
}

fn (mut s Server) cmd_userhost(mut c Client, msg ircmsg.Message) {
	if !s.has_params(mut c, msg, 1) {
		return
	}
	mut replies := []string{}
	for nick in msg.params {
		if replies.len >= 5 {
			break
		}
		peer := s.find_nick(nick) or { continue }
		oper := if peer.oper { '*' } else { '' }
		away := if peer.away != '' { '-' } else { '+' }
		replies << '${peer.nick}${oper}=${away}${peer.user}@${peer.host}'
	}
	if replies.len == 0 {
		s.numeric(mut c, rpl_userhost, '')
	}
	s.numeric_list(mut c, rpl_userhost, [], replies, ' ')
}

fn (mut s Server) cmd_version(mut c Client) {
	s.numeric(mut c, rpl_version, version, s.cfg.name, 'IRCv3 server written in V')
	s.send_isupport(mut c)
}

fn (mut s Server) cmd_time(mut c Client) {
	now := time.utc()
	s.numeric(mut c, rpl_time, s.cfg.name, now.unix().str(), '0', now.http_header_string())
}

fn (mut s Server) cmd_info(mut c Client) {
	s.numeric(mut c, rpl_info, '${version}, an IRCv3 server written in V (https://vlang.io).')
	s.numeric(mut c, rpl_endofinfo, 'End of INFO list')
}

fn (mut s Server) cmd_admin(mut c Client) {
	s.numeric(mut c, rpl_adminme, s.cfg.name, 'Administrative info')
	s.numeric(mut c, rpl_adminloc1, s.cfg.network)
	s.numeric(mut c, rpl_adminloc2, s.cfg.name)
	s.numeric(mut c, rpl_adminemail, 'admin@${s.cfg.name}')
}

fn (mut s Server) cmd_setname(mut c Client, msg ircmsg.Message) {
	if msg.params.len < 1 || msg.params[0] == '' {
		s.fail(mut c, 'SETNAME', 'INVALID_REALNAME', 'Realname is not valid')
		return
	}
	if msg.params[0].len > real_len {
		s.fail(mut c, 'SETNAME', 'INVALID_REALNAME', 'Realname is too long')
		return
	}
	c.real = msg.params[0]
	s.send_to_peers(c, s.user_msg(c, 'SETNAME', [c.real]), true, 'setname')
}

fn (mut s Server) cmd_oper(mut c Client, msg ircmsg.Message) {
	if !s.has_params(mut c, msg, 2) {
		return
	}
	if s.cfg.oper_user == '' || msg.params[0] != s.cfg.oper_user {
		s.numeric(mut c, err_nooperhost, 'No O-lines for your host')
		return
	}
	if !secret_equal(msg.params[1], s.cfg.oper_password) {
		s.numeric(mut c, err_passwdmismatch, 'Password incorrect')
		return
	}
	c.oper = true
	s.numeric(mut c, rpl_youreoper, 'You are now an IRC operator')
	s.send(mut c, ircmsg.Message{
		source:  c.mask()
		command: 'MODE'
		params:  [c.nick, '+o']
	})
}

fn (mut s Server) cmd_kill(mut c Client, msg ircmsg.Message) {
	if !s.has_params(mut c, msg, 2) {
		return
	}
	if !c.oper {
		s.numeric(mut c, err_noprivileges, 'Permission Denied- You do not have the correct IRC operator privileges')
		return
	}
	mut target := s.find_nick(msg.params[0]) or {
		s.numeric(mut c, err_nosuchnick, msg.params[0], 'No such nick/channel')
		return
	}
	reason := truncate(msg.params[1], kick_len)
	s.send(mut target, ircmsg.Message{
		source:  c.mask()
		command: 'KILL'
		params:  [target.nick, reason]
	})
	s.kill(mut target, 'Killed (${c.nick} (${reason}))')
}

// MONITOR (https://ircv3.net/specs/extensions/monitor).
fn (mut s Server) cmd_monitor(mut c Client, msg ircmsg.Message) {
	sub := msg.param(0)
	match sub {
		'+' {
			mut online := []string{}
			mut offline := []string{}
			for nick in msg.param(1).split(',') {
				if nick == '' || !valid_nick(nick) {
					continue
				}
				key := s.fold(nick)
				if key !in c.monitor {
					if c.monitor.len >= max_monitor {
						s.numeric(mut c, err_monlistfull, max_monitor.str(), nick, 'Monitor list is full.')
						break
					}
					c.monitor[key] = true
					if key !in s.monitors {
						s.monitors[key] = map[int]bool{}
					}
					s.monitors[key][c.id] = true
				}
				if peer := s.find_nick(nick) {
					online << peer.mask()
				} else {
					offline << nick
				}
			}
			s.numeric_list(mut c, rpl_mononline, [], online, ',')
			s.numeric_list(mut c, rpl_monoffline, [], offline, ',')
		}
		'-' {
			for nick in msg.param(1).split(',') {
				key := s.fold(nick)
				c.monitor.delete(key)
				s.unwatch(key, c.id)
			}
		}
		'C', 'c' {
			s.remove_monitors(c)
			c.monitor.clear()
		}
		'L', 'l' {
			s.numeric_list(mut c, rpl_monlist, [], c.monitor.keys(), ',')
			s.numeric(mut c, rpl_endofmonlist, 'End of MONITOR list')
		}
		'S', 's' {
			mut online := []string{}
			mut offline := []string{}
			for key, _ in c.monitor {
				if peer := s.find_nick(key) {
					online << peer.mask()
				} else {
					offline << key
				}
			}
			s.numeric_list(mut c, rpl_mononline, [], online, ',')
			s.numeric_list(mut c, rpl_monoffline, [], offline, ',')
		}
		else {
			s.numeric(mut c, err_needmoreparams, 'MONITOR', 'Not enough parameters')
		}
	}
}

fn (mut s Server) unwatch(key string, id int) {
	if key !in s.monitors {
		return
	}
	s.monitors[key].delete(id)
	if s.monitors[key].len == 0 {
		s.monitors.delete(key)
	}
}

fn (mut s Server) remove_monitors(c &Client) {
	for key, _ in c.monitor {
		s.unwatch(key, c.id)
	}
}

// notify_monitors tells the clients monitoring `nick` that it came online or went offline.
fn (mut s Server) notify_monitors(nick string, online bool, c &Client) {
	key := s.fold(nick)
	if key !in s.monitors {
		return
	}
	for id in s.monitors[key].keys() {
		if id == c.id {
			continue
		}
		mut w := s.clients[id] or { continue }
		if !w.registered {
			continue
		}
		if online {
			s.numeric(mut w, rpl_mononline, c.mask())
		} else {
			s.numeric(mut w, rpl_monoffline, nick)
		}
	}
}
