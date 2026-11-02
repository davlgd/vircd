module server

import ircmsg
import store
import time

// client_tags returns the client-only tags (`+` prefix) of a message.
fn client_tags(msg ircmsg.Message) []ircmsg.Tag {
	return msg.tags.filter(it.key.starts_with('+'))
}

fn (mut s Server) cmd_message(mut c Client, msg ircmsg.Message) {
	command := msg.command
	is_notice := command == 'NOTICE'
	if msg.params.len < 1 || msg.params[0] == '' {
		if !is_notice {
			s.numeric(mut c, err_norecipient, 'No recipient given (${command})')
		}
		return
	}
	text := msg.param(1)
	if command != 'TAGMSG' && (msg.params.len < 2 || text == '') {
		if !is_notice {
			s.numeric(mut c, err_notexttosend, 'No text to send')
		}
		return
	}
	targets := msg.params[0].split(',').filter(it != '')
	if targets.len > max_targets {
		if !is_notice {
			s.numeric(mut c, err_toomanytargets, msg.params[0], 'Too many targets')
		}
		return
	}
	ctags := client_tags(msg)
	if command == 'TAGMSG' && !c.has('message-tags') {
		return
	}
	if command != 'TAGMSG' {
		c.last_message = time.now()
	}
	for target in targets {
		s.deliver(mut c, command, target, text, ctags)
	}
}

// deliver sends one PRIVMSG, NOTICE or TAGMSG to one target: a channel,
// `@#channel`/`+#channel` (STATUSMSG), or a nickname.
fn (mut s Server) deliver(mut c Client, command string, target string, text string, ctags []ircmsg.Tag) {
	is_notice := command == 'NOTICE'
	now := time.utc()
	msgid := s.next_msgid()
	mut tags := [ircmsg.Tag{'time', now.format_rfc3339()}, ircmsg.Tag{'msgid', msgid}]
	if c.account != '' {
		tags << ircmsg.Tag{'account', c.account}
	}
	if c.bot {
		tags << ircmsg.Tag{'bot', ''}
	}
	tags << ctags
	mut out := ircmsg.Message{
		tags:    tags
		source:  c.mask()
		command: command
		params:  [target]
	}
	mut body := text
	if command != 'TAGMSG' {
		// Cut the text here rather than per recipient (wire_line), so that every
		// recipient and the history get the same text.
		room := ircmsg.max_line_bytes - 2 - (c.mask().len + command.len + target.len + 6)
		body = truncate(text, if room > 0 { room } else { 0 })
		out.params << body
	}
	entry := store.HistoryEntry{
		msgid:   msgid
		time_ms: now.unix_milli()
		source:  c.mask()
		account: c.account
		command: command
		tags:    ircmsg.encode_tags(ctags)
		text:    body
	}
	mut status := ''
	mut name := target
	if name.len > 1 && (name[0] == `@` || name[0] == `+`) && name[1] == `#` {
		status = name[..1]
		name = name[1..]
	}
	if name.starts_with('#') {
		mut ch := s.channels[s.fold(name)] or {
			if !is_notice {
				s.numeric(mut c, err_nosuchchannel, name, 'No such channel')
			}
			return
		}
		member := ch.members[c.id] or { Member{} }
		in_channel := c.id in ch.members
		if (ch.no_ext && !in_channel) || (ch.moderated && !member.op && !member.voice)
			|| (!member.op && !member.voice && s.is_banned(ch, c)) {
			if !is_notice {
				s.numeric(mut c, err_cannotsendtochan, ch.name, 'Cannot send to channel')
			}
			return
		}
		out.params[0] = status + ch.name
		for id, m in ch.members {
			if id == c.id {
				continue
			}
			if status == '@' && !m.op {
				continue
			}
			if status == '+' && !m.op && !m.voice {
				continue
			}
			mut peer := s.clients[id] or { continue }
			if command == 'TAGMSG' && !peer.has('message-tags') {
				continue
			}
			s.send(mut peer, out)
		}
		if c.has('echo-message') {
			s.send(mut c, out)
		}
		if status == '' && command != 'TAGMSG' {
			s.record(store.HistoryEntry{
				...entry
				target_key: s.fold(ch.name)
				target:     ch.name
			})
		}
		return
	}
	mut peer := s.find_nick(name) or {
		if !is_notice {
			s.numeric(mut c, err_nosuchnick, name, 'No such nick/channel')
		}
		return
	}
	out.params[0] = peer.nick
	if command != 'TAGMSG' || peer.has('message-tags') {
		if peer.id == c.id {
			// A message to oneself: only the echo is a reply to a labeled command.
			s.send_now(mut peer, out)
		} else {
			s.send(mut peer, out)
		}
	}
	if command == 'PRIVMSG' && peer.away != '' {
		s.numeric(mut c, rpl_away, peer.nick, peer.away)
	}
	if c.has('echo-message') {
		s.send(mut c, out)
	}
	if command != 'TAGMSG' && (c.account_id > 0 || peer.account_id > 0) {
		s.record(store.HistoryEntry{
			...entry
			target_key: s.dm_key_of(c, peer)
			target:     peer.nick
		})
	}
}

// dm_key is the history key of a private conversation between two accounts,
// from their permanent ids.
fn dm_key(a int, b int) string {
	return if a < b { 'dm:${a}:${b}' } else { 'dm:${b}:${a}' }
}

// dm_nick_key is the history key of the private conversation between account
// `id` and a client that is not logged in, known by its nickname. Only the
// account can read it back.
fn dm_nick_key(id int, folded_nick string) string {
	return 'dmn:${id}:${folded_nick}'
}

fn (s &Server) dm_key_of(a &Client, b &Client) string {
	if a.account_id > 0 && b.account_id > 0 {
		return dm_key(a.account_id, b.account_id)
	}
	if a.account_id > 0 {
		return dm_nick_key(a.account_id, s.fold(b.nick))
	}
	return dm_nick_key(b.account_id, s.fold(a.nick))
}

fn (mut s Server) record(e store.HistoryEntry) {
	if s.cfg.history_limit <= 0 {
		return
	}
	s.db.add_history(e) or {
		log_error('cannot store a message', err)
		return
	}
	// Prune each conversation every 128 of its messages rather than on every one.
	n := s.history_writes[e.target_key] + 1
	if n >= 128 {
		s.history_writes.delete(e.target_key)
		s.db.prune(e.target_key, s.cfg.history_limit) or {
			log_error('cannot prune the history', err)
		}
	} else {
		s.history_writes[e.target_key] = n
	}
}
