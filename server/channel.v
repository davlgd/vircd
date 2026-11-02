module server

import ircmsg
import time

struct Member {
mut:
	op    bool
	voice bool
}

struct Ban {
	mask   string
	set_by string
	set_at i64
}

@[heap]
struct Channel {
	name    string
	created i64
	// history_floor hides the history of earlier channels of the same name: it
	// is the newest history id when the channel was created.
	history_floor i64
mut:
	topic    string
	topic_by string
	topic_at i64
	// members is keyed by client id; V maps keep insertion order.
	members   map[int]Member
	no_ext    bool = true
	topic_op  bool = true
	moderated bool
	invite    bool
	secret    bool
	key       string
	limit     int
	bans      []Ban
}

fn (ch &Channel) prefix(id int, multi bool) string {
	m := ch.members[id] or { return '' }
	mut p := ''
	if m.op {
		p += '@'
	}
	if m.voice && (multi || p == '') {
		p += '+'
	}
	return p
}

fn (ch &Channel) is_op(id int) bool {
	return (ch.members[id] or { return false }).op
}

fn (ch &Channel) mode_string(show_key bool) []string {
	mut flags := '+'
	mut params := []string{}
	if ch.invite {
		flags += 'i'
	}
	if ch.key != '' {
		flags += 'k'
		params << if show_key { ch.key } else { '*' }
	}
	if ch.limit > 0 {
		flags += 'l'
		params << ch.limit.str()
	}
	if ch.moderated {
		flags += 'm'
	}
	if ch.no_ext {
		flags += 'n'
	}
	if ch.secret {
		flags += 's'
	}
	if ch.topic_op {
		flags += 't'
	}
	mut out := [flags]
	out << params
	return out
}

// valid_channel reports whether `name` is an acceptable channel name.
fn valid_channel(name string) bool {
	if name.len < 2 || name.len > channel_len || name[0] != `#` {
		return false
	}
	for ch in name {
		if ch in [` `, `,`, 7, 0, `\r`, `\n`] {
			return false
		}
	}
	return true
}

// is_banned reports whether a client matches a ban of the channel.
fn (s &Server) is_banned(ch &Channel, c &Client) bool {
	mask := s.fold(c.mask())
	for b in ch.bans {
		if wildcard_match(s.fold(b.mask), mask) {
			return true
		}
	}
	return false
}

// wildcard_match matches `text` against a mask with `*` and `?`. Not
// string.match_glob, which reads `[...]` as a class: `[` and `]` are nickname
// characters.
fn wildcard_match(mask string, text string) bool {
	mut m := 0
	mut t := 0
	mut star := -1
	mut mark := 0
	for t < text.len {
		if m < mask.len && (mask[m] == `?` || mask[m] == text[t]) {
			m++
			t++
		} else if m < mask.len && mask[m] == `*` {
			star = m
			mark = t
			m++
		} else if star >= 0 {
			m = star + 1
			mark++
			t = mark
		} else {
			return false
		}
	}
	for m < mask.len && mask[m] == `*` {
		m++
	}
	return m == mask.len
}

fn (mut s Server) cmd_join(mut c Client, msg ircmsg.Message) {
	if !s.has_params(mut c, msg, 1) {
		return
	}
	if msg.params[0] == '0' {
		for key in c.channels.keys() {
			ch := s.channels[key] or { continue }
			s.part(mut c, ch.name, c.nick)
		}
		return
	}
	names := msg.params[0].split(',')
	keys := msg.param(1).split(',')
	for i, name in names {
		if name == '' {
			continue
		}
		key := if i < keys.len { keys[i] } else { '' }
		s.join(mut c, name, key)
	}
}

fn (mut s Server) join(mut c Client, name string, key string) {
	if !valid_channel(name) {
		s.numeric(mut c, err_nosuchchannel, name, 'No such channel')
		return
	}
	folded := s.fold(name)
	if folded in c.channels {
		return
	}
	if c.channels.len >= max_channels {
		s.numeric(mut c, err_toomanychannels, name, 'You have joined too many channels')
		return
	}
	mut ch := s.channels[folded] or {
		new_ch := &Channel{
			name:          name
			created:       time.now().unix()
			// Without the floor, the channel shows no history at all.
			history_floor: s.db.last_id() or {
				log_error('cannot read the history position', err)
				max_i64
			}
		}
		s.channels[folded] = new_ch
		new_ch
	}
	if ch.members.len > 0 {
		invited := folded in c.invited
		if ch.key != '' && !secret_equal(key, ch.key) && !invited {
			s.numeric(mut c, err_badchannelkey, ch.name, 'Cannot join channel (+k)')
			return
		}
		if ch.invite && !invited {
			s.numeric(mut c, err_inviteonlychan, ch.name, 'Cannot join channel (+i)')
			return
		}
		if ch.limit > 0 && ch.members.len >= ch.limit && !invited {
			s.numeric(mut c, err_channelisfull, ch.name, 'Cannot join channel (+l)')
			return
		}
		if s.is_banned(ch, c) && !invited {
			s.numeric(mut c, err_bannedfromchan, ch.name, 'Cannot join channel (+b)')
			return
		}
	}
	ch.members[c.id] = Member{
		op: ch.members.len == 0
	}
	c.channels[folded] = true
	c.invited.delete(folded)
	plain := s.user_msg(c, 'JOIN', [ch.name])
	extended := s.user_msg(c, 'JOIN', [ch.name, if c.account == '' { '*' } else { c.account },
		c.real])
	away := s.user_msg(c, 'AWAY', [c.away])
	for id, _ in ch.members {
		mut peer := s.clients[id] or { continue }
		s.send(mut peer, if peer.has('extended-join') { extended } else { plain })
		if c.away != '' && id != c.id && peer.has('away-notify') {
			s.send(mut peer, away)
		}
	}
	if ch.topic != '' {
		s.send_topic(mut c, ch)
	}
	if c.has('draft/read-marker') {
		s.send_marker(mut c, ch.name)
	}
	s.send_names(mut c, ch, true)
}

fn (mut s Server) send_topic(mut c Client, ch &Channel) {
	s.numeric(mut c, rpl_topic, ch.name, ch.topic)
	s.numeric(mut c, rpl_topicwhotime, ch.name, ch.topic_by, ch.topic_at.str())
}

// send_names sends the RPL_NAMREPLY lines of a channel, then RPL_ENDOFNAMES
// unless `end` is false (NAMES with several channels ends once).
fn (mut s Server) send_names(mut c Client, ch &Channel, end bool) {
	member := c.id in ch.members
	if !ch.secret || member {
		symbol := if ch.secret { '@' } else { '=' }
		multi := c.has('multi-prefix')
		mut entries := []string{}
		for id, _ in ch.members {
			peer := s.clients[id] or { continue }
			if !member && peer.invisible {
				continue
			}
			who := if c.has('userhost-in-names') { peer.mask() } else { peer.nick }
			entries << ch.prefix(id, multi) + who
		}
		s.numeric_list(mut c, rpl_namreply, [symbol, ch.name], entries, ' ')
	}
	if end {
		s.numeric(mut c, rpl_endofnames, ch.name, 'End of /NAMES list')
	}
}

fn (mut s Server) cmd_part(mut c Client, msg ircmsg.Message) {
	if !s.has_params(mut c, msg, 1) {
		return
	}
	reason := truncate(msg.param(1), kick_len)
	for name in msg.params[0].split(',') {
		if name != '' {
			s.part(mut c, name, reason)
		}
	}
}

fn (mut s Server) part(mut c Client, name string, reason string) {
	folded := s.fold(name)
	mut ch := s.channels[folded] or {
		s.numeric(mut c, err_nosuchchannel, name, 'No such channel')
		return
	}
	if c.id !in ch.members {
		s.numeric(mut c, err_notonchannel, ch.name, "You're not on that channel")
		return
	}
	mut params := [ch.name]
	if reason != '' {
		params << reason
	}
	s.send_channel(ch, s.user_msg(c, 'PART', params), 0, '')
	s.leave(mut c, mut ch)
}

// leave removes a client from a channel, and the channel once it is empty.
fn (mut s Server) leave(mut c Client, mut ch Channel) {
	folded := s.fold(ch.name)
	ch.members.delete(c.id)
	c.channels.delete(folded)
	if ch.members.len == 0 {
		s.channels.delete(folded)
		// Invitations and pruning counters were for this channel, not for a later
		// one of the same name.
		for _, mut peer in s.clients {
			peer.invited.delete(folded)
		}
		s.history_writes.delete(folded)
	}
}

// send_channel sends a message to the members of a channel, except `skip`, and
// only to those with `cap` when it is set.
fn (mut s Server) send_channel(ch &Channel, msg ircmsg.Message, skip int, cap string) {
	for id, _ in ch.members {
		if id == skip {
			continue
		}
		mut peer := s.clients[id] or { continue }
		if cap == '' || peer.has(cap) {
			s.send(mut peer, msg)
		}
	}
}

// KICK takes one channel and several users, or as many channels as users,
// paired in order (RFC 2812 §3.2.8). Each kick is sent as its own message.
fn (mut s Server) cmd_kick(mut c Client, msg ircmsg.Message) {
	if !s.has_params(mut c, msg, 2) {
		return
	}
	chans := msg.params[0].split(',')
	nicks := msg.params[1].split(',')
	if chans.len != 1 && chans.len != nicks.len {
		s.numeric(mut c, err_needmoreparams, 'KICK', 'Not enough parameters')
		return
	}
	mut reason := truncate(msg.param(2), kick_len)
	if reason == '' {
		reason = c.nick
	}
	for i, nick in nicks {
		s.kick(mut c, if chans.len == 1 { chans[0] } else { chans[i] }, nick, reason)
	}
}

fn (mut s Server) kick(mut c Client, name string, nick string, reason string) {
	mut ch := s.channels[s.fold(name)] or {
		s.numeric(mut c, err_nosuchchannel, name, 'No such channel')
		return
	}
	if c.id !in ch.members {
		s.numeric(mut c, err_notonchannel, ch.name, "You're not on that channel")
		return
	}
	if !ch.is_op(c.id) {
		s.numeric(mut c, err_chanoprivsneeded, ch.name, "You're not channel operator")
		return
	}
	mut target := s.find_nick(nick) or {
		s.numeric(mut c, err_nosuchnick, nick, 'No such nick/channel')
		return
	}
	if target.id !in ch.members {
		s.numeric(mut c, err_usernotinchannel, target.nick, ch.name, "They aren't on that channel")
		return
	}
	s.send_channel(ch, s.user_msg(c, 'KICK', [ch.name, target.nick, reason]), 0, '')
	s.leave(mut target, mut ch)
}

fn (mut s Server) find_nick(nick string) ?&Client {
	id := s.nicks[s.fold(nick)] or { return none }
	c := s.clients[id] or { return none }
	if !c.registered {
		return none
	}
	return c
}

fn (mut s Server) cmd_invite(mut c Client, msg ircmsg.Message) {
	if msg.params.len == 0 {
		// INVITE without parameters lists the pending invitations.
		for key, _ in c.invited {
			name := if ch := s.channels[key] { ch.name } else { key }
			s.numeric(mut c, rpl_invitelist, name)
		}
		s.numeric(mut c, rpl_endofinvitelist, 'End of /INVITE list')
		return
	}
	if !s.has_params(mut c, msg, 2) {
		return
	}
	mut target := s.find_nick(msg.params[0]) or {
		s.numeric(mut c, err_nosuchnick, msg.params[0], 'No such nick/channel')
		return
	}
	folded := s.fold(msg.params[1])
	ch := s.channels[folded] or {
		s.numeric(mut c, err_nosuchchannel, msg.params[1], 'No such channel')
		return
	}
	if c.id !in ch.members {
		s.numeric(mut c, err_notonchannel, ch.name, "You're not on that channel")
		return
	}
	if ch.invite && !ch.is_op(c.id) {
		s.numeric(mut c, err_chanoprivsneeded, ch.name, "You're not channel operator")
		return
	}
	if target.id in ch.members {
		s.numeric(mut c, err_useronchannel, target.nick, ch.name, 'is already on channel')
		return
	}
	target.invited[folded] = true
	s.numeric(mut c, rpl_inviting, target.nick, ch.name)
	if target.away != '' {
		s.numeric(mut c, rpl_away, target.nick, target.away)
	}
	invite := s.user_msg(c, 'INVITE', [target.nick, ch.name])
	s.send(mut target, invite)
	for id, m in ch.members {
		if id == c.id || !m.op {
			continue
		}
		mut peer := s.clients[id] or { continue }
		if peer.has('invite-notify') {
			s.send(mut peer, invite)
		}
	}
}

fn (mut s Server) cmd_topic(mut c Client, msg ircmsg.Message) {
	if !s.has_params(mut c, msg, 1) {
		return
	}
	mut ch := s.channels[s.fold(msg.params[0])] or {
		s.numeric(mut c, err_nosuchchannel, msg.params[0], 'No such channel')
		return
	}
	member := c.id in ch.members
	if msg.params.len == 1 {
		if !member && ch.secret {
			s.numeric(mut c, err_notonchannel, ch.name, "You're not on that channel")
			return
		}
		if ch.topic == '' {
			s.numeric(mut c, rpl_notopic, ch.name, 'No topic is set')
		} else {
			s.send_topic(mut c, ch)
		}
		return
	}
	if !member {
		s.numeric(mut c, err_notonchannel, ch.name, "You're not on that channel")
		return
	}
	if ch.topic_op && !ch.is_op(c.id) {
		s.numeric(mut c, err_chanoprivsneeded, ch.name, "You're not channel operator")
		return
	}
	ch.topic = truncate(msg.params[1], topic_len)
	ch.topic_by = c.mask()
	ch.topic_at = time.now().unix()
	s.send_channel(ch, s.user_msg(c, 'TOPIC', [ch.name, ch.topic]), 0, '')
}

fn (mut s Server) cmd_names(mut c Client, msg ircmsg.Message) {
	if msg.params.len < 1 || msg.params[0] == '' {
		s.numeric(mut c, rpl_endofnames, '*', 'End of /NAMES list')
		return
	}
	names := msg.params[0].split(',')
	if names.len == 1 {
		ch := s.channels[s.fold(names[0])] or {
			s.numeric(mut c, rpl_endofnames, names[0], 'End of /NAMES list')
			return
		}
		s.send_names(mut c, ch, true)
		return
	}
	for name in names {
		ch := s.channels[s.fold(name)] or { continue }
		s.send_names(mut c, ch, false)
	}
	s.numeric(mut c, rpl_endofnames, msg.params[0], 'End of /NAMES list')
}

fn (mut s Server) cmd_list(mut c Client, msg ircmsg.Message) {
	s.numeric(mut c, rpl_liststart, 'Channel', 'Users  Name')
	mut wanted := map[string]bool{}
	mut min_users := -1
	mut max_users := -1
	for item in msg.param(0).split(',') {
		if item.starts_with('>') {
			min_users = item[1..].int()
		} else if item.starts_with('<') {
			max_users = item[1..].int()
		} else if item != '' {
			wanted[s.fold(item)] = true
		}
	}
	for key, ch in s.channels {
		if wanted.len > 0 && key !in wanted {
			continue
		}
		if ch.secret && c.id !in ch.members {
			continue
		}
		visible := ch.members.len
		if (min_users >= 0 && visible <= min_users) || (max_users >= 0 && visible >= max_users) {
			continue
		}
		modes := ch.mode_string(false).join(' ')
		s.numeric(mut c, rpl_list, ch.name, visible.str(), '[${modes}] ${ch.topic}')
	}
	s.numeric(mut c, rpl_listend, 'End of /LIST')
}

fn (mut s Server) cmd_mode(mut c Client, msg ircmsg.Message) {
	if !s.has_params(mut c, msg, 1) {
		return
	}
	target := msg.params[0]
	if !target.starts_with('#') {
		s.user_mode(mut c, msg)
		return
	}
	mut ch := s.channels[s.fold(target)] or {
		s.numeric(mut c, err_nosuchchannel, target, 'No such channel')
		return
	}
	if msg.params.len == 1 {
		mut params := [ch.name]
		params << ch.mode_string(c.id in ch.members)
		s.numeric(mut c, rpl_channelmodeis, ...params)
		s.numeric(mut c, rpl_creationtime, ch.name, ch.created.str())
		return
	}
	s.channel_mode(mut c, mut ch, msg.params[1], msg.params[2..])
}

fn (mut s Server) user_mode(mut c Client, msg ircmsg.Message) {
	target := msg.params[0]
	if s.fold(target) != s.fold(c.nick) {
		if _ := s.find_nick(target) {
			s.numeric(mut c, err_usersdontmatch, "Can't change mode for other users")
		} else {
			s.numeric(mut c, err_nosuchnick, target, 'No such nick/channel')
		}
		return
	}
	if msg.params.len == 1 {
		mut modes := '+'
		if c.bot {
			modes += 'B'
		}
		if c.invisible {
			modes += 'i'
		}
		if c.oper {
			modes += 'o'
		}
		if c.wallops {
			modes += 'w'
		}
		s.numeric(mut c, rpl_umodeis, modes)
		return
	}
	mut adding := true
	mut changes := []ModeChange{}
	mut unknown := false
	for ch in msg.params[1] {
		sign := if adding { u8(`+`) } else { u8(`-`) }
		match ch {
			`+` {
				adding = true
			}
			`-` {
				adding = false
			}
			`i` {
				if c.invisible != adding {
					c.invisible = adding
					changes << ModeChange{sign, ch, ''}
				}
			}
			`B` {
				if c.bot != adding {
					c.bot = adding
					changes << ModeChange{sign, ch, ''}
				}
			}
			`w` {
				if c.wallops != adding {
					c.wallops = adding
					changes << ModeChange{sign, ch, ''}
				}
			}
			`o` {
				// Operator status is only given by OPER; it can be dropped.
				if !adding && c.oper {
					c.oper = false
					changes << ModeChange{sign, ch, ''}
				}
			}
			else {
				unknown = true
			}
		}
	}
	if unknown {
		s.numeric(mut c, err_umodeunknownflag, 'Unknown MODE flag')
	}
	for params in mode_lines(c.mask(), c.nick, changes) {
		s.send(mut c, ircmsg.Message{
			source:  c.mask()
			command: 'MODE'
			params:  params
		})
	}
}

fn (mut s Server) channel_mode(mut c Client, mut ch Channel, modes string, args []string) {
	mut adding := true
	mut arg_i := 0
	mut changes := []ModeChange{}
	mut param_modes := 0
	is_op := ch.is_op(c.id)
	for m in modes {
		if m == `+` {
			adding = true
			continue
		}
		if m == `-` {
			adding = false
			continue
		}
		sign := if adding { u8(`+`) } else { u8(`-`) }
		if m == `b` && arg_i >= args.len {
			// A ban list query.
			for b in ch.bans {
				s.numeric(mut c, rpl_banlist, ch.name, b.mask, b.set_by, b.set_at.str())
			}
			s.numeric(mut c, rpl_endofbanlist, ch.name, 'End of channel ban list')
			continue
		}
		if m !in [`b`, `k`, `l`, `o`, `v`, `i`, `m`, `n`, `s`, `t`] {
			s.numeric(mut c, err_unknownmode, m.ascii_str(), 'is unknown mode char to me')
			continue
		}
		if !is_op {
			s.numeric(mut c, err_chanoprivsneeded, ch.name, "You're not channel operator")
			return
		}
		needs_arg := m in [`b`, `o`, `v`] || (m == `k` && adding) || (m == `l` && adding)
		mut arg := ''
		if needs_arg {
			if arg_i >= args.len {
				if m != `k` || adding {
					s.numeric(mut c, err_needmoreparams, 'MODE', 'Not enough parameters')
				}
				continue
			}
			if param_modes >= max_modes {
				continue
			}
			arg = args[arg_i]
			arg_i++
			param_modes++
		} else if m == `k` && arg_i < args.len {
			// `-k` may carry the key; it is ignored.
			arg_i++
		}
		mut changed := false
		mut shown := arg
		match m {
			`i` {
				changed = ch.invite != adding
				ch.invite = adding
			}
			`m` {
				changed = ch.moderated != adding
				ch.moderated = adding
			}
			`n` {
				changed = ch.no_ext != adding
				ch.no_ext = adding
			}
			`s` {
				changed = ch.secret != adding
				ch.secret = adding
			}
			`t` {
				changed = ch.topic_op != adding
				ch.topic_op = adding
			}
			`k` {
				if adding {
					if !valid_key(arg) {
						s.numeric(mut c, err_invalidmodeparam, ch.name, 'k', '*', 'Invalid key')
						continue
					}
					changed = ch.key != arg
					ch.key = arg
				} else {
					changed = ch.key != ''
					shown = '*'
					ch.key = ''
				}
			}
			`l` {
				if adding {
					limit := arg.int()
					if limit <= 0 {
						s.numeric(mut c, err_invalidmodeparam, ch.name, 'l', if arg == '' {
							'*'
						} else {
							arg
						}, 'Invalid limit')
						continue
					}
					changed = ch.limit != limit
					ch.limit = limit
					shown = limit.str()
				} else {
					changed = ch.limit != 0
					ch.limit = 0
				}
			}
			`o`, `v` {
				target := s.find_nick(arg) or {
					s.numeric(mut c, err_nosuchnick, arg, 'No such nick/channel')
					continue
				}
				mut member := ch.members[target.id] or {
					s.numeric(mut c, err_usernotinchannel, target.nick, ch.name, "They aren't on that channel")
					continue
				}
				if m == `o` {
					changed = member.op != adding
					member.op = adding
				} else {
					changed = member.voice != adding
					member.voice = adding
				}
				ch.members[target.id] = member
				shown = target.nick
			}
			`b` {
				mask := normalize_mask(arg)
				if mask.len > max_mask_len || mask.contains(' ') || mask.starts_with(':') {
					s.numeric(mut c, err_invalidmodeparam, ch.name, 'b', '*', 'Invalid ban mask')
					continue
				}
				folded := s.fold(mask)
				idx := ch.bans.map(s.fold(it.mask)).index(folded)
				if adding {
					if idx < 0 && ch.bans.len < max_list_masks {
						ch.bans << Ban{
							mask:   mask
							set_by: c.mask()
							set_at: time.now().unix()
						}
						changed = true
					}
				} else if idx >= 0 {
					ch.bans.delete(idx)
					changed = true
				}
				shown = mask
			}
			else {}
		}
		if changed {
			changes << ModeChange{sign, m, if needs_arg || m == `k` { shown } else { '' }}
		}
	}
	for params in mode_lines(c.mask(), ch.name, changes) {
		s.send_channel(ch, s.user_msg(c, 'MODE', params), 0, '')
	}
}

// ModeChange is one applied mode change, with its argument if it has one.
struct ModeChange {
	sign u8
	mode u8
	arg  string
}

// mode_lines returns the parameters of the MODE lines announcing `changes` to
// `target`: as many lines as needed to stay within the line limit, without
// cutting a change.
fn mode_lines(source string, target string, changes []ModeChange) [][]string {
	// The base counts ` :` after the target: the space before the modes, and a
	// `:` the last argument may need.
	room := ircmsg.max_line_bytes - 2 - ircmsg.Message{
		source:  source
		command: 'MODE'
		params:  [target, '']
	}.str().len
	mut lines := [][]string{}
	mut params := [target, '']
	mut size := 0
	mut last := u8(0)
	for change in changes {
		arg_size := if change.arg == '' { 0 } else { change.arg.len + 1 }
		if params[1] != '' && size + 2 + arg_size > room {
			lines << params
			params = [target, '']
			size = 0
			last = 0
		}
		if change.sign != last {
			params[1] += change.sign.ascii_str()
			last = change.sign
			size++
		}
		params[1] += change.mode.ascii_str()
		size++
		if change.arg != '' {
			params << change.arg
			size += arg_size
		}
	}
	if params[1] != '' {
		lines << params
	}
	return lines
}

// valid_key reports whether `key` can be a channel key: 1 to 23 printable
// characters (RFC 2812), without spaces or commas, which would break JOIN, and
// not starting with `:`, so that it can be any parameter of JOIN and MODE.
fn valid_key(key string) bool {
	if key == '' || key.len > 23 || key.starts_with(':') {
		return false
	}
	for ch in key {
		if ch <= ` ` || ch == `,` || ch == 0x7f {
			return false
		}
	}
	return true
}

// normalize_mask completes a ban mask to the `nick!user@host` form.
fn normalize_mask(mask string) string {
	mut m := mask
	if !m.contains('!') && !m.contains('@') {
		m = m + '!*@*'
	} else if !m.contains('!') {
		m = '*!' + m
	} else if !m.contains('@') {
		m = m + '@*'
	}
	return m
}
