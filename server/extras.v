module server

import ircmsg
import time

// max_stored_markers bounds the read markers sent when an account connects.
const max_stored_markers = 100
// max_markers bounds the read markers kept per account or connection: setting
// one for a new target past the limit drops the oldest marker (by its time).
const max_markers = 1000

// MARKREAD (https://ircv3.net/specs/extensions/read-marker). Markers of an
// account are stored and shared by its connections; a client without an
// account keeps them for the connection only.
fn (mut s Server) cmd_markread(mut c Client, msg ircmsg.Message) {
	if msg.params.len < 1 || msg.params[0] == '' {
		s.fail(mut c, 'MARKREAD', 'NEED_MORE_PARAMS', 'Missing target')
		return
	}
	target := msg.params[0]
	if !valid_channel(target) && !valid_nick(target) {
		s.fail(mut c, 'MARKREAD', 'INVALID_PARAMS', target, 'Invalid target')
		return
	}
	if msg.params.len == 1 {
		s.send_marker(mut c, target)
		return
	}
	raw := msg.params[1]
	ms := if raw.starts_with('timestamp=') { parse_server_time(raw[10..]) } else { none }
	if ms == none {
		s.fail(mut c, 'MARKREAD', 'INVALID_PARAMS', target, 'Invalid timestamp')
		return
	}
	key := s.fold(target)
	if c.account_id == 0 {
		if key !in c.read_markers && c.read_markers.len >= max_markers {
			mut oldest := ''
			mut oldest_ms := max_i64
			for k, v in c.read_markers {
				if v < oldest_ms {
					oldest, oldest_ms = k, v
				}
			}
			c.read_markers.delete(oldest)
		}
		if ms > c.read_markers[key] {
			c.read_markers[key] = ms
		}
		s.send_marker(mut c, target)
		return
	}
	stored := s.db.set_marker(c.account_id, key, ms, max_markers) or {
		s.fail(mut c, 'MARKREAD', 'INTERNAL_ERROR', target, 'Could not store the read marker')
		return
	}
	line := s.marker_msg(target, stored)
	// Every connection of the account learns the new marker.
	for _, mut peer in s.clients {
		if peer.account_id == c.account_id && peer.registered && peer.has('draft/read-marker') {
			s.send(mut peer, line)
		}
	}
	if !c.has('draft/read-marker') {
		s.send(mut c, line)
	}
}

fn (mut s Server) marker_msg(target string, ms i64) ircmsg.Message {
	return ircmsg.Message{
		source:  s.cfg.name
		command: 'MARKREAD'
		params:  [target,
			if ms > 0 { 'timestamp=${time.unix_milli(ms).format_rfc3339()}' } else { '*' }]
	}
}

// send_marker sends the read marker of `target`, or `*` when there is none.
fn (mut s Server) send_marker(mut c Client, target string) {
	key := s.fold(target)
	ms := if c.account_id > 0 {
		s.db.get_marker(c.account_id, key) or {
			s.fail(mut c, 'MARKREAD', 'INTERNAL_ERROR', target, 'Could not read the read marker')
			return
		}
	} else {
		c.read_markers[key]
	}
	s.send(mut c, s.marker_msg(target, ms))
}

// send_stored_markers sends the most recent read markers of the account when a
// client registers, so that it can show what was read on other devices.
fn (mut s Server) send_stored_markers(mut c Client) {
	if c.account_id == 0 || !c.has('draft/read-marker') {
		return
	}
	markers := s.db.markers(c.account_id, max_stored_markers) or {
		log_error('cannot read stored read markers', err)
		return
	}
	for m in markers {
		name := if ch := s.channels[m.target] { ch.name } else { m.target }
		s.send(mut c, s.marker_msg(name, m.time_ms))
	}
}

const help_topics = {
	'':            ['vIRCd is an IRCv3 server. Commands: ' + help_commands.join(' '),
		'Use HELP <command> for details.']
	'PRIVMSG':     ['PRIVMSG <target>[,<target>] :<text>', 'Sends a message to channels or nicknames.']
	'NOTICE':      ['NOTICE <target>[,<target>] :<text>',
		'Like PRIVMSG, but never answered automatically.']
	'JOIN':        ['JOIN <channel>[,<channel>] [<key>[,<key>]]',
		'Joins channels; JOIN 0 leaves them all.']
	'PART':        ['PART <channel>[,<channel>] [:<reason>]', 'Leaves channels.']
	'MODE':        ['MODE <target> [<modes> [<params>]]',
		'Channel modes: b k l i m n s t o v. User modes: B i o w.']
	'MONITOR':     ['MONITOR {+|-} <nick>[,<nick>] | MONITOR {C|L|S}',
		'Tells you when nicknames come online or go offline.']
	'MARKREAD':    ['MARKREAD <target> [timestamp=<time>]',
		'Gets or sets the read marker of a conversation.']
	'CHATHISTORY': ['CHATHISTORY <subcommand> <target> <reference> <limit>',
		'Replays stored messages (draft/chathistory).']
}

const help_commands = ['ADMIN', 'AWAY', 'CAP', 'CHATHISTORY', 'HELP', 'INFO', 'INVITE', 'ISON',
	'JOIN', 'KICK', 'KILL', 'LINKS', 'LIST', 'LUSERS', 'MARKREAD', 'MODE', 'MONITOR', 'MOTD', 'NAMES',
	'NICK', 'NOTICE', 'OPER', 'PART', 'PING', 'PRIVMSG', 'QUIT', 'SETNAME', 'TAGMSG', 'TIME', 'TOPIC',
	'USERHOST', 'VERSION', 'WALLOPS', 'WHO', 'WHOIS', 'WHOWAS']!

fn (mut s Server) cmd_help(mut c Client, msg ircmsg.Message) {
	subject := msg.param(0).to_upper()
	lines := help_topics[subject] or {
		if subject in help_commands {
			['${subject}: see https://modern.ircdocs.horse']
		} else {
			s.numeric(mut c, err_helpnotfound, msg.param(0), 'No help available on this topic')
			return
		}
	}
	shown := if subject == '' { '*' } else { subject }
	s.numeric(mut c, rpl_helpstart, shown, lines[0])
	for line in lines[1..] {
		s.numeric(mut c, rpl_helptxt, shown, line)
	}
	s.numeric(mut c, rpl_endofhelp, shown, 'End of /HELP')
}

fn (mut s Server) cmd_links(mut c Client) {
	s.numeric(mut c, rpl_links, s.cfg.name, s.cfg.name, '0 ${s.cfg.description}')
	s.numeric(mut c, rpl_endoflinks, '*', 'End of /LINKS list')
}

// WALLOPS goes from an operator to every client with user mode +w, and back
// to the sender.
fn (mut s Server) cmd_wallops(mut c Client, msg ircmsg.Message) {
	if !s.has_params(mut c, msg, 1) {
		return
	}
	if !c.oper {
		s.numeric(mut c, err_noprivileges, 'Permission Denied- You do not have the correct IRC operator privileges')
		return
	}
	out := s.user_msg(c, 'WALLOPS', [truncate(msg.params[0], topic_len)])
	for _, mut peer in s.clients {
		if peer.registered && (peer.wallops || peer.id == c.id) {
			s.send(mut peer, out)
		}
	}
}
