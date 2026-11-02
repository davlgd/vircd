module server

import crypto.scram
import ircmsg
import log
import time

// Client is one connection, owned by the dispatcher.
@[heap]
struct Client {
	id   int
	out  chan string
	link &Link
	ip   string
	tls  bool
mut:
	host        string
	nick        string
	user        string
	real        string
	registered  bool
	got_user    bool
	pass_ok     bool
	cap_version int
	negotiating bool
	caps        map[string]bool
	account     string
	account_id  int
	away        string
	invisible   bool
	oper        bool
	bot         bool
	wallops     bool
	// read_markers holds the read markers of a client without an account.
	read_markers map[string]i64
	// channels holds the folded names of the channels the client is in.
	channels     map[string]bool
	invited      map[string]bool
	monitor      map[string]bool
	connected    time.Time
	last_active  time.Time
	last_message time.Time
	ping_pending bool
	ping_sent    time.Time
	// dead is set when the client must go; gone once it is removed.
	dead        bool
	gone        bool
	quit_reason string
	// SASL state.
	sasl_mech     string
	sasl_buffer   string
	sasl_scram    &scram.Server = unsafe { nil }
	sasl_failures int
	auth_pending  bool
	sasl_binding  &AuthBinding = unsafe { nil }
	pending       []string
}

fn (c &Client) has(cap string) bool {
	return c.caps[cap] or { false }
}

// target is the name numerics are addressed to: the nickname, or `*` before NICK.
fn (c &Client) target() string {
	return if c.nick == '' { '*' } else { c.nick }
}

fn (c &Client) mask() string {
	return '${c.nick}!${c.user}@${c.host}'
}

// Capture collects the replies to a labeled command (labeled-response).
@[heap]
struct Capture {
	id    int
	label string
mut:
	lines []ircmsg.Message
}

// tag_cap is the capability a client needs to receive a tag.
fn tag_cap(key string) string {
	return match key {
		'time' { 'server-time' }
		'account' { 'account-tag' }
		'batch' { 'batch' }
		'label' { 'labeled-response' }
		else { 'message-tags' }
	}
}

// send queues a message for a client, keeping only the tags its capabilities
// allow. While a labeled command runs, the replies to its client are held back
// in the capture instead.
fn (mut s Server) send(mut c Client, msg ircmsg.Message) {
	if s.capture != unsafe { nil } && s.capture.id == c.id {
		s.capture.lines << msg
		return
	}
	s.send_now(mut c, msg)
}

fn (mut s Server) send_now(mut c Client, msg ircmsg.Message) {
	if c.gone {
		return
	}
	mut m := msg
	if m.tags.len > 0 {
		m.tags = msg.tags.filter(c.has(tag_cap(it.key)))
	}
	line := wire_line(m) or {
		log.error('dropped a ${m.command} line longer than ${ircmsg.max_line_bytes} bytes')
		return
	}
	s.send_raw(mut c, line)
}

// text_commands end with a free text parameter, which wire_line may shorten.
const text_commands = ['AWAY', 'ERROR', 'FAIL', 'JOIN', 'KICK', 'NOTICE', 'PART', 'PRIVMSG', 'QUIT',
	'SETNAME', 'TOPIC', 'WALLOPS']!

// wire_line serializes a message within the protocol line limit (tags apart).
// The limits on names and arguments keep structured messages within it; when a
// free text (a topic, a reason, a real name) makes the line too long, the text
// is shortened. Lists are split before (numeric_list). It fails for a line that
// cannot be brought within the limit.
fn wire_line(msg ircmsg.Message) ?string {
	line := msg.str()
	_, rest := ircmsg.split_tags(line)
	excess := rest - (ircmsg.max_line_bytes - 2)
	if excess <= 0 {
		return line
	}
	numeric := msg.command.len == 3 && msg.command[0].is_digit()
	if msg.params.len == 0 || !(numeric || msg.command in text_commands)
		|| msg.params.last().len <= excess {
		return none
	}
	mut params := msg.params.clone()
	params[params.len - 1] = truncate(params.last(), params.last().len - excess)
	return ircmsg.Message{
		...msg
		params: params
	}.str()
}

// send_raw queues a line; a client whose queue is full is disconnected.
fn (mut s Server) send_raw(mut c Client, line string) {
	if c.gone {
		return
	}
	if c.out.try_push(line + '\r\n') != .success {
		s.kill(mut c, 'SendQ exceeded')
	}
}

// flush_capture sends the replies of a labeled command: an ACK when there are
// none, the reply with a `label` tag when there is one, a labeled-response
// batch otherwise.
fn (mut s Server) flush_capture(mut c Client) {
	capture := s.capture
	s.capture = unsafe { nil }
	label := ircmsg.Tag{'label', capture.label}
	if capture.lines.len == 0 {
		s.send_now(mut c, ircmsg.Message{
			tags:    [label]
			source:  s.cfg.name
			command: 'ACK'
		})
		return
	}
	if capture.lines.len == 1 {
		mut m := capture.lines[0]
		m.tags = [label]
		m.tags << capture.lines[0].tags
		s.send_now(mut c, m)
		return
	}
	if !c.has('batch') {
		for m in capture.lines {
			s.send_now(mut c, m)
		}
		return
	}
	id := s.next_msgid()
	s.send_now(mut c, ircmsg.Message{
		tags:    [label]
		source:  s.cfg.name
		command: 'BATCH'
		params:  ['+' + id, 'labeled-response']
	})
	for line in capture.lines {
		mut m := line
		if !line.has_tag('batch') {
			m.tags = [ircmsg.Tag{'batch', id}]
			m.tags << line.tags
		}
		s.send_now(mut c, m)
	}
	s.send_now(mut c, ircmsg.Message{
		source:  s.cfg.name
		command: 'BATCH'
		params:  ['-' + id]
	})
}

// numeric_list sends a numeric whose last parameter is a list of `items`
// joined by `sep`, on as many lines as needed: an item is never cut.
fn (mut s Server) numeric_list(mut c Client, code string, params []string, items []string, sep string) {
	mut fixed := [c.target()]
	fixed << params
	fixed << ''
	room := ircmsg.max_line_bytes - 2 - ircmsg.Message{
		source:  s.cfg.name
		command: code
		params:  fixed
	}.str().len
	mut start := 0
	mut size := 0
	for i, item in items {
		if i > start && size + sep.len + item.len > room {
			s.numeric(mut c, code, ...with_list(params, items[start..i], sep))
			start = i
			size = 0
		}
		size += if i > start { sep.len + item.len } else { item.len }
	}
	if items.len > start {
		s.numeric(mut c, code, ...with_list(params, items[start..], sep))
	}
}

fn with_list(params []string, items []string, sep string) []string {
	mut p := params.clone()
	p << items.join(sep)
	return p
}

// has_params reports whether `msg` has at least `n` parameters, the first one
// not empty; otherwise it answers ERR_NEEDMOREPARAMS.
fn (mut s Server) has_params(mut c Client, msg ircmsg.Message, n int) bool {
	if msg.params.len >= n && msg.params[0] != '' {
		return true
	}
	s.numeric(mut c, err_needmoreparams, msg.command, 'Not enough parameters')
	return false
}

// numeric sends a numeric reply to the client.
fn (mut s Server) numeric(mut c Client, code string, params ...string) {
	mut p := [c.target()]
	p << params
	s.send(mut c, ircmsg.Message{
		source:  s.cfg.name
		command: code
		params:  p
	})
}

// fail sends a standard reply FAIL (https://ircv3.net/specs/extensions/standard-replies).
fn (mut s Server) fail(mut c Client, command string, code string, params ...string) {
	mut p := [command, code]
	p << params
	s.send(mut c, ircmsg.Message{
		source:  s.cfg.name
		command: 'FAIL'
		params:  p
	})
}

// user_msg builds a message sent on behalf of a client, with the server tags.
fn (mut s Server) user_msg(c &Client, command string, params []string) ircmsg.Message {
	mut tags := [ircmsg.Tag{'time', time.utc().format_rfc3339()}]
	if c.account != '' {
		tags << ircmsg.Tag{'account', c.account}
	}
	return ircmsg.Message{
		tags:    tags
		source:  c.mask()
		command: command
		params:  params
	}
}

// send_to_peers sends a message to every client sharing a channel with `c`,
// optionally including `c`, and only to clients with `cap` when it is set.
fn (mut s Server) send_to_peers(c &Client, msg ircmsg.Message, include_self bool, cap string) {
	mut seen := map[int]bool{}
	if !include_self {
		seen[c.id] = true
	}
	for key, _ in c.channels {
		ch := s.channels[key] or { continue }
		for id, _ in ch.members {
			if id in seen {
				continue
			}
			seen[id] = true
			mut peer := s.clients[id] or { continue }
			if cap == '' || peer.has(cap) {
				s.send(mut peer, msg)
			}
		}
	}
	if include_self && c.id !in seen {
		seen[c.id] = true
		mut me := s.clients[c.id] or { return }
		if cap == '' || me.has(cap) {
			s.send(mut me, msg)
		}
	}
	// extended-monitor: clients monitoring `c` get the same notifications.
	if cap != '' {
		key := s.fold(c.nick)
		if key in s.monitors {
			for id in s.monitors[key].keys() {
				if id in seen {
					continue
				}
				mut w := s.clients[id] or { continue }
				if w.registered && w.has('extended-monitor') && w.has(cap) {
					s.send(mut w, msg)
				}
			}
		}
	}
}
