// Module server is the IRC server: one acceptor thread, one reader and one
// writer thread per connection, and a single dispatcher thread that owns all
// the server state (clients, nicknames, channels), so that no state is shared.
module server

import crypto.rand
import encoding.utf8
import ircmsg
import log
import net
import net.mbedtls
import store
import sync.stdatomic
import time

enum EventKind {
	connected
	line
	too_long
	closed
	auth_done
	tick
	released
}

// Event is what the other threads tell the dispatcher.
struct Event {
	kind EventKind
	id   int
	line string
	// connected
	out  chan string
	link &Link = unsafe { nil }
	ip   string
	tls  bool
	// auth_done
	auth_ok     bool
	account_id  int
	credentials string
}

// Server is the dispatcher state. Only the dispatcher thread touches it,
// except `events`, which every thread posts to.
@[heap]
pub struct Server {
	cfg    Config
	events chan Event = chan Event{cap: 8192}
mut:
	tcp        &net.TcpListener     = unsafe { nil }
	tls        &mbedtls.SSLListener = unsafe { nil }
	clients    map[int]&Client
	nicks      map[string]int
	channels   map[string]&Channel
	db         &store.Store = unsafe { nil }
	created    time.Time
	whowas     []WhowasEntry
	monitors   map[string]map[int]bool
	auth_queue []AuthJob
	auth_busy  int
	capture    &Capture = unsafe { nil }
	max_seen   int
	// guest_seq numbers the Guest nicknames given to clients that lose a reserved nickname.
	guest_seq  int
	msgid_base string
	msgid_seq  u64
	per_ip     map[string]int
	// closing maps the clients removed but whose threads still run to their address.
	closing map[int]string
	// history_writes counts messages per conversation since its last pruning.
	history_writes map[string]int
	loopback       bool
}

// new_server checks the configuration, opens the database and binds the listener.
pub fn new_server(cfg Config) !&Server {
	if (cfg.tls_cert == '') != (cfg.tls_key == '') {
		return error('--tls-cert and --tls-key go together')
	}
	if !valid_name(cfg.name, 63) || !valid_name(cfg.network, 32) {
		return error('--name and --network take letters, digits, `.`, `-` and `_` (at most 63 and 32 bytes)')
	}
	if !utf8.validate_str(cfg.description) || cfg.motd.any(!utf8.validate_str(it)) {
		return error('the description and the MOTD must be UTF-8')
	}
	if cfg.flood_rate < 0 || cfg.flood_burst < 1 || cfg.history_limit < 0 || cfg.max_per_ip < 1 {
		return error('--flood-rate and --history cannot be negative; --flood-burst and --max-per-ip must be at least 1')
	}
	mut s := &Server{
		cfg:     cfg
		created: time.now()
	}
	s.db = store.open(cfg.db)!
	s.msgid_base = rand.bytes(6)!.hex()
	if cfg.tls_cert != '' {
		check_tls_compiler()!
		s.tls = mbedtls.new_ssl_listener(cfg.listen, mbedtls.SSLConnectConfig{
			cert:     cfg.tls_cert
			cert_key: cfg.tls_key
		})!
		host := cfg.listen.all_before_last(':').trim('[]')
		s.loopback = is_loopback(host)
	} else {
		family := if cfg.listen.starts_with('[') { net.AddrFamily.ip6 } else { net.AddrFamily.ip }
		s.tcp = net.listen_tcp(family, cfg.listen)!
		s.loopback = is_loopback(s.tcp.addr()!.str().all_before_last(':').trim('[]'))
	}
	return s
}

fn is_loopback(host string) bool {
	return host.starts_with('127.') || host == '::1' || host == 'localhost'
}

// run serves clients until the process stops.
pub fn (mut s Server) run() {
	spawn ticker(s.events)
	if s.tls != unsafe { nil } {
		log.info('${version} listening on ${s.cfg.listen} (TLS)')
		spawn accept_tls(mut s.tls, s.events, s.cfg)
	} else {
		log.info('${version} listening on ${s.cfg.listen}')
		spawn accept_tcp(mut s.tcp, s.events, s.cfg)
	}
	for {
		ev := <-s.events or { return }
		s.handle_event(ev)
	}
}

fn ticker(events chan Event) {
	for {
		time.sleep(time.second)
		events <- Event{
			kind: .tick
		}
	}
}

fn accept_tcp(mut l net.TcpListener, events chan Event, cfg Config) {
	mut next_id := 1
	for {
		mut conn := l.accept() or {
			log.warn('accept failed: ${err}')
			time.sleep(10 * time.millisecond)
			continue
		}
		conn.set_read_timeout(net.infinite_timeout)
		conn.set_write_timeout(60 * time.second)
		ip := conn.peer_ip() or { '?' }
		mut link := tcp_link(mut conn)
		start_client(mut link, next_id, ip, false, events, cfg)
		next_id++
	}
}

// max_handshakes bounds the TLS handshakes running at once, before the
// dispatcher can apply its connection limits.
const max_handshakes = 64

fn accept_tls(mut l mbedtls.SSLListener, events chan Event, cfg Config) {
	mut next_id := 1
	mut handshakes := stdatomic.new_atomic(i64(0))
	for {
		mut conn := l.accept_raw_with_timeout(net.infinite_timeout) or {
			log.warn('accept failed: ${err}')
			time.sleep(10 * time.millisecond)
			continue
		}
		if handshakes.load() >= max_handshakes {
			conn.shutdown() or {}
			continue
		}
		handshakes.add(1)
		spawn tls_handshake(mut conn, next_id, events, cfg, mut handshakes)
		next_id++
	}
}

fn tls_handshake(mut conn mbedtls.SSLConn, id int, events chan Event, cfg Config, mut handshakes stdatomic.AtomicVal[i64]) {
	defer {
		handshakes.sub(1)
	}
	conn.complete_handshake(10 * time.second) or {
		conn.shutdown() or {}
		return
	}
	ip := conn.peer_addr() or {
		conn.shutdown() or {}
		return
	}.str().all_before_last(':').trim('[]')
	mut link := tls_link(mut conn) or {
		conn.shutdown() or {}
		return
	}
	start_client(mut link, id, ip, true, events, cfg)
}

// start_client registers the connection with the dispatcher, then starts its
// threads. The `connected` event is posted first, so it precedes every line.
fn start_client(mut link Link, id int, ip string, tls bool, events chan Event, cfg Config) {
	out := chan string{cap: cfg.sendq}
	link.id = id
	link.events = events
	events <- Event{
		kind: .connected
		id:   id
		out:  out
		link: link
		ip:   ip
		tls:  tls
	}
	spawn writer(mut link, out)
	spawn reader(mut link, id, events, cfg)
}

fn (mut s Server) handle_event(ev Event) {
	match ev.kind {
		.connected {
			s.on_connect(ev)
		}
		.line {
			mut c := s.clients[ev.id] or { return }
			if c.dead {
				return
			}
			if c.auth_pending {
				if c.pending.len >= 100 {
					s.kill(mut c, 'Excess flood')
				} else {
					c.pending << ev.line
				}
				return
			}
			s.handle_line(mut c, ev.line)
		}
		.too_long {
			mut c := s.clients[ev.id] or { return }
			s.numeric(mut c, err_inputtoolong, 'Input line was too long')
		}
		.closed {
			if mut c := s.clients[ev.id] {
				s.quit(mut c, if c.dead { c.quit_reason } else { 'Connection closed' })
			}
		}
		.released {
			// Both threads are done and the descriptor is closed: the connection no
			// longer counts against the limits.
			if ip := s.closing[ev.id] {
				s.closing.delete(ev.id)
				s.per_ip[ip]--
				if s.per_ip[ip] <= 0 {
					s.per_ip.delete(ip)
				}
			}
		}
		.auth_done {
			s.on_auth_done(ev)
		}
		.tick {
			s.on_tick()
		}
	}
}

fn (mut s Server) on_connect(ev Event) {
	if s.clients.len + s.closing.len >= s.cfg.max_clients || s.per_ip[ev.ip] >= s.cfg.max_per_ip {
		ev.out.try_push('ERROR :Closing link: too many connections\r\n')
		ev.out.try_push(close_marker)
		return
	}
	now := time.now()
	mut c := &Client{
		id:          ev.id
		out:         ev.out
		link:        ev.link
		ip:          ev.ip
		host:        display_host(ev.ip)
		tls:         ev.tls
		connected:   now
		last_active: now
		pass_ok:     s.cfg.password == ''
	}
	s.clients[c.id] = c
	s.per_ip[ev.ip]++
}

// display_host is the host shown in masks: IPv6 addresses starting with `:`
// would read as a trailing parameter, so they get a leading 0.
fn display_host(ip string) string {
	return if ip.starts_with(':') { '0' + ip } else { ip }
}

// handle_line parses and runs one line of a client.
fn (mut s Server) handle_line(mut c Client, line string) {
	c.last_active = time.now()
	c.ping_pending = false
	tags_len, rest_len := ircmsg.split_tags(line)
	if tags_len > ircmsg.max_client_tags_bytes || rest_len > ircmsg.max_line_bytes - 2 {
		s.numeric(mut c, err_inputtoolong, 'Input line was too long')
		return
	}
	msg := ircmsg.parse(line) or { return }
	label := msg.tag('label') or { '' }
	if !utf8.validate_str(line) {
		// UTF8ONLY: nothing that is not UTF-8 is relayed or stored.
		s.fail(mut c, msg.command, 'INVALID_UTF8', 'Message rejected, your IRC software MUST use UTF-8 encoding on this network')
		return
	}
	if label != '' && c.has('labeled-response') && label.len <= 64 {
		s.capture = &Capture{
			id:    c.id
			label: label
		}
		s.dispatch(mut c, msg)
		s.flush_capture(mut c)
	} else {
		s.dispatch(mut c, msg)
	}
	s.reap()
}

// reap removes clients killed while running a command, once the command is done.
fn (mut s Server) reap() {
	for _, mut c in s.clients {
		if c.dead && !c.gone {
			s.quit(mut c, c.quit_reason)
		}
	}
}

fn (mut s Server) dispatch(mut c Client, msg ircmsg.Message) {
	match msg.command {
		'CAP' {
			s.cmd_cap(mut c, msg)
			return
		}
		'AUTHENTICATE' {
			s.cmd_authenticate(mut c, msg)
			return
		}
		'PASS' {
			s.cmd_pass(mut c, msg)
			return
		}
		'NICK' {
			s.cmd_nick(mut c, msg)
			return
		}
		'USER' {
			s.cmd_user(mut c, msg)
			return
		}
		'PING' {
			s.cmd_ping(mut c, msg)
			return
		}
		'PONG' {
			return
		}
		'QUIT' {
			reason := msg.param(0)
			s.kill(mut c, if reason == '' { 'Quit' } else { 'Quit: ${truncate(reason, kick_len)}' })
			return
		}
		else {}
	}
	if !c.registered {
		s.numeric(mut c, err_notregistered, 'You have not registered')
		return
	}
	match msg.command {
		'PRIVMSG', 'NOTICE', 'TAGMSG' { s.cmd_message(mut c, msg) }
		'JOIN' { s.cmd_join(mut c, msg) }
		'PART' { s.cmd_part(mut c, msg) }
		'KICK' { s.cmd_kick(mut c, msg) }
		'INVITE' { s.cmd_invite(mut c, msg) }
		'TOPIC' { s.cmd_topic(mut c, msg) }
		'NAMES' { s.cmd_names(mut c, msg) }
		'LIST' { s.cmd_list(mut c, msg) }
		'MODE' { s.cmd_mode(mut c, msg) }
		'WHO' { s.cmd_who(mut c, msg) }
		'WHOIS' { s.cmd_whois(mut c, msg) }
		'WHOWAS' { s.cmd_whowas(mut c, msg) }
		'AWAY' { s.cmd_away(mut c, msg) }
		'ISON' { s.cmd_ison(mut c, msg) }
		'USERHOST' { s.cmd_userhost(mut c, msg) }
		'MOTD' { s.send_motd(mut c) }
		'LUSERS' { s.send_lusers(mut c) }
		'VERSION' { s.cmd_version(mut c) }
		'TIME' { s.cmd_time(mut c) }
		'INFO' { s.cmd_info(mut c) }
		'ADMIN' { s.cmd_admin(mut c) }
		'SETNAME' { s.cmd_setname(mut c, msg) }
		'MONITOR' { s.cmd_monitor(mut c, msg) }
		'CHATHISTORY' { s.cmd_chathistory(mut c, msg) }
		'OPER' { s.cmd_oper(mut c, msg) }
		'KILL' { s.cmd_kill(mut c, msg) }
		'MARKREAD' { s.cmd_markread(mut c, msg) }
		'HELP', 'HELPOP' { s.cmd_help(mut c, msg) }
		'LINKS' { s.cmd_links(mut c) }
		'WALLOPS' { s.cmd_wallops(mut c, msg) }
		else { s.numeric(mut c, err_unknowncommand, msg.command, 'Unknown command') }
	}
}

fn (mut s Server) on_tick() {
	now := time.now()
	for _, mut c in s.clients {
		if c.dead {
			continue
		}
		if !c.registered {
			if now - c.connected > s.cfg.registration_timeout {
				s.kill(mut c, 'Registration timeout')
			}
			continue
		}
		idle := now - c.last_active
		if c.ping_pending {
			if now - c.ping_sent > s.cfg.ping_timeout {
				s.kill(mut c, 'Ping timeout: ${int(idle.seconds())} seconds')
			}
		} else if idle > s.cfg.ping_interval {
			c.ping_pending = true
			c.ping_sent = now
			s.send_raw(mut c, 'PING :${s.cfg.name}')
		}
	}
	s.reap()
}

// kill marks a client for disconnection; `reap` (or the reader closing) finishes it.
fn (mut s Server) kill(mut c Client, reason string) {
	if c.dead {
		return
	}
	c.dead = true
	c.quit_reason = reason
}

// quit removes a client: it tells its channels and monitors, then queues ERROR
// and the close marker, which makes the writer close the connection.
fn (mut s Server) quit(mut c Client, reason string) {
	if c.gone {
		return
	}
	c.gone = true
	c.dead = true
	if c.registered {
		s.send_to_peers(c, s.user_msg(c, 'QUIT', [reason]), false, '')
		for key in c.channels.keys() {
			mut ch := s.channels[key] or { continue }
			s.leave(mut c, mut ch)
		}
		s.add_whowas(c)
		s.notify_monitors(c.nick, false, c)
		s.remove_monitors(c)
	}
	if c.nick != '' {
		key := s.fold(c.nick)
		if s.nicks[key] or { 0 } == c.id {
			s.nicks.delete(key)
		}
	}
	// send_raw ignores clients that are gone, so the last line is queued directly.
	error_line := wire_line(ircmsg.Message{
		command: 'ERROR'
		params:  ['Closing link: (${c.user}@${c.host}) [${reason}]']
	}) or { 'ERROR :Closing link' }
	c.out.try_push(error_line + '\r\n')
	if c.out.try_push(close_marker) != .success {
		// The queue is full: the writer may be stuck on a client that does not
		// read. Wake both threads; the remaining lines are dropped.
		c.out.close()
		c.link.wake()
	}
	s.clients.delete(c.id)
	// The slot is released once both connection threads have exited (`released` event).
	s.closing[c.id] = c.ip
}

// valid_name reports whether `name` can be the server or network name: it is
// sent as a message source and an ISUPPORT value.
fn valid_name(name string, max_len int) bool {
	return name != '' && name.len <= max_len
		&& name.bytes().all(it.is_alnum() || it in [`.`, `-`, `_`])
}

// log_error reports on standard error a failure no client is told about.
fn log_error(what string, err IError) {
	log.error('${what}: ${err.msg()}')
}

fn (s &Server) fold(name string) string {
	return casemapping.fold(name)
}

fn truncate(s string, max int) string {
	if s.len <= max {
		return s
	}
	// Do not cut a UTF-8 sequence in the middle.
	mut end := max
	for end > 0 && s[end] & 0xc0 == 0x80 {
		end--
	}
	return s[..end]
}

fn (mut s Server) next_msgid() string {
	s.msgid_seq++
	return '${s.msgid_base}${s.msgid_seq}'
}
