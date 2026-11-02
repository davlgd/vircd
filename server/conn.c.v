module server

import ircmsg
import net
import net.mbedtls
import strings
import sync.stdatomic
import time

// Stream is a client connection, in clear text or TLS.
interface Stream {
mut:
	read(mut buf []u8) !int
	write_string(s string) !int
	close() !
}

// Link is what the reader and writer threads of one connection share. The
// connection is closed by whichever of the two threads finishes last, so that
// no thread ever uses a closed (and possibly reused) file descriptor.
@[heap]
struct Link {
mut:
	stream Stream
	fd     int
	refs   i64 = 2
	// id and events let the last thread report that the descriptor is closed.
	id     int
	events chan Event
}

// wake makes a blocked read return, without releasing the file descriptor.
fn (l &Link) wake() {
	net.shutdown(l.fd)
}

fn (mut l Link) release() {
	if stdatomic.sub_i64(&l.refs, 1) == 0 {
		l.stream.close() or {}
		l.events <- Event{
			kind: .released
			id:   l.id
		}
	}
}

fn tcp_link(mut conn net.TcpConn) &Link {
	return &Link{
		stream: conn
		fd:     conn.sock.handle
	}
}

fn tls_link(mut conn mbedtls.SSLConn) !&Link {
	mut stream := new_tls_stream(mut conn)!
	return &Link{
		stream: stream
		fd:     conn.handle
	}
}

// max_client_line is the longest line a client may send: tags, then the
// RFC 1459 512 bytes, CR LF included.
const max_client_line = ircmsg.max_client_tags_bytes + ircmsg.max_line_bytes

// reader reads lines from the client and posts them as events. It applies
// flood control by delaying lines past the burst, which also slows the client
// down through TCP back-pressure.
fn reader(mut link Link, id int, events chan Event, cfg Config) {
	defer {
		events <- Event{
			kind: .closed
			id:   id
		}
		link.release()
	}
	mut buf := []u8{len: 4096}
	mut pending := []u8{cap: 1024}
	mut discarding := false
	mut tokens := f64(cfg.flood_burst)
	mut last := time.now()
	for {
		n := link.stream.read(mut buf) or { return }
		if n <= 0 {
			return
		}
		mut start := 0
		for i in 0 .. n {
			if buf[i] != `\n` {
				continue
			}
			if discarding {
				discarding = false
				start = i + 1
				continue
			}
			pending << buf[start..i]
			start = i + 1
			mut line := pending.bytestr()
			pending.clear()
			if line.ends_with('\r') {
				line = line[..line.len - 1]
			}
			if line.len == 0 {
				continue
			}
			if cfg.flood_rate > 0 {
				now := time.now()
				tokens += f64(now - last) / f64(time.second) * f64(cfg.flood_rate)
				if tokens > f64(cfg.flood_burst) {
					tokens = f64(cfg.flood_burst)
				}
				last = now
				if tokens < 1 {
					time.sleep(time.Duration(i64((1 - tokens) / f64(cfg.flood_rate) * f64(time.second))))
					tokens = 1
					last = time.now()
				}
				tokens -= 1
			}
			events <- Event{
				kind: .line
				id:   id
				line: line
			}
		}
		if discarding {
			continue
		}
		pending << buf[start..n]
		if pending.len > max_client_line {
			pending.clear()
			discarding = true
			events <- Event{
				kind: .too_long
				id:   id
			}
		}
	}
}

// close_marker, queued after the last line, tells the writer to finish. Closing
// the channel instead could drop the lines still queued.
const close_marker = '\x00close'

// writer sends the lines queued for the client until the close marker (or a
// closed queue), then wakes the reader so that the connection is torn down.
fn writer(mut link Link, out chan string) {
	defer {
		link.wake()
		link.release()
	}
	mut batch := strings.new_builder(4096)
	for {
		line := <-out or { return }
		mut last := line == close_marker
		if !last {
			batch.write_string(line)
		}
		// Send what is already queued in the same write.
		mut next := ''
		for !last && batch.len < 32768 && out.try_pop(mut next) == .success {
			if next == close_marker {
				last = true
			} else {
				batch.write_string(next)
			}
		}
		if batch.len > 0 {
			link.stream.write_string(batch.str()) or { return }
		}
		if last {
			return
		}
	}
}
