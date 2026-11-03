module server

import io
import net
import net.mbedtls
import sync
import time

#include <poll.h>

// check_tls_compiler refuses TLS in TCC builds: with TCC (V's default C compiler
// on some platforms), TLS 1.3 handshakes crash inside Mbed TLS (PSA key slots).
fn check_tls_compiler() ! {
	$if tinyc {
		return error('TLS needs a build made with clang or gcc: v -cc clang -o vircd .')
	}
}

struct C.pollfd {
mut:
	fd      int
	events  i16
	revents i16
}

fn C.poll(fds &C.pollfd, nfds u32, timeout int) int

// TlsStream lets one reader and one writer thread share a TLS connection. Mbed
// TLS does not allow concurrent calls on the same context, so every call into
// it holds `mu`; the socket is non-blocking and waits happen outside the lock,
// so a reader waiting for data never holds back the writer.
@[heap]
struct TlsStream {
mut:
	conn &mbedtls.SSLConn
	mu   &sync.Mutex = sync.new_mutex()
	fd   int
	// failed is set, under `mu`, once the connection has ended: after a fatal
	// Mbed TLS error or the end of the stream, the context must not be used
	// again (ssl.h), so neither thread calls into it any more.
	failed bool
	// closed is set, under `mu`, by close, which frees the context.
	closed bool
	// write_timeout is the time budget of one write (see tls_write_timeout).
	write_timeout time.Duration = tls_write_timeout
}

// new_tls_stream wraps a connection whose handshake is complete.
fn new_tls_stream(mut conn mbedtls.SSLConn) !&TlsStream {
	net.set_blocking(conn.handle, false)!
	// v_mbedtls_net_send is net.mbedtls's sender, which sets MSG_NOSIGNAL on Linux.
	C.mbedtls_ssl_set_bio(&conn.ssl, &conn.server_fd, C.v_mbedtls_net_send, C.mbedtls_net_recv,
		unsafe { nil })
	return &TlsStream{
		conn: conn
		fd:   conn.handle
	}
}

// wait_fd waits until the socket is ready for `events`, or `timeout_ms` passes
// (-1: no limit). Errors and hang-ups count as ready: the next TLS call reports them.
fn wait_fd(fd int, events i16, timeout_ms int) {
	mut pfd := C.pollfd{
		fd:     fd
		events: events
	}
	C.poll(&pfd, 1, timeout_ms)
}

fn is_retryable(r int) bool {
	return r == C.MBEDTLS_ERR_SSL_WANT_READ || r == C.MBEDTLS_ERR_SSL_WANT_WRITE
		|| r == C.MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET
}

// call runs one Mbed TLS call under the lock, unless the connection has ended.
// When the call ends it, the context is marked failed and the socket shut down,
// which wakes the other thread. The end of the stream is reported as `io.Eof`,
// any other failure as an error. `reading` tells that the call is a read into
// a non-empty buffer: `mbedtls_ssl_read` returns 0 when the socket reached EOF
// without a close_notify.
fn (mut t TlsStream) call(reading bool, f fn (mut t TlsStream) int) !int {
	t.mu.lock()
	if t.failed {
		t.mu.unlock()
		return error('TLS connection ended')
	}
	r := f(mut t)
	if reading && r == 0 {
		t.failed = true
		t.mu.unlock()
		net.shutdown(t.fd)
		return io.Eof{}
	}
	if r < 0 && !is_retryable(r) {
		t.failed = true
		t.mu.unlock()
		net.shutdown(t.fd)
		if r == C.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || r == C.MBEDTLS_ERR_SSL_CONN_EOF {
			return io.Eof{}
		}
		$if trace_tls ? {
			eprintln('TLS fd ${t.fd}: fatal Mbed TLS error ${r}')
		}
		return error_with_code('TLS error ${r}', r)
	}
	t.mu.unlock()
	return r
}

// read returns 0 at the end of the stream, whether the peer sent close_notify
// or just closed the socket: the reader drops an incomplete last line either
// way. Other failures are errors.
fn (mut t TlsStream) read(mut buf []u8) !int {
	if buf.len == 0 {
		return 0
	}
	for {
		r := t.call(true, fn [mut buf] (mut t TlsStream) int {
			return C.mbedtls_ssl_read(&t.conn.ssl, buf.data, buf.len)
		}) or {
			if err is io.Eof {
				return 0
			}
			return err
		}
		if r >= 0 {
			return r
		}
		if r == C.MBEDTLS_ERR_SSL_WANT_READ {
			wait_fd(t.fd, i16(C.POLLIN), -1)
		} else if r == C.MBEDTLS_ERR_SSL_WANT_WRITE {
			wait_fd(t.fd, i16(C.POLLOUT), 1000)
		}
	}
	return 0
}

// tls_write_timeout is the time budget of one write, so that a client that
// stops reading cannot hold its writer thread. It is measured on the monotonic
// clock from the start of the write, and checked under the lock before each
// Mbed TLS call, so waiting for the lock counts too. Once it has run out, no
// further TLS write starts and the stream ends: a write abandoned after
// WANT_WRITE leaves the context unusable. Each poll is given at most the
// remaining budget; scheduling may still delay its return.
const tls_write_timeout = 60 * time.second

fn (mut t TlsStream) write_string(s string) !int {
	mut sent := 0
	clock := time.new_stopwatch()
	budget := t.write_timeout
	for sent < s.len {
		done := sent
		r := t.call(false, fn [s, done, clock, budget] (mut t TlsStream) int {
			if clock.elapsed() >= budget {
				return C.MBEDTLS_ERR_SSL_TIMEOUT
			}
			return C.mbedtls_ssl_write(&t.conn.ssl, unsafe { s.str + done }, s.len - done)
		}) or {
			if err.code() == C.MBEDTLS_ERR_SSL_TIMEOUT {
				return error('TLS write timed out')
			}
			return err
		}
		if r > 0 {
			sent += r
			continue
		}
		left := int(time.Duration(budget - clock.elapsed()).milliseconds())
		remaining := if left > 0 { left } else { 0 }
		if r == C.MBEDTLS_ERR_SSL_WANT_WRITE {
			wait_fd(t.fd, i16(C.POLLOUT), remaining)
		} else if r == C.MBEDTLS_ERR_SSL_WANT_READ {
			wait_fd(t.fd, i16(C.POLLIN), if remaining < 100 { remaining } else { 100 })
		}
	}
	return sent
}

// close frees the connection. Link.release calls it once neither thread uses
// the stream any more; it is idempotent, and later calls into the stream fail.
fn (mut t TlsStream) close() ! {
	t.mu.lock()
	defer {
		t.mu.unlock()
	}
	if t.closed {
		return
	}
	t.closed = true
	t.failed = true
	t.conn.shutdown()!
}
