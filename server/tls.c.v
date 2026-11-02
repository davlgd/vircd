module server

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
	// failed is set, under `mu`, after a fatal Mbed TLS error: the context must
	// not be used again (ssl.h), so neither thread calls into it any more.
	failed bool
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

// call runs one Mbed TLS call under the lock, unless the context has failed,
// and marks it failed (waking the other thread) when the call fails for good.
fn (mut t TlsStream) call(f fn (mut t TlsStream) int) !int {
	t.mu.lock()
	if t.failed {
		t.mu.unlock()
		return error('TLS connection failed')
	}
	r := f(mut t)
	if r < 0 && !is_retryable(r) {
		$if trace_tls ? {
			eprintln('TLS fd ${t.fd}: fatal Mbed TLS error ${r}')
		}
		t.failed = true
		t.mu.unlock()
		net.shutdown(t.fd)
		return error('TLS error ${r}')
	}
	t.mu.unlock()
	return r
}

fn (mut t TlsStream) read(mut buf []u8) !int {
	for {
		r := t.call(fn [mut buf] (mut t TlsStream) int {
			return C.mbedtls_ssl_read(&t.conn.ssl, buf.data, buf.len)
		}) or {
			// The peer's close_notify ends the stream like EOF.
			return 0
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

// tls_write_timeout bounds how long a client may refuse to read.
const tls_write_timeout = 60 * time.second

fn (mut t TlsStream) write_string(s string) !int {
	mut sent := 0
	deadline := time.now().add(tls_write_timeout)
	for sent < s.len {
		done := sent
		r := t.call(fn [s, done] (mut t TlsStream) int {
			return C.mbedtls_ssl_write(&t.conn.ssl, unsafe { s.str + done }, s.len - done)
		})!
		if r > 0 {
			sent += r
			continue
		}
		remaining := int((deadline - time.now()).milliseconds())
		if remaining <= 0 {
			return error('TLS write timed out')
		}
		if r == C.MBEDTLS_ERR_SSL_WANT_WRITE {
			wait_fd(t.fd, i16(C.POLLOUT), remaining)
		} else if r == C.MBEDTLS_ERR_SSL_WANT_READ {
			wait_fd(t.fd, i16(C.POLLIN), if remaining < 100 { remaining } else { 100 })
		}
	}
	return sent
}

fn (mut t TlsStream) close() ! {
	t.mu.lock()
	defer {
		t.mu.unlock()
	}
	t.conn.shutdown()!
}
