module server

import io
import net.mbedtls

// unused_stream returns a stream whose context was never set up: a test fails
// with an Mbed TLS error, not the expected one, if the stream calls into it.
fn unused_stream() &TlsStream {
	return &TlsStream{
		conn: &mbedtls.SSLConn{}
		fd:   -1
	}
}

fn returning(r int) fn (mut t TlsStream) int {
	return fn [r] (mut t TlsStream) int {
		return r
	}
}

fn ended(mut t TlsStream) bool {
	t.call(false, returning(5)) or { return err.msg() == 'TLS connection ended' }
	return false
}

fn test_a_read_at_eof_ends_the_stream() {
	mut t := unused_stream()
	if _ := t.call(true, returning(0)) {
		assert false, 'EOF must end the read'
	} else {
		assert err is io.Eof
	}
	assert t.failed
	assert ended(mut t)
}

fn test_a_write_of_zero_bytes_does_not_end_the_stream() {
	mut t := unused_stream()
	assert t.call(false, returning(0))! == 0
	assert !t.failed
}

fn test_close_notify_and_conn_eof_end_the_stream_as_eof() {
	for code in [C.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY, C.MBEDTLS_ERR_SSL_CONN_EOF] {
		mut t := unused_stream()
		if _ := t.call(true, returning(code)) {
			assert false, 'the end of the stream must end the read'
		} else {
			assert err is io.Eof
		}
		assert ended(mut t)
	}
}

fn test_a_fatal_error_ends_the_stream_as_an_error() {
	mut t := unused_stream()
	if _ := t.call(false, returning(C.MBEDTLS_ERR_SSL_INVALID_MAC)) {
		assert false, 'a fatal error must be reported'
	} else {
		assert err !is io.Eof
		assert err.msg().contains('TLS error')
	}
	assert ended(mut t)
}

fn test_retryable_results_keep_the_stream() {
	for code in [C.MBEDTLS_ERR_SSL_WANT_READ, C.MBEDTLS_ERR_SSL_WANT_WRITE] {
		mut t := unused_stream()
		assert t.call(true, returning(code))! == code
		assert !t.failed
	}
}

fn test_no_write_starts_once_the_budget_has_run_out() {
	mut t := unused_stream()
	t.write_timeout = 0
	if _ := t.write_string('hello') {
		assert false, 'the write must time out'
	} else {
		assert err.msg() == 'TLS write timed out'
	}
	// An abandoned write leaves the context unusable.
	assert ended(mut t)
}

fn test_close_is_idempotent_and_ends_the_stream() {
	mut t := unused_stream()
	// The context was never opened, so the first close reports it.
	t.close() or {}
	assert t.closed
	t.close()!
	assert ended(mut t)
}
