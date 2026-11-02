module store

// Marker is the read marker of one conversation.
pub struct Marker {
pub:
	target  string
	time_ms i64
}

// get_marker returns the read marker of `target` for account `id`, or 0.
pub fn (mut s Store) get_marker(id int, target string) !i64 {
	rows := s.query('SELECT time_ms FROM read_markers WHERE account_id = ? AND target = ?',
		id.str(), target)!
	return if rows.len == 0 { i64(0) } else { rows[0].val(0).i64() }
}

// set_marker moves the read marker of `target` forward to `time_ms` (it never
// goes back) and returns the stored value. An account keeps at most `limit`
// markers: a marker for a new target past the limit drops the oldest ones.
pub fn (mut s Store) set_marker(id int, target string, time_ms i64, limit int) !i64 {
	if limit < 1 {
		return error('the read marker limit must be positive')
	}
	// One transaction, so that the quota holds even if a statement fails.
	return s.transaction(fn [id, target, time_ms, limit] (mut s Store) !i64 {
		s.query('INSERT INTO read_markers (account_id, target, time_ms) VALUES (?, ?, ?) ON CONFLICT (account_id, target) DO UPDATE SET time_ms = MAX(time_ms, excluded.time_ms)',
			id.str(), target, time_ms.str())!
		// Keep the target just set and the `limit - 1` most recent other markers.
		s.query('DELETE FROM read_markers WHERE account_id = ? AND target <> ? AND target NOT IN (SELECT target FROM read_markers WHERE account_id = ? AND target <> ? ORDER BY time_ms DESC LIMIT ?)',
			id.str(), target, id.str(), target, (limit - 1).str())!
		return s.get_marker(id, target)!
	})
}

// markers returns the `limit` most recent read markers of account `id`.
pub fn (mut s Store) markers(id int, limit int) ![]Marker {
	rows := s.query('SELECT target, time_ms FROM read_markers WHERE account_id = ? ORDER BY time_ms DESC LIMIT ?',
		id.str(), limit.str())!
	return rows.map(Marker{it.val(0), it.val(1).i64()})
}
