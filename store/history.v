module store

// HistoryEntry is a stored PRIVMSG, NOTICE or TAGMSG.
pub struct HistoryEntry {
pub:
	// id orders messages stored in the same millisecond; it is set when reading.
	id         i64
	msgid      string
	target_key string
	// target is the channel or nickname the message was sent to, as written.
	target  string
	time_ms i64
	source  string
	account string
	command string
	// tags are the client-only tags of the message, encoded without `@`.
	tags string
	text string
}

// add_history stores a message.
pub fn (mut s Store) add_history(e HistoryEntry) ! {
	s.query('INSERT INTO history (msgid, target_key, target, time_ms, source, account, command, tags, text) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
		e.msgid, e.target_key, e.target, e.time_ms.str(), e.source, e.account, e.command, e.tags,
		e.text)!
}

const history_columns = 'id, msgid, target_key, target, time_ms, source, account, command, tags, text'

fn row_entry(vals []string) HistoryEntry {
	return HistoryEntry{
		id:         vals[0].i64()
		msgid:      vals[1]
		target_key: vals[2]
		target:     vals[3]
		time_ms:    vals[4].i64()
		source:     vals[5]
		account:    vals[6]
		command:    vals[7]
		tags:       vals[8]
		text:       vals[9]
	}
}

// Position is a point in the history of a target: a stored message, or a time.
pub struct Position {
pub:
	time_ms i64
	// id breaks ties between messages stored in the same millisecond.
	id i64
	// is_time is set for a timestamp, which excludes every message at that
	// millisecond on both sides (CHATHISTORY timestamps are exclusive bounds).
	is_time bool
}

fn (p Position) after_id() i64 {
	return if p.is_time { max_i64 } else { p.id }
}

fn (p Position) before_id() i64 {
	return if p.is_time { 0 } else { p.id }
}

// less reports whether `a` is before `b`.
pub fn (a Position) less(b Position) bool {
	return a.time_ms < b.time_ms || (a.time_ms == b.time_ms && a.id < b.id)
}

// is_after reports whether the entry is strictly after `p`.
pub fn (e HistoryEntry) is_after(p Position) bool {
	return e.time_ms > p.time_ms || (e.time_ms == p.time_ms && e.id > p.after_id())
}

// is_before reports whether the entry is strictly before `p`.
pub fn (e HistoryEntry) is_before(p Position) bool {
	return e.time_ms < p.time_ms || (e.time_ms == p.time_ms && e.id < p.before_id())
}

// history_end is the position after every message.
pub const history_end = Position{max_i64, max_i64, false}

// position_at returns the position of a timestamp.
pub fn position_at(time_ms i64) Position {
	return Position{
		time_ms: time_ms
		is_time: true
	}
}

// Range selects the history of one conversation. Messages stored up to the
// history id `floor_id` are hidden, for example those of an earlier channel of
// the same name. Ids only grow (AUTOINCREMENT), whatever the clock does.
pub struct Range {
pub:
	key      string
	floor_id i64
}

// position_of returns the position of the message `msgid`.
pub fn (mut s Store) position_of(r Range, msgid string) !Position {
	rows := s.query('SELECT time_ms, id FROM history WHERE target_key = ? AND msgid = ? AND id > ?',
		r.key, msgid, r.floor_id.str())!
	if rows.len == 0 {
		return NotFoundError{
			what: 'message'
		}
	}
	return Position{
		time_ms: rows[0].val(0).i64()
		id:      rows[0].val(1).i64()
	}
}

// before returns up to `limit` messages strictly before `pos`, oldest first.
pub fn (mut s Store) before(r Range, pos Position, limit int) ![]HistoryEntry {
	rows := s.query('SELECT ${history_columns} FROM (SELECT * FROM history WHERE target_key = ? AND id > ? AND (time_ms < ? OR (time_ms = ? AND id < ?)) ORDER BY time_ms DESC, id DESC LIMIT ?) ORDER BY time_ms, id',
		r.key, r.floor_id.str(), pos.time_ms.str(), pos.time_ms.str(), pos.before_id().str(),
		limit.str())!
	return rows.map(row_entry(it.vals))
}

// after returns up to `limit` messages strictly after `pos`, oldest first.
pub fn (mut s Store) after(r Range, pos Position, limit int) ![]HistoryEntry {
	rows := s.query('SELECT ${history_columns} FROM history WHERE target_key = ? AND id > ? AND (time_ms > ? OR (time_ms = ? AND id > ?)) ORDER BY time_ms, id LIMIT ?',
		r.key, r.floor_id.str(), pos.time_ms.str(), pos.time_ms.str(), pos.after_id().str(),
		limit.str())!
	return rows.map(row_entry(it.vals))
}

// latest returns the `limit` most recent messages, oldest first.
pub fn (mut s Store) latest(r Range, limit int) ![]HistoryEntry {
	return s.before(r, history_end, limit)
}

// between returns up to `limit` messages strictly between two positions, oldest
// first. When `start` is after `end`, the messages closest to `start` are kept
// (the CHATHISTORY BETWEEN rule).
pub fn (mut s Store) between(r Range, start Position, end Position, limit int) ![]HistoryEntry {
	if start.less(end) {
		return s.after(r, start, limit)!.filter(it.is_before(end))
	}
	return s.before(r, start, limit)!.filter(it.is_after(end))
}

// TargetActivity is the time of the last message of a conversation.
pub struct TargetActivity {
pub:
	target_key string
	target     string
	time_ms    i64
}

// targets returns the conversations among `ranges` whose latest message is
// strictly between `from_ms` and `to_ms`. When `from_ms` is before `to_ms` the
// oldest come first, otherwise the newest: the `limit` closest to `from_ms` are kept.
pub fn (mut s Store) targets(ranges []Range, from_ms i64, to_ms i64, limit int) ![]TargetActivity {
	lo, hi := if from_ms < to_ms { from_ms, to_ms } else { to_ms, from_ms }
	mut out := []TargetActivity{}
	for r in ranges {
		rows := s.query('SELECT target, time_ms FROM history WHERE target_key = ? AND id > ? ORDER BY time_ms DESC, id DESC LIMIT 1',
			r.key, r.floor_id.str())!
		if rows.len == 0 {
			continue
		}
		t := rows[0].val(1).i64()
		if t > lo && t < hi {
			out << TargetActivity{r.key, rows[0].val(0), t}
		}
	}
	if from_ms < to_ms {
		out.sort(a.time_ms < b.time_ms)
	} else {
		out.sort(a.time_ms > b.time_ms)
	}
	return if out.len > limit { out[..limit] } else { out }
}

// dm_targets returns the private conversation keys of account `id`: keys
// `dm:<id>:<id>` (permanent account ids) and `dmn:<id>:<nickname>`.
pub fn (mut s Store) dm_targets(id int) ![]string {
	rows := s.query('SELECT DISTINCT target_key FROM history WHERE target_key LIKE ? OR target_key LIKE ? OR target_key LIKE ?',
		'dm:${id}:%', 'dm:%:${id}', 'dmn:${id}:%')!
	return rows.map(it.val(0))
}

// last_id returns the id of the newest stored message, or 0.
pub fn (mut s Store) last_id() !i64 {
	rows := s.query('SELECT COALESCE(MAX(id), 0) FROM history')!
	return rows[0].val(0).i64()
}

// prune keeps at most `keep` messages per target.
pub fn (mut s Store) prune(target_key string, keep int) ! {
	s.query('DELETE FROM history WHERE target_key = ? AND id NOT IN (SELECT id FROM history WHERE target_key = ? ORDER BY time_ms DESC, id DESC LIMIT ?)',
		target_key, target_key, keep.str())!
}
