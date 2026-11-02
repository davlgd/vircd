module server

import ircmsg
import store
import time

// CHATHISTORY (https://ircv3.net/specs/extensions/chathistory).
fn (mut s Server) cmd_chathistory(mut c Client, msg ircmsg.Message) {
	if !c.has('draft/chathistory') {
		s.fail(mut c, 'CHATHISTORY', 'UNKNOWN_COMMAND', 'CHATHISTORY', 'You need the draft/chathistory capability')
		return
	}
	sub := msg.param(0).to_upper()
	if sub == 'TARGETS' {
		s.chathistory_targets(mut c, msg)
		return
	}
	if sub !in ['LATEST', 'BEFORE', 'AFTER', 'AROUND', 'BETWEEN'] {
		s.fail(mut c, 'CHATHISTORY', 'INVALID_PARAMS', sub, 'Unknown subcommand')
		return
	}
	needed := if sub == 'BETWEEN' { 5 } else { 4 }
	if msg.params.len < needed {
		s.fail(mut c, 'CHATHISTORY', 'INVALID_PARAMS', sub, 'Not enough parameters')
		return
	}
	target := msg.params[1]
	r := s.history_range(c, target) or {
		if err is InvalidHistoryRequest {
			s.fail(mut c, 'CHATHISTORY', 'INVALID_TARGET', sub, target, 'Messages could not be retrieved')
		} else {
			s.fail(mut c, 'CHATHISTORY', 'MESSAGE_ERROR', sub, target, 'Messages could not be retrieved')
		}
		return
	}
	limit_str := msg.params[needed - 1]
	limit := limit_str.int()
	if limit <= 0 || limit.str() != limit_str {
		s.fail(mut c, 'CHATHISTORY', 'INVALID_PARAMS', sub, limit_str, 'Invalid limit')
		return
	}
	n := if limit > chathistory_max { chathistory_max } else { limit }
	mut ref := store.history_end
	if !(sub == 'LATEST' && msg.params[2] == '*') {
		ref = s.history_ref(r, msg.params[2]) or {
			s.ref_failed(mut c, sub, target, msg.params[2], err)
			return
		}
	}
	mut ref2 := store.Position{}
	if sub == 'BETWEEN' {
		ref2 = s.history_ref(r, msg.params[3]) or {
			s.ref_failed(mut c, sub, target, msg.params[3], err)
			return
		}
	}
	entries := s.query_history(sub, r, ref, ref2, n) or {
		s.fail(mut c, 'CHATHISTORY', 'MESSAGE_ERROR', sub, target, 'Messages could not be retrieved')
		return
	}
	s.send_history(mut c, target, entries)
}

// InvalidHistoryRequest is a CHATHISTORY target or reference the client may
// not use or that does not exist; other errors come from the database.
struct InvalidHistoryRequest {
	Error
}

fn (mut s Server) ref_failed(mut c Client, sub string, target string, raw string, err IError) {
	if err is InvalidHistoryRequest {
		s.fail(mut c, 'CHATHISTORY', 'INVALID_PARAMS', sub, raw, 'Invalid message reference')
	} else {
		s.fail(mut c, 'CHATHISTORY', 'MESSAGE_ERROR', sub, target, 'Messages could not be retrieved')
	}
}

fn (mut s Server) query_history(sub string, r store.Range, ref store.Position, ref2 store.Position, n int) ![]store.HistoryEntry {
	return match sub {
		'LATEST' {
			if ref == store.history_end {
				s.db.latest(r, n)!
			} else {
				// The newest messages after the reference.
				s.db.between(r, store.history_end, ref, n)!
			}
		}
		'BEFORE' {
			s.db.before(r, ref, n)!
		}
		'AFTER' {
			s.db.after(r, ref, n)!
		}
		'AROUND' {
			s.around(r, ref, n)!
		}
		else {
			s.db.between(r, ref, ref2, n)!
		}
	}
}

// around returns about `n` messages centred on the reference, which is
// included: the message of a msgid, or the messages at a timestamp.
fn (mut s Server) around(r store.Range, ref store.Position, n int) ![]store.HistoryEntry {
	mut out := s.db.before(r, ref, n / 2)!
	pos := if ref.is_time {
		store.Position{ref.time_ms, 0, false}
	} else {
		store.Position{ref.time_ms, ref.id - 1, false}
	}
	out << s.db.after(r, pos, n - out.len)!
	return out
}

// history_range returns the conversation a client may read: a channel it is
// in (only since the channel was created), or a private conversation of its
// account with another account or with a client that has none.
fn (mut s Server) history_range(c &Client, target string) !store.Range {
	if target.starts_with('#') {
		folded := s.fold(target)
		if folded !in c.channels {
			return InvalidHistoryRequest{}
		}
		ch := s.channels[folded] or { return InvalidHistoryRequest{} }
		return store.Range{
			key:      folded
			floor_id: ch.history_floor
		}
	}
	if c.account_id == 0 || !valid_nick(target) {
		return InvalidHistoryRequest{}
	}
	// An online client is its account, or its nickname when it is not logged in;
	// an offline target is the account of that name, if there is one.
	if peer := s.find_nick(target) {
		return store.Range{
			key: s.dm_key_of(c, peer)
		}
	}
	acct := s.db.find_account(s.fold(target)) or {
		if err is store.NotFoundError {
			return store.Range{
				key: dm_nick_key(c.account_id, s.fold(target))
			}
		}
		return err
	}
	return store.Range{
		key: dm_key(c.account_id, acct.id)
	}
}

// history_ref parses `msgid=...` or `timestamp=...`.
fn (mut s Server) history_ref(r store.Range, raw string) !store.Position {
	if raw.starts_with('msgid=') {
		return s.db.position_of(r, raw[6..]) or {
			if err is store.NotFoundError {
				return InvalidHistoryRequest{}
			}
			return err
		}
	}
	if raw.starts_with('timestamp=') {
		ms := parse_server_time(raw[10..]) or { return InvalidHistoryRequest{} }
		return store.position_at(ms)
	}
	return InvalidHistoryRequest{}
}

// parse_server_time parses `YYYY-MM-DDThh:mm:ss[.sss]Z` to Unix milliseconds.
fn parse_server_time(s string) ?i64 {
	if !s.ends_with('Z') || s.len < 20 {
		return none
	}
	t := time.parse_iso8601(s) or { return none }
	return t.unix_milli()
}

fn (mut s Server) send_history(mut c Client, target string, entries []store.HistoryEntry) {
	id := s.next_msgid()
	use_batch := c.has('batch')
	if use_batch {
		s.send(mut c, ircmsg.Message{
			source:  s.cfg.name
			command: 'BATCH'
			params:  ['+' + id, 'chathistory', target]
		})
	}
	for e in entries {
		mut tags := []ircmsg.Tag{}
		if use_batch {
			tags << ircmsg.Tag{'batch', id}
		}
		tags << ircmsg.Tag{'time', time.unix_milli(e.time_ms).format_rfc3339()}
		tags << ircmsg.Tag{'msgid', e.msgid}
		if e.account != '' {
			tags << ircmsg.Tag{'account', e.account}
		}
		if e.tags != '' {
			tags << ircmsg.parse_tags(e.tags) or { []ircmsg.Tag{} }
		}
		mut params := [e.target]
		if e.command != 'TAGMSG' {
			params << e.text
		}
		s.send(mut c, ircmsg.Message{
			tags:    tags
			source:  e.source
			command: e.command
			params:  params
		})
	}
	if use_batch {
		s.send(mut c, ircmsg.Message{
			source:  s.cfg.name
			command: 'BATCH'
			params:  ['-' + id]
		})
	}
}

fn (mut s Server) chathistory_targets(mut c Client, msg ircmsg.Message) {
	if msg.params.len < 4 {
		s.fail(mut c, 'CHATHISTORY', 'INVALID_PARAMS', 'TARGETS', 'Not enough parameters')
		return
	}
	mut bounds := []i64{}
	for raw in msg.params[1..3] {
		if !raw.starts_with('timestamp=') {
			s.fail(mut c, 'CHATHISTORY', 'INVALID_PARAMS', 'TARGETS', raw, 'Invalid timestamp')
			return
		}
		bounds << parse_server_time(raw[10..]) or {
			s.fail(mut c, 'CHATHISTORY', 'INVALID_PARAMS', 'TARGETS', raw, 'Invalid timestamp')
			return
		}
	}
	limit := msg.params[3].int()
	if limit <= 0 {
		s.fail(mut c, 'CHATHISTORY', 'INVALID_PARAMS', 'TARGETS', msg.params[3], 'Invalid limit')
		return
	}
	mut ranges := []store.Range{}
	for key, _ in c.channels {
		ch := s.channels[key] or { continue }
		ranges << store.Range{
			key:      key
			floor_id: ch.history_floor
		}
	}
	if c.account_id > 0 {
		dms := s.db.dm_targets(c.account_id) or {
			s.fail(mut c, 'CHATHISTORY', 'MESSAGE_ERROR', 'TARGETS', '*', 'Messages could not be retrieved')
			return
		}
		for key in dms {
			ranges << store.Range{
				key: key
			}
		}
	}
	n := if limit > chathistory_max { chathistory_max } else { limit }
	found := s.db.targets(ranges, bounds[0], bounds[1], n) or {
		s.fail(mut c, 'CHATHISTORY', 'MESSAGE_ERROR', 'TARGETS', '*', 'Messages could not be retrieved')
		return
	}
	// Names are resolved first, so that a database error is reported before the batch starts.
	mut names := []string{cap: found.len}
	for t in found {
		names << s.target_name(c, t) or {
			if err is store.NotFoundError {
				// The other account was deleted: the conversation has no name any more.
				''
			} else {
				s.fail(mut c, 'CHATHISTORY', 'MESSAGE_ERROR', 'TARGETS', '*', 'Messages could not be retrieved')
				return
			}
		}
	}
	id := s.next_msgid()
	use_batch := c.has('batch')
	if use_batch {
		s.send(mut c, ircmsg.Message{
			source:  s.cfg.name
			command: 'BATCH'
			params:  ['+' + id, 'draft/chathistory-targets']
		})
	}
	for i, t in found {
		if names[i] == '' {
			continue
		}
		tags := if use_batch { [ircmsg.Tag{'batch', id}] } else { []ircmsg.Tag{} }
		s.send(mut c, ircmsg.Message{
			tags:    tags
			source:  s.cfg.name
			command: 'CHATHISTORY'
			params:  ['TARGETS', names[i], time.unix_milli(t.time_ms).format_rfc3339()]
		})
	}
	if use_batch {
		s.send(mut c, ircmsg.Message{
			source:  s.cfg.name
			command: 'BATCH'
			params:  ['-' + id]
		})
	}
}

// target_name returns how a client names a conversation: the channel, the
// other account, or the nickname of the client without an account.
fn (mut s Server) target_name(c &Client, t store.TargetActivity) !string {
	if t.target_key.starts_with('dmn:') {
		nick := t.target_key.all_after_first('dmn:').all_after_first(':')
		return if peer := s.find_nick(nick) { peer.nick } else { nick }
	}
	if t.target_key.starts_with('dm:') {
		parts := t.target_key.split(':')
		other := if parts[1].int() == c.account_id { parts[2].int() } else { parts[1].int() }
		return s.db.account_by_id(other)!.name
	}
	return if ch := s.channels[t.target_key] { ch.name } else { t.target }
}
