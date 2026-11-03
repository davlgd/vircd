module store

import db.sqlite
import os

const test_dir = os.join_path(os.vtmp_dir(), 'vircd_store_test_${os.getpid()}')

fn testsuite_begin() {
	os.mkdir_all(test_dir) or { panic(err) }
}

fn testsuite_end() {
	os.rmdir_all(test_dir) or {}
}

fn temp_store(name string) !&Store {
	mut s := open(os.join_path(test_dir, '${name}.db'))!
	s.iterations = 4096
	return s
}

fn test_dummy_credentials() {
	path := os.join_path(test_dir, 'dummy.db')
	mut s := open(path)!
	alice := s.dummy_credentials('alice')
	assert alice.salt.len == 16
	assert alice.iterations == s.iterations
	assert alice.salt == s.dummy_credentials('alice').salt
	assert alice.salt != s.dummy_credentials('bob').salt
	assert !check_password(alice, '')
	s.close()
	// The secret is kept: a restarted server gives the same salt.
	mut reopened := open(path)!
	defer {
		reopened.close()
	}
	assert reopened.dummy_credentials('alice').salt == alice.salt
	assert reopened.dummy_credentials('alice').stored_key == alice.stored_key
}

fn test_migration_from_v1() {
	path := os.join_path(test_dir, 'v1.db')
	mut db := sqlite.connect(path)!
	for stmt in schema_v1 {
		assert db.exec_none(stmt) == sqlite.sqlite_done
	}
	assert db.exec_none("INSERT INTO accounts (name, name_key, credentials) VALUES ('Alice', 'alice', 'x')") == sqlite.sqlite_done
	assert db.exec_none('PRAGMA user_version = 1') == sqlite.sqlite_done
	db.close()!
	mut s := open(path)!
	defer {
		s.close()
	}
	assert s.db.q_int('PRAGMA user_version')! == migrations.len
	assert s.dummy_secret.len == dummy_secret_len
	assert s.list_accounts()! == ['Alice']
}

fn test_malformed_dummy_secret() {
	for value in ['', '00', 'zz'.repeat(32), '00'.repeat(33)] {
		path := os.join_path(test_dir, 'bad_secret.db')
		mut s := open(path)!
		s.query('UPDATE settings SET value = ? WHERE name = ?', value, 'dummy_secret')!
		s.close()
		if mut reopened := open(path) {
			reopened.close()
			assert false, 'opened with dummy secret "${value}"'
		} else {
			assert err.msg().contains('dummy secret'), err.msg()
		}
		os.rm(path)!
		for suffix in ['-wal', '-shm'] {
			os.rm(path + suffix) or {}
		}
	}
}

fn test_accounts() {
	mut s := temp_store('accounts')!
	defer {
		s.close()
	}
	acct := s.add_account('Alice', 'alice', 'correct horse')!
	assert acct.name == 'Alice'
	assert check_password(acct.credentials, 'correct horse')
	assert !check_password(acct.credentials, 'wrong horse')
	assert !check_password(s.dummy_credentials('alice'), 'correct horse')
	if _ := s.add_account('ALICE', 'alice', 'another one') {
		assert false
	}
	if _ := s.add_account('bad name', 'bad name', 'password1') {
		assert false
	}
	if _ := s.add_account('bob', 'bob', '') {
		assert false
	}
	s.set_password('alice', 'new password')!
	assert check_password(s.find_account('alice')!.credentials, 'new password')
	assert s.list_accounts()! == ['Alice']
	s.remove_account('alice')!
	if _ := s.find_account('alice') {
		assert false
	}
}

fn test_history() {
	mut s := temp_store('history')!
	defer {
		s.close()
	}
	for i in 0 .. 10 {
		s.add_history(HistoryEntry{
			msgid:      'm${i}'
			target_key: '#c'
			target:     '#C'
			time_ms:    1000 + i / 2 * 10
			source:     'n!u@h'
			command:    'PRIVMSG'
			text:       'msg ${i}'
		})!
	}
	r := Range{
		key: '#c'
	}
	assert s.latest(r, 3)!.map(it.msgid) == ['m7', 'm8', 'm9']
	p4 := s.position_of(r, 'm4')!
	assert s.before(r, p4, 2)!.map(it.msgid) == ['m2', 'm3']
	assert s.after(r, p4, 2)!.map(it.msgid) == ['m5', 'm6']
	p8 := s.position_of(r, 'm8')!
	assert s.between(r, p4, p8, 10)!.map(it.msgid) == ['m5', 'm6', 'm7']
	assert s.between(r, p8, p4, 2)!.map(it.msgid) == ['m6', 'm7']
	// Timestamps are exclusive on both sides: m4 and m5 share 1020.
	assert s.after(r, position_at(1020), 1)!.map(it.msgid) == ['m6']
	assert s.before(r, position_at(1020), 1)!.map(it.msgid) == ['m3']
	assert s.between(r, position_at(1010), position_at(1030), 10)!.map(it.msgid) == [
		'm4',
		'm5',
	]
	assert s.between(r, position_at(1030), position_at(1010), 10)!.map(it.msgid) == [
		'm4',
		'm5',
	]
	// The floor hides older messages.
	floored := Range{
		key:      '#c'
		floor_id: s.position_of(r, 'm5')!.id
	}
	assert s.latest(floored, 100)!.map(it.msgid) == ['m6', 'm7', 'm8', 'm9']
	if _ := s.position_of(floored, 'm1') {
		assert false
	}
	s.prune('#c', 4)!
	assert s.latest(r, 100)!.len == 4
	s.add_history(HistoryEntry{
		msgid:      'd1'
		target_key: 'dm:1:12'
		target:     'bob'
		time_ms:    5000
		command:    'PRIVMSG'
	})!
	assert s.dm_targets(12)! == ['dm:1:12']
	assert s.dm_targets(2)! == []
	t := s.targets([r, Range{
		key: 'dm:1:12'
	}], 10000, 0, 10)!
	assert t.map(it.target_key) == ['dm:1:12', '#c']
	forward := s.targets([r, Range{
		key: 'dm:1:12'
	}], 0, 10000, 1)!
	assert forward.map(it.target_key) == ['#c']
	// Only the latest message of a conversation counts for TARGETS.
	assert s.targets([r], 0, 1035, 10)!.len == 0
}

fn test_markers() {
	mut s := temp_store('markers')!
	defer {
		s.close()
	}
	assert s.get_marker(1, '#c')! == 0
	assert s.set_marker(1, '#c', 2000, 10)! == 2000
	assert s.set_marker(1, '#c', 1000, 10)! == 2000
	assert s.set_marker(1, 'bob', 3000, 10)! == 3000
	assert s.get_marker(2, '#c')! == 0
	assert s.markers(1, 10)!.map(it.target) == ['bob', '#c']
	// Past the limit, the oldest markers go; the one just set always stays.
	assert s.set_marker(1, 'old', 500, 2)! == 500
	assert s.markers(1, 10)!.map(it.target) == ['bob', 'old']
	if _ := s.set_marker(1, 'x', 1, 0) {
		assert false
	}
}

fn test_reopen_keeps_the_database_private() {
	path := os.join_path(test_dir, 'reopen.db')
	mut s := open(path)!
	s.add_account('carol', 'carol', 'password1')!
	s.close()
	mut again := open(path)!
	defer {
		again.close()
	}
	assert again.list_accounts()! == ['carol']
	for file in [path, path + '-wal', path + '-shm'] {
		assert os.stat(file)!.get_mode().bitmask() & 0o077 == 0, file
	}
}

fn open_and_close(path string) ! {
	mut s := open(path)!
	s.close()
}

fn test_simultaneous_opens_of_a_new_database() {
	path := os.join_path(test_dir, 'race.db')
	mut threads := []thread !{}
	for _ in 0 .. 8 {
		threads << spawn open_and_close(path)
	}
	for t in threads {
		t.wait()!
	}
}
