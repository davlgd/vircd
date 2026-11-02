module store

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

fn test_accounts() {
	mut s := temp_store('accounts')!
	defer {
		s.close()
	}
	acct := s.add_account('Alice', 'alice', 'correct horse')!
	assert acct.name == 'Alice'
	assert check_password(acct.credentials, 'correct horse')
	assert !check_password(acct.credentials, 'wrong horse')
	assert !check_password(s.dummy_credentials()!, 'correct horse')
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
