// Module store keeps the persistent state of the server in SQLite: accounts
// and the message history served by CHATHISTORY.
module store

import crypto.rand
import crypto.scram
import db.sqlite
import encoding.hex
import os
import time

// migrations[i] brings the schema from version i to version i + 1; the version
// is kept in PRAGMA user_version. Never edit a released migration: append one.
const migrations = [schema_v1, schema_v2]

// schema_v1 creates accounts, the message history and read markers.
// accounts.name_key is the name folded with the server casemapping, so that two
// accounts never differ only by case. credentials is a SCRAM-SHA-256 record
// (crypto.scram encoding); it verifies both SCRAM and PLAIN logins.
// Account ids are never reused (AUTOINCREMENT), so that the private history of a
// deleted account never goes to a new account of the same name.
// history.target_key is a folded channel name, `dm:<id>:<id>` (account ids,
// smallest first) for private messages between accounts, or `dmn:<id>:<nick>`
// for private messages between an account and a client without one.
// read_markers.target is a folded channel name or nickname.
const schema_v1 = [
	'CREATE TABLE accounts (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		name        TEXT    NOT NULL,
		name_key    TEXT    NOT NULL UNIQUE,
		credentials TEXT    NOT NULL
	)',
	'CREATE TABLE history (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		msgid      TEXT    NOT NULL UNIQUE,
		target_key TEXT    NOT NULL,
		target     TEXT    NOT NULL,
		time_ms    INTEGER NOT NULL,
		source     TEXT    NOT NULL,
		account    TEXT    NOT NULL,
		command    TEXT    NOT NULL,
		tags       TEXT    NOT NULL,
		text       TEXT    NOT NULL
	)',
	'CREATE INDEX history_target_time ON history (target_key, time_ms, id)',
	'CREATE TABLE read_markers (
		account_id INTEGER NOT NULL,
		target     TEXT    NOT NULL,
		time_ms    INTEGER NOT NULL,
		PRIMARY KEY (account_id, target)
	)',
]

// schema_v2 adds settings, values the server generates once and keeps, such as
// the secret behind the credentials of unknown accounts (`dummy_credentials`).
const schema_v2 = [
	'CREATE TABLE settings (
		name  TEXT NOT NULL PRIMARY KEY,
		value TEXT NOT NULL
	)',
]

// busy_timeout_ms is how long a query waits for a lock held by another process
// (the command line). The server runs queries on its event loop, so it is short.
const busy_timeout_ms = 250

// Store is a connection to the database. It is not safe to share between threads.
pub struct Store {
mut:
	db sqlite.DB
	// dummy_secret derives the credentials of unknown accounts; it never changes
	// once created, so that they stay the same across restarts.
	dummy_secret []u8
pub mut:
	// iterations is the PBKDF2 cost of new credentials; tests lower it.
	iterations int = scram.default_iterations
}

// NotFoundError is returned when an account or message does not exist.
pub struct NotFoundError {
	Error
pub:
	what string
}

// msg returns a description of what was not found.
pub fn (e NotFoundError) msg() string {
	return '${e.what} not found'
}

// open opens the database file, configures the connection and applies migrations.
// The database holds credentials, so its files are made private to the owner.
pub fn open(path string) !&Store {
	// Create the file private before SQLite opens it (exclusively, so that a
	// database created meanwhile is never truncated); SQLite gives the WAL and
	// shared-memory files the permissions of the database file.
	create_private(path)!
	os.chmod(path, 0o600)!
	mut s := &Store{
		db: sqlite.connect(path)!
	}
	s.configure() or {
		s.close()
		return error('cannot open ${path}: ${err}')
	}
	for file in [path, path + '-wal', path + '-shm'] {
		if os.is_file(file) {
			os.chmod(file, 0o600) or {
				s.close()
				return error('cannot make ${file} private: ${err}')
			}
		}
	}
	return s
}

fn (mut s Store) configure() ! {
	s.db.busy_timeout(busy_timeout_ms)
	s.enable_wal()!
	s.db.synchronization_mode(.normal)!
	// The version is read in the transaction, so that two processes opening a new
	// database cannot both run the migrations.
	s.transaction(migrate)!
	s.dummy_secret = s.load_dummy_secret()!
}

// dummy_secret_len is the size of the secret behind unknown accounts' credentials.
const dummy_secret_len = 32

// load_dummy_secret returns the secret behind the credentials of unknown
// accounts, creating it the first time. INSERT OR IGNORE keeps the first secret
// if two processes create it at the same time. A malformed secret is an error,
// never replaced: replacing it would change the salts of unknown names.
fn (mut s Store) load_dummy_secret() ![]u8 {
	s.query('INSERT OR IGNORE INTO settings (name, value) VALUES (?, ?)', 'dummy_secret',
		rand.bytes(dummy_secret_len)!.hex())!
	rows := s.query('SELECT value FROM settings WHERE name = ?', 'dummy_secret')!
	if rows.len != 1 {
		return error('the dummy secret is missing')
	}
	secret := hex.decode(rows[0].val(0)) or { return error('the dummy secret is not hexadecimal') }
	if secret.len != dummy_secret_len {
		return error('the dummy secret has ${secret.len} bytes instead of ${dummy_secret_len}')
	}
	return secret
}

// migrate brings the schema to the latest version and returns it.
fn migrate(mut s Store) !int {
	version := s.db.q_int('PRAGMA user_version')!
	if version > migrations.len {
		return error('database schema ${version} is newer than this server (${migrations.len})')
	}
	for v in version .. migrations.len {
		for stmt in migrations[v] {
			s.exec(stmt)!
		}
	}
	if version < migrations.len {
		s.exec('PRAGMA user_version = ${migrations.len}')!
	}
	return migrations.len
}

// enable_wal switches the database to write-ahead logging. On a new database
// this needs an exclusive lock, which SQLite does not wait for: another process
// opening the database at the same time can hold it for a moment, so retry.
fn (mut s Store) enable_wal() ! {
	deadline := time.now().add(5 * time.second)
	for {
		mode := s.db.q_string('PRAGMA journal_mode = WAL') or {
			if time.now() < deadline {
				time.sleep(20 * time.millisecond)
				continue
			}
			return err
		}
		if mode != 'wal' {
			return error('cannot enable WAL journal mode (got ${mode})')
		}
		return
	}
}

// transaction runs `f` in an immediate (write-locked) transaction, which it
// commits if `f` succeeds and rolls back otherwise, and returns its result.
fn (mut s Store) transaction[T](f fn (mut s Store) !T) !T {
	s.exec('BEGIN IMMEDIATE')!
	result := f(mut s) or {
		s.exec('ROLLBACK') or {}
		return err
	}
	s.exec('COMMIT') or {
		s.exec('ROLLBACK') or {}
		return err
	}
	return result
}

// exec runs a statement that returns no rows. Unlike sqlite.DB.exec, it reports
// errors raised while the statement runs, such as SQLITE_BUSY.
fn (mut s Store) exec(stmt string) ! {
	code := s.db.exec_none(stmt)
	if code != sqlite.sqlite_ok && code != sqlite.sqlite_done && code != sqlite.sqlite_row {
		return s.db.error_message(code, stmt)
	}
}

// query runs a statement with `?` parameters and returns its rows.
fn (mut s Store) query(stmt string, params ...string) ![]sqlite.Row {
	return s.db.exec_param_many(stmt, params)
}

// close releases the connection.
pub fn (mut s Store) close() {
	s.db.close() or {}
}
