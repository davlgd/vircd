module store

import crypto.rand
import crypto.scram
import crypto.subtle
import ircmsg

// max_account_name is the longest account name accepted.
pub const max_account_name = 32
// min_password is the shortest password the command line accepts by default.
pub const min_password = 8
// max_password is the longest password accepted.
pub const max_password = 1024

// Account is an identity users log in to with SASL.
pub struct Account {
pub:
	// id is permanent: it is never given to another account.
	id          int
	name        string
	credentials scram.Credentials
}

// valid_account_name reports whether `name` can be an account name: it must also
// be a valid nickname, since an account owns the nickname of its name.
pub fn valid_account_name(name string) bool {
	return ircmsg.valid_nickname(name, max_account_name)
}

// validate_password checks the length of a new password.
pub fn validate_password(password string) ! {
	if password == '' || password.len > max_password {
		return error('passwords must be 1 to ${max_password} bytes long')
	}
	for c in password {
		if c < 0x20 || c == 0x7f {
			return error('passwords cannot contain control characters')
		}
	}
}

// add_account creates an account. `name_key` is the name folded with the server
// casemapping.
pub fn (mut s Store) add_account(name string, name_key string, password string) !Account {
	if !valid_account_name(name) {
		return error('invalid account name "${name}"')
	}
	validate_password(password)!
	if _ := s.find_account(name_key) {
		return error('account ${name} already exists')
	}
	creds := s.new_credentials(password)!
	s.query('INSERT INTO accounts (name, name_key, credentials) VALUES (?, ?, ?)', name,
		name_key, creds.encode())!
	return s.find_account(name_key)!
}

fn (s &Store) new_credentials(password string) !scram.Credentials {
	return scram.derive_credentials(.sha256, password, rand.bytes(16)!, s.iterations)!
}

// set_password replaces the password of an account.
pub fn (mut s Store) set_password(name_key string, password string) ! {
	validate_password(password)!
	creds := s.new_credentials(password)!
	s.query('UPDATE accounts SET credentials = ? WHERE name_key = ?', creds.encode(), name_key)!
	s.check_changed()!
}

// remove_account deletes an account. Its history stays.
pub fn (mut s Store) remove_account(name_key string) ! {
	s.query('DELETE FROM accounts WHERE name_key = ?', name_key)!
	s.check_changed()!
}

// check_changed reports a missing account when the last statement changed no row.
fn (mut s Store) check_changed() ! {
	if s.db.get_affected_rows_count() != 1 {
		return NotFoundError{
			what: 'account'
		}
	}
}

// account_by_id returns the account with the permanent id `id`.
pub fn (mut s Store) account_by_id(id int) !Account {
	return s.account_where('id', id.str())
}

// find_account returns the account whose folded name is `name_key`.
pub fn (mut s Store) find_account(name_key string) !Account {
	return s.account_where('name_key', name_key)
}

fn (mut s Store) account_where(column string, value string) !Account {
	rows := s.query('SELECT id, name, credentials FROM accounts WHERE ${column} = ?', value)!
	if rows.len == 0 {
		return NotFoundError{
			what: 'account'
		}
	}
	return Account{
		id:          rows[0].val(0).int()
		name:        rows[0].val(1)
		credentials: scram.parse_credentials(rows[0].val(2))!
	}
}

// list_accounts returns the names of all accounts.
pub fn (mut s Store) list_accounts() ![]string {
	return s.query('SELECT name FROM accounts ORDER BY name_key')!.map(it.val(0))
}

// dummy_credentials returns credentials nobody can log in with, of the same cost
// as real ones, so that unknown accounts take as long to reject as known ones.
pub fn (s &Store) dummy_credentials() !scram.Credentials {
	return s.new_credentials(rand.bytes(16)!.hex())
}

// check_password verifies a PLAIN password against SCRAM credentials: it derives
// the stored key with the same salt and iteration count and compares it in
// constant time. It is slow on purpose; do not call it on the server event loop.
pub fn check_password(creds scram.Credentials, password string) bool {
	if creds.salt.len == 0 || password.len > max_password {
		return false
	}
	derived := scram.derive_credentials(creds.mechanism, password, creds.salt, creds.iterations) or {
		return false
	}
	return subtle.constant_time_compare(derived.stored_key, creds.stored_key) == 1
}
