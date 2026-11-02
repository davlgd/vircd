module main

import cli { Command, Flag }
import os
import server
import store

fn main() {
	mut app := Command{
		name:        'vircd'
		description: 'An IRCv3 server with SASL authentication, backed by SQLite.'
		version:     server.version
		posix_mode:  true
		flags:       [
			Flag{
				flag:          .string
				name:          'db'
				abbrev:        'd'
				description:   'Path to the SQLite database.'
				default_value: ['vircd.db']
				global:        true
			},
		]
		commands:    [serve_command(), account_command()]
	}
	app.setup()
	app.parse(os.args)
}

fn serve_command() Command {
	d := server.Config{}
	return Command{
		name:        'serve'
		description: 'Run the IRC server.'
		execute:     run_serve
		flags:       [
			Flag{
				flag:          .string
				name:          'listen'
				abbrev:        'l'
				description:   'Address to listen on.'
				default_value: [d.listen]
			},
			Flag{
				flag:          .string
				name:          'name'
				description:   'Server name.'
				default_value: [d.name]
			},
			Flag{
				flag:          .string
				name:          'network'
				description:   'Network name (NETWORK in ISUPPORT).'
				default_value: [d.network]
			},
			Flag{
				flag:          .string
				name:          'description'
				description:   'Server description, shown by WHOIS and LINKS.'
				default_value: [d.description]
			},
			Flag{
				flag:        .string
				name:        'password'
				description: 'Connection password clients must send with PASS.'
			},
			Flag{
				flag:        .string
				name:        'oper-user'
				description: 'Operator name for OPER.'
			},
			Flag{
				flag:        .string
				name:        'oper-password'
				description: 'Operator password for OPER.'
			},
			Flag{
				flag:        .string
				name:        'tls-cert'
				description: 'TLS certificate (PEM file); enables TLS.'
			},
			Flag{
				flag:        .string
				name:        'tls-key'
				description: 'TLS private key (PEM file).'
			},
			Flag{
				flag:        .bool
				name:        'allow-plaintext-auth'
				description: 'Allow SASL PLAIN without TLS off loopback.'
			},
			Flag{
				flag:        .bool
				name:        'relaxed-nicks'
				description: 'Allow nicknames other than account names.'
			},
			Flag{
				flag:        .string
				name:        'motd'
				description: 'File holding the message of the day.'
			},
			Flag{
				flag:          .int
				name:          'flood-rate'
				description:   'Lines per second after the burst; 0: no limit.'
				default_value: [d.flood_rate.str()]
			},
			Flag{
				flag:          .int
				name:          'flood-burst'
				description:   'Lines accepted at once before flood control.'
				default_value: [d.flood_burst.str()]
			},
			Flag{
				flag:          .int
				name:          'history'
				description:   'Messages kept per conversation; 0: none.'
				default_value: [d.history_limit.str()]
			},
			Flag{
				flag:          .int
				name:          'max-per-ip'
				description:   'Connections allowed from one address.'
				default_value: [d.max_per_ip.str()]
			},
		]
	}
}

fn run_serve(cmd Command) ! {
	mut cfg := server.Config{
		db:                   cmd.flags.get_string('db')!
		listen:               cmd.flags.get_string('listen')!
		name:                 cmd.flags.get_string('name')!
		network:              cmd.flags.get_string('network')!
		description:          cmd.flags.get_string('description')!
		password:             cmd.flags.get_string('password')!
		oper_user:            cmd.flags.get_string('oper-user')!
		oper_password:        cmd.flags.get_string('oper-password')!
		tls_cert:             cmd.flags.get_string('tls-cert')!
		tls_key:              cmd.flags.get_string('tls-key')!
		allow_plaintext_auth: cmd.flags.get_bool('allow-plaintext-auth')!
		force_nick_account:   !cmd.flags.get_bool('relaxed-nicks')!
		flood_rate:           cmd.flags.get_int('flood-rate')!
		flood_burst:          cmd.flags.get_int('flood-burst')!
		history_limit:        cmd.flags.get_int('history')!
		max_per_ip:           cmd.flags.get_int('max-per-ip')!
	}
	motd := cmd.flags.get_string('motd')!
	if motd != '' {
		cfg.motd = os.read_lines(motd)!
	}
	mut srv := server.new_server(cfg)!
	srv.run()
}

fn account_command() Command {
	return Command{
		name:        'account'
		description: 'Manage accounts.'
		commands:    [
			Command{
				name:          'add'
				description:   'Create an account.'
				usage:         '<name>'
				required_args: 1
				execute:       account_add
				flags:         password_flags()
			},
			Command{
				name:          'passwd'
				description:   'Change the password of an account.'
				usage:         '<name>'
				required_args: 1
				execute:       account_passwd
				flags:         password_flags()
			},
			Command{
				name:          'remove'
				description:   'Delete an account.'
				usage:         '<name>'
				required_args: 1
				execute:       account_remove
			},
			Command{
				name:        'list'
				description: 'List accounts.'
				execute:     account_list
			},
		]
	}
}

fn password_flags() []Flag {
	return [
		Flag{
			flag:        .bool
			name:        'password-stdin'
			description: 'Read the password from standard input.'
		},
		Flag{
			flag:        .bool
			name:        'weak-password'
			description: 'Accept passwords under ${store.min_password} bytes (tests).'
		},
	]
}

fn read_password(cmd Command) !string {
	mut password := ''
	if cmd.flags.get_bool('password-stdin')! {
		password = os.get_raw_line().trim_right('\r\n')
	} else {
		first := os.input_password('Password: ') or { return error('cannot read password') }
		second := os.input_password('Again: ') or { return error('cannot read password') }
		if first != second {
			return error('passwords differ')
		}
		password = first
	}
	if password.len < store.min_password && !cmd.flags.get_bool('weak-password')! {
		return error('passwords must be at least ${store.min_password} bytes long')
	}
	return password
}

fn open_store(cmd Command) !&store.Store {
	return store.open(cmd.flags.get_string('db')!)!
}

fn account_add(cmd Command) ! {
	name := cmd.args[0]
	password := read_password(cmd)!
	mut st := open_store(cmd)!
	defer {
		st.close()
	}
	st.add_account(name, server.casemapping.fold(name), password)!
	println('account ${name} created')
}

fn account_passwd(cmd Command) ! {
	name := cmd.args[0]
	password := read_password(cmd)!
	mut st := open_store(cmd)!
	defer {
		st.close()
	}
	st.set_password(server.casemapping.fold(name), password)!
	println('password of ${name} changed')
}

fn account_remove(cmd Command) ! {
	mut st := open_store(cmd)!
	defer {
		st.close()
	}
	st.remove_account(server.casemapping.fold(cmd.args[0]))!
	println('account ${cmd.args[0]} removed')
}

fn account_list(cmd Command) ! {
	mut st := open_store(cmd)!
	defer {
		st.close()
	}
	for name in st.list_accounts()! {
		println(name)
	}
}
