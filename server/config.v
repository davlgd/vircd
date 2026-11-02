module server

import ircmsg
import store
import time

// version is the server version, sent in RPL_MYINFO and VERSION.
pub const version = 'vIRCd-0.1.0'

// casemapping folds nicknames, channel names and account names before comparing them.
pub const casemapping = ircmsg.Casemapping.rfc1459

// Config holds everything `serve` can set.
@[params]
pub struct Config {
pub mut:
	// listen is the address to bind, `host:port`.
	listen string = '127.0.0.1:6667'
	// name is the server name, the source of server messages.
	name string = 'irc.localhost'
	// network is the NETWORK ISUPPORT token.
	network string = 'vIRCd'
	// description is the server description, shown by WHOIS and LINKS.
	description string = 'vIRCd server'
	// db is the SQLite database path.
	db string = 'vircd.db'
	// password, when set, is the connection password clients must send with PASS.
	password string
	// oper_user and oper_password enable OPER for one operator.
	oper_user     string
	oper_password string
	// tls_cert and tls_key enable TLS on the listener (PEM files).
	tls_cert string
	tls_key  string
	// allow_plaintext_auth allows SASL PLAIN without TLS on a non-loopback address.
	allow_plaintext_auth bool
	// force_nick_account makes a logged-in client use its account name as nickname.
	// Account names are reserved either way: only the account may use them.
	force_nick_account bool = true
	// motd is the message of the day, one line per element.
	motd []string = ['Welcome to vIRCd, an IRCv3 server written in V.']
	// max_clients is the most simultaneous connections.
	max_clients int = 1000
	// max_per_ip is the most simultaneous connections from one address.
	max_per_ip int = 20
	// sendq is the most lines queued for one client before it is disconnected.
	sendq int = 4096
	// flood_burst lines are processed at once; then one line every 1/flood_rate seconds.
	// A flood_rate of 0 disables flood control.
	flood_burst int = 20
	flood_rate  int = 5
	// ping_interval is the idle time before the server sends PING; a client that
	// does not answer within ping_timeout more is disconnected.
	ping_interval time.Duration = 90 * time.second
	ping_timeout  time.Duration = 60 * time.second
	// registration_timeout is how long a connection may stay unregistered.
	registration_timeout time.Duration = 60 * time.second
	// history_limit is the most messages kept per conversation; 0 disables history.
	history_limit int = 10000
	// auth_workers is the most password checks running at once.
	auth_workers int = 4
}

// limits advertised in ISUPPORT and enforced by the server.
// nick_len lets every account name be used as a nickname.
const nick_len = store.max_account_name
const user_len = 18
// host_len fits any IP address in text, as hosts are not resolved (display_host
// may add a leading 0).
const host_len = 46
const channel_len = 64
const topic_len = 390
const away_len = 390
const kick_len = 390
const real_len = 390
const max_targets = 4
const max_channels = 100
const max_modes = 4
const max_monitor = 100
const max_list_masks = 100
// max_mask_len bounds a ban mask; a full nick!user@host is shorter.
const max_mask_len = 128
const chathistory_max = 100
const whowas_max = 1000
