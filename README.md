# vIRCd

An IRCv3 server written in [V](https://vlang.io), with SASL authentication and SQLite storage. It is a single-server daemon for small communities and personal use, and a testbed for IRC modules that could later move to V's standard library.

## Quick start

You need V built from master at commit `ea8fab4` (2026-11-01) or later, clang or gcc, and the SQLite library (`libsqlite3-dev` on Debian/Ubuntu; included in macOS).

```sh
v -cc clang -prod -o vircd .
./vircd account add david                # asks for the password twice
./vircd serve --name irc.example --network Example
```

The server listens on `127.0.0.1:6667` and stores everything in `vircd.db` (`--db` changes the path). Connect with any IRC client, logging in with SASL as `david`.

Build with clang or gcc: with TCC, V's default C compiler on some platforms, TLS handshakes crash inside Mbed TLS, so a TCC build refuses to start with `--tls-cert`.

## TLS

Give a certificate and its key in PEM files; the listener then speaks TLS only:

```sh
./vircd serve --listen 0.0.0.0:6697 --tls-cert cert.pem --tls-key key.pem
```

For a local test, `tests/create-local-tls.sh certs` creates a CA (`certs/ca.pem`) and a `localhost` certificate (`certs/server.pem`, `certs/server.key`) valid for 7 days. It installs nothing: tell your client to trust `certs/ca.pem`.

SASL PLAIN sends the password in clear, so it is refused without TLS, unless the server listens on a loopback address or `--allow-plaintext-auth` is set.

## Connecting with Halloy

Store your password in a file only you can read, then add to Halloy's `config.toml` (see also `examples/halloy-local.toml`):

```toml
[servers.vircd]
nickname = "david"
server = "127.0.0.1"
port = 6667
use_tls = false
channels = ["#vlang"]

[servers.vircd.sasl.plain]
username = "david"
password_file = "/absolute/path/to/vircd-password.txt"
disconnect_on_failure = true
```

With TLS, use `server = "localhost"`, the TLS port, `use_tls = true` and `root_cert_path` pointing to the CA certificate, in the same `[servers.vircd]` block.

## Command line

Flags go before positional arguments. `--db` applies to every command.

| Command | Purpose |
|---|---|
| `serve [flags]` | Run the server |
| `account add [--password-stdin] [--weak-password] <name>` | Create an account |
| `account passwd [--password-stdin] [--weak-password] <name>` | Change a password |
| `account remove <name>` | Delete an account (its message history stays) |
| `account list` | List accounts |

Account passwords are typed twice without echo, or read from the first line of standard input with `--password-stdin`; they never appear on the command line. They must be at least 8 bytes long, unless `--weak-password` is given (for test fixtures). Accounts can be managed while the server runs.

`serve` flags:

| Flag | Default | Meaning |
|---|---|---|
| `--listen` | `127.0.0.1:6667` | Address to bind |
| `--name` | `irc.localhost` | Server name (letters, digits, `.`, `-`, `_`) |
| `--network` | `vIRCd` | Network name (`NETWORK` ISUPPORT token) |
| `--description` | `vIRCd server` | Server description (WHOIS, LINKS) |
| `--password` | | Connection password clients send with `PASS` |
| `--oper-user`, `--oper-password` | | One operator, for `OPER` |
| `--tls-cert`, `--tls-key` | | Serve TLS |
| `--allow-plaintext-auth` | off | Allow SASL PLAIN without TLS on a non-loopback address |
| `--motd` | | Message of the day file |
| `--flood-rate`, `--flood-burst` | `5`, `20` | Lines per second after a burst; `0` disables flood control |
| `--history` | `10000` | Messages kept per conversation; `0` stops recording (stored history stays readable) |
| `--max-per-ip` | `20` | Connections allowed from one address |
| `--relaxed-nicks` | off | Let logged-in clients use nicknames other than their account name (for irctest) |

## How it behaves

- **Accounts and nicknames.** An account name is a reserved nickname: only a client logged in to that account can use it, and a logged-in client always uses its account name (changing its case is allowed). A client therefore gets its account name at registration, or when it logs in later; other nicknames get `432`, and reserved ones `433`. An account has one connection at a time: a second one is refused. If someone took an account's name before the account was created, they are renamed `Guest<n>` when the account logs in.
- **SASL.** PLAIN and SCRAM-SHA-256. An account stores a SCRAM-SHA-256 verifier (PBKDF2-SHA-256, 32768 iterations, random salt), which checks both mechanisms; nothing reversible is stored. PLAIN also runs a password derivation for unknown accounts, as costly as for an account with the same iteration count, and SCRAM gives each unknown name a pseudorandom salt of its own, stable as long as the database is kept, instead of a salt shared by all unknown names. A connection gets five failed attempts.
- **History** (`draft/chathistory`). Channel messages are kept per channel; private messages per pair of accounts, or per account and nickname when the other side is not logged in (only the account can read those). Channels are not persistent: a channel disappears with its last member, and a channel created again later does not show what was said before.
- **Retention.** `--history` is a target, not a hard cap: each conversation is pruned every 128 of its messages, so it can hold up to 127 more in between.
- **Read markers** (`draft/read-marker`). An account's markers are stored, shared by its connections and sent when it logs in (the 100 most recent). A client without an account keeps its markers for the connection only. At most 1000 markers are kept per account; past that, the oldest goes.
- **Limits.** Lines are limited to 512 bytes plus 4096 bytes of client tags; relayed messages are shortened to fit 512 bytes. A client that does not read its output is disconnected.

## Protocol support

Capabilities: `account-notify`, `account-tag`, `away-notify`, `batch`, `cap-notify`, `draft/chathistory`, `draft/read-marker`, `echo-message`, `extended-join`, `extended-monitor`, `invite-notify`, `labeled-response`, `message-tags` (with `msgid` and the `bot` tag), `multi-prefix`, `sasl`, `server-time`, `setname`, `userhost-in-names`. The server is `UTF8ONLY`: lines that are not UTF-8 get `FAIL <command> INVALID_UTF8`.

Commands: `ADMIN`, `AUTHENTICATE`, `AWAY`, `CAP`, `CHATHISTORY`, `HELP` (or `HELPOP`), `INFO`, `INVITE`, `ISON`, `JOIN`, `KICK`, `KILL`, `LINKS`, `LIST`, `LUSERS`, `MARKREAD`, `MODE`, `MONITOR`, `MOTD`, `NAMES`, `NICK`, `NOTICE`, `OPER`, `PART`, `PASS`, `PING`, `PONG`, `PRIVMSG`, `QUIT`, `SETNAME`, `TAGMSG`, `TIME`, `TOPIC`, `USER`, `USERHOST`, `VERSION`, `WALLOPS`, `WHO` (with WHOX), `WHOIS`, `WHOWAS`.

Channel modes: `b`, `i`, `k`, `l`, `m`, `n`, `s`, `t`, and the `o` and `v` prefixes. User modes: `B` (bot), `i`, `o`, `w` (WALLOPS).

Not implemented: server linking, services, multiple connections sharing a nickname, client account registration (`REGISTER`), WebSocket, STS, extbans, `draft/multiline`, message redaction, metadata.

## Design

| Directory | Contents |
|---|---|
| `ircmsg/` | IRC line and IRCv3 tag parsing and serialization, nickname grammar, casemappings. No server dependency: the part meant for V's standard library. |
| `store/` | SQLite schema and migrations, accounts, history, read markers. |
| `server/` | The server. One thread accepts connections; each connection has a reader and a writer thread; a single dispatcher thread owns all state (clients, nicknames, channels), so there are no locks on it. Password checks run on worker threads. |
| `main.v` | Command line. |
| `tests/` | End-to-end smoke test, irctest adapter, local TLS helper. |

## Tests

```sh
v -cc clang test .                                # unit tests (ircmsg, store, TLS stream)
v -cc clang -o vircd . && python3 tests/smoke.py  # end-to-end, add --tls for TLS
```

`tests/smoke.py` needs only Python 3 (and `openssl` with `--tls`). `tests/irctest/` runs the [irctest](https://github.com/progval/irctest) conformance suite against vIRCd; see its README.

## License

Apache License 2.0, see `LICENSE`.
