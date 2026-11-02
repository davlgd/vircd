# Working on vIRCd

Read `README.md` first: it describes what the server does and how it is laid out.

## Commands

```sh
v fmt -w .                                   # format
v vet .                                      # style notices
v -cc clang test .                           # unit tests (ircmsg, store)
v -cc clang -o vircd . && python3 tests/smoke.py && python3 tests/smoke.py --tls
```

Always build with `-cc clang` (or gcc): TLS crashes in TCC builds. Before a release, also run the irctest suite (`tests/irctest/README.md`); only its two documented failures are expected.

## Rules the code relies on

- One dispatcher thread (`Server.run` in `server/server.v`) owns every `Server` and `Client` field. Reader threads only send it `Event`s; it queues output lines on each client's `out` channel, which that client's writer thread sends. Do not share state another way.
- Nothing slow runs on the dispatcher: PBKDF2 password checks go to `auth_worker` threads. SQLite queries do run there, so keep them indexed and small.
- Database access goes through `Store.query`, `Store.exec` and `Store.transaction`: `db.sqlite`'s own `exec`, `commit` and `rollback` ignore errors raised while a statement runs.
- Lines sent to clients stay within 512 bytes, tags apart: lists go through `numeric_list`, mode changes through `mode_lines`, and `wire_line` shortens a final free text (topic, reason, real name) or drops the line. Never announce a state change on a line that could be dropped.
- Names are compared folded with `server.casemapping` (`Server.fold`); the database stores folded keys.
- A released schema migration is never edited: add a new one to `store/store.v`.
- `ircmsg` must not depend on the server or the store.
- When the protocol support changes, update `README.md` and `tests/irctest/profile.json`.
