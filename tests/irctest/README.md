# irctest adapter

[irctest](https://github.com/progval/irctest) is the conformance suite most IRC servers use. This directory lets it drive vIRCd: `vircd_controller.py` starts a fresh server and database for each test, and `profile.json` declares what vIRCd implements (SASL mechanisms, capabilities, optional behaviors, ISUPPORT tokens), so that irctest runs the matching tests. Update the profile when the server changes; never use it to hide a failure.

## Setup

Use irctest revision `7d5d761b7b67f9031daf7784e743d630def22a96`, unmodified:

```sh
git clone https://github.com/progval/irctest.git /tmp/irctest
git -C /tmp/irctest checkout 7d5d761b7b67f9031daf7784e743d630def22a96
uv venv /tmp/irctest-venv
uv pip install --python /tmp/irctest-venv/bin/python -r tests/irctest/requirements.lock
export IRCTEST_SRC=/tmp/irctest IRCTEST_PYTHON=/tmp/irctest-venv/bin/python
export VIRCD_BIN="$PWD/vircd"
```

## Run

`run.sh` passes its arguments to pytest, from the irctest checkout. The whole suite takes about five minutes:

```sh
tests/irctest/run.sh -q -m "not Ergo and not deprecated and not Sable" irctest/server_tests/
```

Expected result: everything passes or is skipped except two tests, for features vIRCd does not have:

- `links.py::ServicesLinksTestCase::testLinksWithServices` expects a services server linked to the IRC server; vIRCd manages accounts itself.
- `read_marker.py::ReadMarkerServiceTestCase::testReadMarkerPropagatedToOtherSessions` connects twice with the same nickname (Ergo's multiclient).

Skipped tests cover what vIRCd does not implement (WebSocket, extbans, `draft/multiline`, …).

## Server options used

The controller runs `vircd serve` with options meant for tests only:

- `--flood-rate 0` disables flood control, which this suite does not test.
- `--relaxed-nicks` lets logged-in clients use nicknames other than their account name, as most irctest SASL tests do. Account names stay reserved.
- Accounts are created with `account add --weak-password`, since some tests use six-character passwords.
