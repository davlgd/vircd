#!/usr/bin/env python3
"""End-to-end checks of a vIRCd binary, with Python's standard library only.

Starts the server on a free local port with a fresh database, then runs real
client sessions: SASL PLAIN and SCRAM-SHA-256, a channel conversation, the
nickname rules, line length limits, and read markers kept across connections;
then, on a server started with --relaxed-nicks, read markers shared by two
simultaneous sessions. With --tls, it also creates a local CA and connects with
certificate and host name verification.
"""

import argparse
import base64
import contextlib
import hashlib
import hmac
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import time

PASSWORD = secrets.token_urlsafe(24)
LONG_NAME = "g" * 32  # the longest account name and nickname


def parse(line):
    tags = {}
    source = None
    if line.startswith("@"):
        raw, line = line[1:].split(" ", 1)
        tags = dict(p.partition("=")[::2] for p in raw.split(";"))
    if line.startswith(":"):
        source, line = line[1:].split(" ", 1)
    if " :" in line:
        rest, trailing = line.split(" :", 1)
        params = rest.split() + [trailing]
    else:
        params = line.split()
    return {"tags": tags, "source": source, "command": params[0], "params": params[1:]}


class Client:
    def __init__(self, server):
        self.sock = socket.create_connection(("127.0.0.1", server.port), timeout=5)
        if server.tls:
            self.sock = server.tls.wrap_socket(self.sock, server_hostname="localhost")
        self.file = self.sock.makefile("rb")

    def send(self, line):
        self.sock.sendall((line + "\r\n").encode())

    def until(self, command, check=lambda _: True):
        """Reads up to the first `command` message for which `check` holds."""
        seen = []
        for _ in range(200):
            line = self.file.readline()
            if not line.endswith(b"\r\n"):
                raise AssertionError(f"connection closed while waiting for {command}: {seen}")
            msg = parse(line[:-2].decode())
            msg["size"] = len(line) - len(line.split(b" ", 1)[0]) - 1 if line.startswith(b"@") else len(line)
            seen.append(msg)
            if msg["command"] == "PING":
                self.send("PONG :" + msg["params"][-1])
            if msg["command"] == command and check(msg):
                return msg, seen
        raise AssertionError(f"no {command} in {seen}")

    def register(self, nick, account=None, caps=(), mechanism="PLAIN"):
        """Registers, logging in to `account` first when one is given."""
        caps = set(caps) | ({"sasl"} if account else set())
        if caps:
            self.send("CAP LS 302")
            self.send("CAP REQ :" + " ".join(sorted(caps)))
            self.until("CAP", lambda m: m["params"][1] == "ACK")
        self.send("NICK " + nick)
        self.send(f"USER {nick} 0 * :vIRCd smoke test")
        if account:
            self.login(account, mechanism)
        if caps:
            self.send("CAP END")

    def login(self, account, mechanism="PLAIN"):
        self.send("AUTHENTICATE " + mechanism)
        self.until("AUTHENTICATE")
        if mechanism == "PLAIN":
            self.authenticate(f"\0{account}\0{PASSWORD}")
        else:
            self.scram(account)
        self.until("903")

    def authenticate(self, payload):
        self.send("AUTHENTICATE " + base64.b64encode(payload.encode()).decode())

    def challenge(self):
        msg, _ = self.until("AUTHENTICATE")
        return base64.b64decode(msg["params"][0]).decode()

    def scram(self, account):
        """SCRAM-SHA-256 (RFC 5802, RFC 7677), checking the server signature too."""
        nonce = secrets.token_urlsafe(18)
        client_first = f"n={account},r={nonce}"
        self.authenticate("n,," + client_first)
        server_first = self.challenge()
        attrs = dict(kv.split("=", 1) for kv in server_first.split(","))
        assert attrs["r"].startswith(nonce), server_first
        salted = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(),
                                     base64.b64decode(attrs["s"]), int(attrs["i"]))
        client_final = f"c=biws,r={attrs['r']}"
        auth_message = f"{client_first},{server_first},{client_final}".encode()
        client_key = hmac.digest(salted, b"Client Key", "sha256")
        signature = hmac.digest(hashlib.sha256(client_key).digest(), auth_message, "sha256")
        proof = bytes(a ^ b for a, b in zip(client_key, signature))
        self.authenticate(client_final + ",p=" + base64.b64encode(proof).decode())
        server_key = hmac.digest(salted, b"Server Key", "sha256")
        expected = base64.b64encode(hmac.digest(server_key, auth_message, "sha256")).decode()
        assert self.challenge() == "v=" + expected
        self.send("AUTHENTICATE +")

    def close(self):
        with contextlib.suppress(OSError):
            self.file.close()
            self.sock.close()


class Server:
    def __init__(self, binary, workdir, tls, *options):
        self.binary = binary
        self.db = str(workdir / "vircd.db")
        self.tls = None
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        args = [binary, "--db", self.db, "serve", "--listen", f"127.0.0.1:{self.port}",
                "--flood-rate", "0", *options]
        if tls:
            certs = workdir / "certs"
            subprocess.run(["sh", str(Path(__file__).parent / "create-local-tls.sh"), str(certs)],
                           check=True, capture_output=True)
            args += ["--tls-cert", str(certs / "server.pem"), "--tls-key", str(certs / "server.key")]
            self.tls = ssl.create_default_context(cafile=str(certs / "ca.pem"))
        self.log_path = workdir / "server.log"
        self.log = open(self.log_path, "wb")
        self.proc = subprocess.Popen(args, stdout=self.log, stderr=self.log)
        self.clients = []

    def add_account(self, name):
        subprocess.run([self.binary, "--db", self.db, "account", "add", "--password-stdin", name],
                       input=PASSWORD + "\n", text=True, check=True, timeout=30,
                       stdout=subprocess.DEVNULL)

    def connect(self):
        deadline = time.monotonic() + 10
        while True:
            try:
                client = Client(self)
                break
            except ConnectionRefusedError:
                if self.proc.poll() is not None or time.monotonic() > deadline:
                    raise
                time.sleep(0.05)
        self.clients.append(client)
        return client

    def stop(self):
        for client in self.clients:
            client.close()
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        finally:
            self.log.close()


def check_conversation(server):
    """Two accounts, one per SASL mechanism, talk in a channel."""
    alice = server.connect()
    alice.register("alice", "alice", {"server-time", "message-tags", "account-tag"})
    alice.until("001")
    bob = server.connect()
    bob.register("bob", "bob", {"echo-message"}, mechanism="SCRAM-SHA-256")
    bob.until("001")
    for client in (alice, bob):
        client.send("JOIN #smoke")
        client.until("366")
    bob.send("PRIVMSG #smoke :Hello — café")
    msg, _ = alice.until("PRIVMSG")
    assert msg["source"].startswith("bob!") and msg["params"] == ["#smoke", "Hello — café"], msg
    assert msg["tags"]["account"] == "bob" and msg["tags"]["time"].endswith("Z"), msg
    echo, _ = bob.until("PRIVMSG")
    assert echo["params"] == msg["params"], echo
    alice.send("WHOIS bob")
    _, whois = alice.until("318")
    assert any(m["command"] == "330" and m["params"][2] == "bob" for m in whois), whois
    bob.send("QUIT :bye")
    quit_msg, _ = alice.until("QUIT")
    assert quit_msg["source"].startswith("bob!"), quit_msg


def check_nicknames(server):
    """Account names are reserved, and logged-in clients use theirs."""
    guest = server.connect()
    guest.register("Dave")
    refused, _ = guest.until("433")
    assert refused["params"][:2] == ["*", "Dave"] and "reserved" in refused["params"][2], refused
    guest.send("NICK visitor")
    guest.until("001")
    guest.send("NICK dave")
    guest.until("433", lambda m: m["params"][:2] == ["visitor", "dave"])

    erin = server.connect()
    erin.register("someone", "erin")
    welcome, _ = erin.until("001")
    assert welcome["params"][0] == "erin", welcome
    erin.send("NICK other")
    erin.until("432", lambda m: m["params"][1] == "other")
    erin.send("NICK Erin")
    erin.until("NICK", lambda m: m["params"] == ["Erin"])

    second = server.connect()
    second.register("erin2", "erin")
    second.until("433", lambda m: m["params"][1] == "erin")
    second.until("ERROR")

    late = server.connect()
    late.register("latecomer", caps={"sasl"})
    late.until("001")
    late.login("dave")
    late.until("NICK", lambda m: m["source"].startswith("latecomer!") and m["params"] == ["dave"])

    squatter = server.connect()
    squatter.register("carol")
    squatter.until("001")
    server.add_account("carol")
    carol = server.connect()
    carol.register("carol_", "carol")
    welcome, _ = carol.until("001")
    assert welcome["params"][0] == "carol", welcome
    squatter.until("NICK", lambda m: m["source"].startswith("carol!")
                   and m["params"][0].startswith("Guest"))


def check_line_limits(server):
    """Replies stay within 512 bytes (tags apart): lists are split, long text is shortened."""
    gina = server.connect()
    gina.register(LONG_NAME, LONG_NAME)
    gina.until("001")
    channels = [f"#{i:02d}" + "x" * 60 for i in range(30)]
    for i in range(0, len(channels), 5):
        gina.send("JOIN " + ",".join(channels[i:i + 5]))
    gina.until("366", lambda m: m["params"][1] == channels[-1])
    gina.send("WHOIS " + LONG_NAME)
    _, whois = gina.until("318")
    lists = [m for m in whois if m["command"] == "319"]
    assert len(lists) > 1 and all(m["size"] <= 512 for m in lists), lists
    listed = [name.lstrip("@+") for m in lists for name in m["params"][2].split()]
    assert sorted(listed) == sorted(channels), listed
    # Many mode changes and long ban masks go out on several MODE lines.
    masks = [f"{c}" * 40 + "!*@*" for c in "wxyz"]
    gina.send(f"MODE {channels[0]} " + "+i-i" * 50 + "+bbbb " + " ".join(masks))
    gina.send("PING :modes")
    _, seen = gina.until("PONG")
    modes = [m for m in seen if m["command"] == "MODE"]
    assert len(modes) > 1 and all(m["size"] <= 512 for m in modes), modes
    assert sorted(a for m in modes for a in m["params"][2:]) == masks, modes
    # With a 32-byte nickname, a 390-byte topic would make a 526-byte line.
    gina.send(f"TOPIC {channels[0]} :" + "é" * 195)
    topic, _ = gina.until("TOPIC")
    assert topic["size"] <= 512 and topic["params"][1] == "é" * len(topic["params"][1]), topic


def check_read_markers(server):
    """A read marker set in one session comes back in the next one, never backwards."""
    first = server.connect()
    first.register("frank", "frank", {"draft/read-marker", "echo-message", "server-time"})
    first.until("001")
    first.send("JOIN #markers")
    first.until("366")
    first.send("PRIVMSG #markers :read me")
    echo, _ = first.until("PRIVMSG")
    marker = "timestamp=" + echo["tags"]["time"]
    first.send("MARKREAD #markers " + marker)
    first.until("MARKREAD", lambda m: m["params"] == ["#markers", marker])
    first.send("QUIT")
    first.until("ERROR")

    second = server.connect()
    second.register("frank", "frank", {"draft/read-marker"})
    second.until("MARKREAD", lambda m: m["params"] == ["#markers", marker])
    second.send("MARKREAD #markers timestamp=2020-01-01T00:00:00.000Z")
    second.until("MARKREAD", lambda m: m["params"] == ["#markers", marker])


def check_markers_across_sessions(server):
    """Two simultaneous sessions of one account share their read markers (--relaxed-nicks)."""
    sessions = []
    for nick in ("helen-laptop", "helen-phone"):
        session = server.connect()
        session.register(nick, "helen", {"draft/read-marker"})
        session.until("001")
        session.send("JOIN #shared")
        session.until("366")
        sessions.append(session)
    marker = "timestamp=2026-01-01T00:00:00.000Z"
    sessions[0].send("MARKREAD #shared " + marker)
    for session in sessions:
        session.until("MARKREAD", lambda m: m["params"] == ["#shared", marker])


def run(binary, tls, accounts, checks, *options):
    with tempfile.TemporaryDirectory(prefix="vircd-smoke-") as temp:
        server = Server(binary, Path(temp), tls, *options)
        try:
            for name in accounts:
                server.add_account(name)
            for check in checks:
                check(server)
                print("ok", check.__name__)
        except BaseException:
            print(server.log_path.read_text(errors="replace"))
            raise
        finally:
            server.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--binary", type=Path, default=Path("vircd"))
    parser.add_argument("--tls", action="store_true", help="serve TLS with a new local CA")
    args = parser.parse_args()
    binary = str(args.binary.resolve(strict=True))
    run(binary, args.tls, ("alice", "bob", "dave", "erin", "frank", LONG_NAME),
        [check_conversation, check_nicknames, check_line_limits, check_read_markers])
    run(binary, args.tls, ("helen",), [check_markers_across_sessions], "--relaxed-nicks")
    print(f"PASS ({'TLS' if args.tls else 'TCP'})")


if __name__ == "__main__":
    main()
