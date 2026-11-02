"""irctest adapter for an isolated, local vIRCd process and SQLite database."""

import json
import os
from pathlib import Path
import socket
import subprocess
import time

from irctest.basecontrollers import BaseServerController, DirectoryBasedController
from irctest.runner import NotImplementedByController
from irctest.specifications import Capabilities, OptionalBehaviors


# What the server implements, so that irctest runs the matching tests.
PROFILE = json.loads((Path(__file__).parent / "profile.json").read_text())


class VircdController(BaseServerController, DirectoryBasedController):
    software_name = "vIRCd"
    supports_sts = False
    supported_sasl_mechanisms = set(PROFILE["sasl"])
    capabilities = frozenset(Capabilities(c) for c in PROFILE["capabilities"])
    optional_behaviors = frozenset(
        OptionalBehaviors[b] for b in PROFILE["optional_behaviors"]
    )
    isupport = PROFILE["isupport"]

    def run(self, hostname, port, *, password, ssl, run_services, faketime,
            websocket_hostname=None, websocket_port=None):
        if websocket_port is not None:
            raise NotImplementedByController("WebSocket listener")
        self.create_config()
        self.hostname = "127.0.0.1"
        self.port = port
        self.port_open = False
        self.binary = str(Path(os.environ["VIRCD_BIN"]).resolve(strict=True))
        self.db = self.directory / "vircd.sqlite"
        args = [self.binary, "--db", str(self.db), "serve", "--listen",
                f"127.0.0.1:{port}", "--name", "My.Little.Server", "--network",
                "vIRCdTest", "--description", "test server", "--oper-user", "operuser", "--oper-password", "operpassword",
                "--flood-rate", "0", "--relaxed-nicks"]
        if password is not None:
            args += ["--password", password]
        if ssl:
            self.gen_ssl()
            args += ["--tls-cert", str(self.pem_path), "--tls-key", str(self.key_path)]
        self._args = args
        self.proc = self.execute(args)

    def wait_for_port(self):
        deadline = time.monotonic() + 15
        while not self.port_open:
            self.check_is_alive()
            try:
                with socket.create_connection((self.hostname, self.port), timeout=1):
                    pass
                self.port_open = True
            except (ConnectionRefusedError, socket.timeout):
                if time.monotonic() >= deadline:
                    raise TimeoutError("vIRCd listener did not open within 15 seconds")
                time.sleep(0.025)

    def wait_for_services(self):
        pass  # Account management is built into vIRCd.

    def registerUser(self, case, username, password=None):
        if password is None:
            raise NotImplementedByController("passwordless account creation")
        self.wait_for_port()
        subprocess.run([self.binary, "--db", str(self.db), "account", "add",
                        "--password-stdin", "--weak-password", username],
                       input=password + "\n", text=True, check=True, timeout=30,
                       stdout=subprocess.DEVNULL)

    def restart(self):
        self.kill_proc()
        self.port_open = False
        self.proc = self.execute(self._args)
        self.wait_for_port()


def get_irctest_controller_class():
    return VircdController
