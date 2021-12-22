"""stunnel client tests"""

import logging
import os
import pathlib
from plugin_collection import Plugin
from maketest import (
    Config,
    ClientConnectExec
)


class StunnelTest(ClientConnectExec):
    """Base class for stunnel client-server tests."""

    def __init__(self, cfg: Config, logger: logging.Logger, path:pathlib.Path):
        super().__init__(cfg, logger, path)
        self.params.ssl_server = True
        self.params.services = ['client']


class ExecConnect(StunnelTest):
    """Simple execute a local inetd-type program in the client service.
       The execArgs option contains arguments for exec including the program name.
    """

    def __init__(self, cfg: Config, logger: logging.Logger, path:pathlib.Path):
        super().__init__(cfg, logger, path)
        self.params.description = '231. Test exec+connect service'
        self.events.failure = [
            "peer did not return a certificate",
            "bad certificate",
            "certificate verify failed",
            "unsupported protocol",
            "TLS accepted: previous session reused",
            "Redirecting connection",
            "Connection reset by peer",
            "Connection lost",
            "Client received unexpected message",
            "Server received unexpected message",
            "Something went wrong",
            "INTERNAL ERROR"
        ]
        self.path = path


    async def prepare_client_cfgfile(
        self, cfg: Config, ports: list, service: str
    ) -> pathlib.Path:
        """Create a configuration file for a stunnel client."""
        contents = f"""
    pid = {cfg.tempd}/stunnel_{service}.pid
    foreground = yes
    debug = debug
    syslog = no

    [{service}]
    client = yes
    exec = {cfg.pythondir}
    execArgs = python3 {cfg.scriptdir}/reader.py {self.path}
    connect = 127.0.0.1:{ports[0]}
    cert = {cfg.certdir}/client_cert.pem
    """
        cfgfile = cfg.tempd / "stunnel_client.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile, os.devnull


class StunnelClientServerTest(Plugin):
    """Stunnel client tests
       HTTP client --> stunnel client --> HTTPS server
    """
    # pylint: disable=too-few-public-methods

    def __init__(self):
        super().__init__()
        self.description = 'Execute a local inetd-type program'


    async def perform_operation(self, cfg: Config, logger: logging.Logger) -> None:
        """Run tests"""
        path = os.path.join(cfg.tempd, 'unix.sock')
        stunnel = ExecConnect(cfg, logger, path)
        await stunnel.test_stunnel(cfg)
