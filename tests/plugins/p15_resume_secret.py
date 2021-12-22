"""stunnel client-server tests"""

import logging
import os
import pathlib
from plugin_collection import Plugin
from maketest import (
    Config,
    ServerReopen
)


class StunnelTest(ServerReopen):
    """Base class for stunnel client-server tests."""

    def __init__(self, cfg: Config, logger: logging.Logger, path:pathlib.Path):
        super().__init__(cfg, logger, path)
        self.params.services = ['server', 'client']
        self.params.conn_num = 4
        self.events.count = 1


class ResumeTicketSecret(StunnelTest):
    """Checking if the reloaded server resume the session with secret keys for
       the session ticket processing.
       We expect exactly 2 "TLS accepted: previous session reused" to be logged by the
       [server] service, because the server holds keys for the session ticket processing.
       The ticket session resumption also works for the FORK model.
    """

    def __init__(self, cfg: Config, logger: logging.Logger, path:pathlib.Path):
        super().__init__(cfg, logger, path)
        self.params.description = '151. Session resumption with secret keys'
        self.events.count = 3
        self.events.success = [
            "TLS accepted: previous session reused"
        ]
        self.events.failure = [
            "peer did not return a certificate",
            "bad certificate",
            "certificate verify failed",
            "unsupported protocol",
            #"TLS accepted: previous session reused",
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
    ) -> (pathlib.Path, pathlib.Path):
        """Create a configuration file for a stunnel client."""
        contents = f"""
    pid = {cfg.tempd}/stunnel_{service}.pid
    foreground = yes
    debug = debug
    syslog = no

    retry = yes

    [{service}]
    client = yes
    exec = {cfg.pythondir}
    execArgs = python3 {cfg.scriptdir}/reader.py {self.path}
    connect = 127.0.0.1:{ports[1]}
    cert = {cfg.certdir}/client_cert.pem
    """
        cfgfile = cfg.tempd / "stunnel_client.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile, os.devnull


    async def prepare_server_cfgfile(
        self, cfg: Config, port: int, service: str
    ) -> pathlib.Path:
        """Create a configuration file for a stunnel server."""
        contents = f"""
    pid = {cfg.tempd}/stunnel_{service}.pid
    foreground = yes
    debug = debug
    syslog = no

    options = -NO_TICKET
    ticketKeySecret = 6c:42:72:46:57:23:3a:3d:4b:54:2d:7b:55:4b:6e:8f:32:5c:21:6a:2e:6e:47:31:57:20:2f:75:26:7b:4d:25
    ticketMacSecret = 3f:3c:77:53:32:48:79:76:75:7a:50:33:70:65:47:27:32:79:73:7e:73:2c:21:6c:3a:6f:30:28:4c:5c:27:1f

    [{service}]
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{port}
    cert = {cfg.certdir}/server_cert.pem
    verifyPeer = yes
    CAfile = {cfg.certdir}/PeerCerts.pem
    """
        cfgfile = cfg.tempd / "stunnel_server.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile


    async def prepare_additional_server_cfgfile(
        self, cfg: Config, ports: list, lport: int
    ) -> pathlib.Path:
        """Create a configuration file for new stunnel server."""
        contents = f"""
    pid = {cfg.tempd}/stunnel_new_server.pid
    foreground = yes
    debug = debug
    syslog = no

    ticketKeySecret = 6c:42:72:46:57:23:3a:3d:4b:54:2d:7b:55:4b:6e:8f:32:5c:21:6a:2e:6e:47:31:57:20:2f:75:26:7b:4d:25
    ticketMacSecret = 3f:3c:77:53:32:48:79:76:75:7a:50:33:70:65:47:27:32:79:73:7e:73:2c:21:6c:3a:6f:30:28:4c:5c:27:1f

    [server]
    accept = 127.0.0.1:{ports[1]}
    connect = 127.0.0.1:{lport}
    cert = {cfg.certdir}/server_cert.pem
    verifyPeer = yes
    CAfile = {cfg.certdir}/PeerCerts.pem
    """
        cfgfile = cfg.tempd / "stunnel_server.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile


class StunnelClientServerTest(Plugin):
    """Stunnel client-server tests
       HTTP client --> stunnel client --> stunnel server --> HTTP server
    """
    # pylint: disable=too-few-public-methods

    def __init__(self):
        super().__init__()
        self.description = 'Resume session'


    async def perform_operation(self, cfg: Config, logger: logging.Logger) -> None:
        """Run tests"""
        path = os.path.join(cfg.tempd, 'unix.sock')
        stunnel = ResumeTicketSecret(cfg, logger, path)
        await stunnel.test_stunnel(cfg)
