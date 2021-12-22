"""stunnel client-server tests"""

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
        self.params.services = ['server', 'client']
        self.params.conn_num = 3
        self.events.count = 2


class ResumeTicketTLSv12(StunnelTest):
    """Checking the stateless session ticket resumption (RFC 4507bis) with TLSv1.2.
       We expect exactly 2 "TLS accepted: previous session reused" to be logged by the
       [server] service, because [client] connected 3 times (1 new session, 2 reused sessions).
       The following options are used to disable session cache:
       - The "sessionCacheSize = 1" option sets the internal session cache size.
       - "options = -NO_TICKET" (it is the default with OpenSSL 1.1.1 or later)
       Stateless session ticket resumption also works with the FORK threading model.
    """

    def __init__(self, cfg: Config, logger: logging.Logger, path:pathlib.Path):
        super().__init__(cfg, logger, path)
        self.params.description = '141. Stateless session ticket resumption with TLSv1.2'
        self.events.count = 2
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

    sslVersionMax = TLSv1.2
    sessionCacheSize = 1
    options = -NO_TICKET

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


class ResumeTicketTLSv13(StunnelTest):
    """Checking the stateless session ticket resumption (RFC 4507bis) with TLS 1.3.
       We expect exactly 2 "TLS accepted: previous session reused" to be logged by the
       [server] service, because [client] connected 3 times (1 new session, 2 reused sessions).
       The following options are used to disable session cache:
       - The "sessionCacheSize = 1" option sets the internal session cache size.
       - "options = -NO_TICKET" (it is the default with OpenSSL 1.1.1 or later).
       Stateless session ticket resumption also works with the FORK threading model.
    """

    def __init__(self, cfg: Config, logger: logging.Logger, path:pathlib.Path):
        super().__init__(cfg, logger, path)
        self.params.description = '142. Stateless session ticket resumption with TLSv1.3'
        self.events.count = 2
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

    sslVersion = TLSv1.3
    sessionCacheSize = 1
    options = -NO_TICKET

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
        stunnel = ResumeTicketTLSv12(cfg, logger, path)
        await stunnel.test_stunnel(cfg)

        stunnel = ResumeTicketTLSv13(cfg, logger, path)
        await stunnel.test_stunnel(cfg)
