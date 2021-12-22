"""stunnel client-server tests"""

import logging
import os
import pathlib
from plugin_collection import Plugin
from maketest import (
    Config,
    StunnelAcceptConnect
)

class StunnelTest(StunnelAcceptConnect):
    """Base class for stunnel client-server tests."""

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.services = ['server', 'client']
        self.params.conn_num = 3
        self.events.count = 2
        self.events.skip = [
            "FORK"
        ]


class ResumeRedirectWrongCert(StunnelTest):
    """Checking if redirect TLS client connections works properly when the session is resumed.
       Redirect TLS client connections on certificate-based authentication failures.
       Exactly 2 "TLS accepted: previous session reused" logs for [server] services are expected,
       because the client presents the wrong certificate.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '181. Session resumption and redirect (wrong certificate)'
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
            #"Redirecting connection",
            "Connection reset by peer",
            "Connection lost",
            "Client received unexpected message",
            "Server received unexpected message",
            "Something went wrong",
            "INTERNAL ERROR"
        ]


    async def prepare_client_cfgfile(
        self, cfg: Config, ports: list, service: str
    ) -> (pathlib.Path, pathlib.Path):
        """Create a configuration file for a stunnel client."""
        contents = f"""
    pid = {cfg.tempd}/stunnel_{service}.pid
    foreground = yes
    debug = debug
    syslog = no

    [{service}]
    client = yes
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{ports[1]}
    ;cert = {cfg.certdir}/client_cert.pem
    ;wrong certificate
    cert = {cfg.certdir}/stunnel.pem
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

    [{service}]
    accept = 127.0.0.1:0
    exec = {cfg.pythondir}
    execArgs = python3 {cfg.scriptdir}/error.py
    redirect = 127.0.0.1:{port}
    cert = {cfg.certdir}/server_cert.pem
    verifyPeer = yes
    CAfile = {cfg.certdir}/PeerCerts.pem
    """
        cfgfile = cfg.tempd / "stunnel_server.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile


class ResumeRedirectNoCert(StunnelTest):
    """Checking if redirect TLS client connections works properly when the session is resumed.
       Redirect TLS client connections on certificate-based authentication failures.
       Exactly 2 "TLS accepted: previous session reused" logs for [server] services are expected,
       because the client does not present the any certificate.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '182. Session resumption and redirect (no certificate)'
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
            #"Redirecting connection",
            "Connection reset by peer",
            "Connection lost",
            "Client received unexpected message",
            "Server received unexpected message",
            "Something went wrong",
            "INTERNAL ERROR"
        ]


    async def prepare_client_cfgfile(
        self, cfg: Config, ports: list, service: str
    ) -> (pathlib.Path, pathlib.Path):
        """Create a configuration file for a stunnel client."""
        contents = f"""
    pid = {cfg.tempd}/stunnel_{service}.pid
    foreground = yes
    debug = debug
    syslog = no

    [{service}]
    client = yes
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{ports[1]}
    ;no certificate
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

    [{service}]
    accept = 127.0.0.1:0
    exec = {cfg.pythondir}
    execArgs = python3 {cfg.scriptdir}/error.py
    redirect = 127.0.0.1:{port}
    cert = {cfg.certdir}/server_cert.pem
    verifyPeer = yes
    CAfile = {cfg.certdir}/PeerCerts.pem
    """
        cfgfile = cfg.tempd / "stunnel_server.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile


class ResumeNoRedirectCorrectCert(StunnelTest):
    """Checking if redirect TLS client connections works properly when the session is resumed.
       Do not redirect TLS client connections on certificate-based authentication success.
       Just 2 "TLS accepted: previous session reused" log for [server] service
       is expected, because the client presents the *correct* certificate.
       HTTP client --> stunnel client --> stunnel server --> HTTP server
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '183. Session resumption and no redirect (valid certificate)'
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


    async def prepare_client_cfgfile(
        self, cfg: Config, ports: list, service: str
    ) -> (pathlib.Path, pathlib.Path):
        """Create a configuration file for a stunnel client."""
        contents = f"""
    pid = {cfg.tempd}/stunnel_{service}.pid
    foreground = yes
    debug = debug
    syslog = no

    [{service}]
    client = yes
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{ports[1]}
    ;correct certificate
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

    [{service}]
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{port}
    redirect = 127.0.0.1:0
    cert = {cfg.certdir}/server_cert.pem
    verifyPeer = yes
    CAfile = {cfg.certdir}/PeerCerts.pem
    """
        cfgfile = cfg.tempd / "stunnel_server.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile


class RedirectStunnelTest(Plugin):
    """Stunnel redirect-client-server tests
       HTTP client --> stunnel client --> stunnel server --> HTTP server or "Wrong_connection!"
    """
    # pylint: disable=too-few-public-methods

    def __init__(self):
        super().__init__()
        self.description = 'Resume redirected connection'


    async def perform_operation(self, cfg: Config, logger: logging.Logger) -> None:
        """Run tests"""
        stunnel = ResumeRedirectWrongCert(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = ResumeRedirectNoCert(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = ResumeNoRedirectCorrectCert(cfg, logger)
        await stunnel.test_stunnel(cfg)
