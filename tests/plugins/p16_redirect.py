"""stunnel server tests"""

import logging
import pathlib
from plugin_collection import Plugin
from maketest import (
    Config,
    StunnelAcceptConnect
)

class StunnelTest(StunnelAcceptConnect):
    """Base class for stunnel server tests."""

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.ssl_client = True
        self.params.services = ['server']


class RedirectWrongPeerCert(StunnelTest):
    """Redirect stunnel server test.
       The client presents the *wrong* certificate so the connection is redirected.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '161. Redirect connection (wrong peer certificate)'
        self.params.context = 'load_wrong_cert'
        self.events.count = 1
        self.events.success = [
            "Redirecting connection"
        ]
        self.events.failure = [
            "peer did not return a certificate",
            "bad certificate",
            "certificate verify failed",
            "unsupported protocol",
            "TLS accepted: previous session reused",
            #"Redirecting connection",
            "Connection reset by peer",
            "Connection lost",
            "Client received unexpected message",
            "Server received unexpected message",
            "Something went wrong",
            "INTERNAL ERROR"
        ]


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


class RedirectNoPeerCert(StunnelTest):
    """Redirect stunnel server test.
       The client does not present any certificate so the connection is redirected.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '162. Redirect connection (no peer certificate)'
        self.events.count = 1
        self.events.success = [
            "Redirecting connection"
        ]
        self.events.failure = [
            "peer did not return a certificate",
            "bad certificate",
            "certificate verify failed",
            "unsupported protocol",
            "TLS accepted: previous session reused",
            #"Redirecting connection",
            "Connection reset by peer",
            "Connection lost",
            "Client received unexpected message",
            "Server received unexpected message",
            "Something went wrong",
            "INTERNAL ERROR"
        ]


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


class NoRedirectCorrectPeerCert(StunnelTest):
    """No redirect stunnel server test.
       The client presents the *correct* certificate and the connection is not redirected.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '163. Not redirected connection (valid peer certificate)'
        self.params.context = 'load_correct_cert'
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


class RedirectWrongChainCert(StunnelTest):
    """Redirect stunnel server test.
       The client does not present any certificate so the connection is redirected.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '164. Redirect connection (wrong chain)'
        self.events.count = 1
        self.events.success = [
            "Redirecting connection"
        ]
        self.events.failure = [
            "peer did not return a certificate",
            "bad certificate",
            "certificate verify failed",
            "unsupported protocol",
            "TLS accepted: previous session reused",
            #"Redirecting connection",
            "Connection reset by peer",
            "Connection lost",
            "Client received unexpected message",
            "Server received unexpected message",
            "Something went wrong",
            "INTERNAL ERROR"
        ]


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
    verifyChain = yes
    CAfile = {cfg.certdir}/CACert.pem
    """
        cfgfile = cfg.tempd / "stunnel_server.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile


class RedirectNoChainCert(StunnelTest):
    """No redirect stunnel server test.
       The client does not present any certificate so the connection is redirected.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '165. Redirect connection (no chain)'
        self.events.count = 1
        self.events.success = [
            "Redirecting connection"
        ]
        self.events.failure = [
            "peer did not return a certificate",
            "bad certificate",
            "certificate verify failed",
            "unsupported protocol",
            "TLS accepted: previous session reused",
            #"Redirecting connection",
            "Connection reset by peer",
            "Connection lost",
            "Client received unexpected message",
            "Server received unexpected message",
            "Something went wrong",
            "INTERNAL ERROR"
        ]


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
    verifyChain = yes
    CAfile = {cfg.certdir}/CACert.pem
    """
        cfgfile = cfg.tempd / "stunnel_server.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile


class NoRedirectCorrectChainCert(StunnelTest):
    """No redirect stunnel server test.
       The client presents the *correct* certificate and the connection is not redirected.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '166. Not redirected connection (valid chain)'
        self.params.context = 'load_correct_cert'
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
    verifyChain = yes
    CAfile = {cfg.certdir}/CACert.pem
    """
        cfgfile = cfg.tempd / "stunnel_server.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile


class RedirectStunnelTest(Plugin):
    """Stunnel redirect server tests
       HTTPS client --> stunnel server --> HTTP server or "Wrong_connection!"
    """
    # pylint: disable=too-few-public-methods

    def __init__(self):
        super().__init__()
        self.description = 'Redirect connection'


    async def perform_operation(self, cfg: Config, logger: logging.Logger) -> None:
        """Run tests"""
        stunnel = RedirectWrongPeerCert(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = RedirectNoPeerCert(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = NoRedirectCorrectPeerCert(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = RedirectWrongChainCert(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = RedirectNoChainCert(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = NoRedirectCorrectChainCert(cfg, logger)
        await stunnel.test_stunnel(cfg)
