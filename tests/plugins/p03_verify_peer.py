"""stunnel server tests"""

import logging
import pathlib
from plugin_collection import Plugin, ERR_CONN_RESET
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


class VerifyPeer(StunnelTest):
    """Checking if the verifyPeer option verifies the peer certificate.
       The peer certificate is stored in the file specified with CAfile.
       The success is expected because the client presents the valid certificate.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '031. Test \"verifyPeer\" option'
        self.params.context = 'load_correct_cert'
        self.events.failure = [
            "peer did not return a certificate",
            "bad certificate",
            "certificate verify failed",
            "unsupported protocol",
            "TLS accepted: previous session reused",
            "Redirecting connection",
            ERR_CONN_RESET,
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
    foreground = yes
    debug = debug
    syslog = no

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


class FailureVerifyPeer(StunnelTest):
    """Checking if the verifyPeer option verifies the peer certificate.
       The valid peer certificate is stored in the file specified with CAfile.
       The failure is expected because the client presents an incorrect certificate.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '032. Failure test \"verifyPeer\" option'
        self.params.context = 'load_wrong_cert'
        self.events.count = 1
        self.events.success = [
            "certificate verify failed",
            "unknown CA",
            "alert unknown ca",
            ERR_CONN_RESET
        ]
        self.events.failure = [
            "peer did not return a certificate",
            "bad certificate",
            #"certificate verify failed",
            "unsupported protocol",
            "TLS accepted: previous session reused",
            "Redirecting connection",
            #ERR_CONN_RESET,
            #"Connection lost",
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
    foreground = yes
    debug = debug
    syslog = no

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


class StunnelServerTest(Plugin):
    """Stunnel server tests:
       HTTPS client --> stunnel server --> HTTP server
    """
    # pylint: disable=too-few-public-methods

    def __init__(self):
        super().__init__()
        self.description = 'Verify peer'


    async def perform_operation(self, cfg: Config, logger: logging.Logger) -> None:
        """Run tests"""
        stunnel = VerifyPeer(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = FailureVerifyPeer(cfg, logger)
        await stunnel.test_stunnel(cfg)
