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


class VerifyCRL(StunnelTest):
    """Checking if the CRL is verified.
       The verifyChain option verifies the peer certificate starting from the root CA.
       The self-signed root CA certificate is stored in the file specified with CAfile.
       Certificate Revocation Lists file is stored in the file specified with CRLfile.
       The success is expected because python client presents the valid certificate.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '051. CRL file with valid certificate'
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
    cert = {cfg.certdir}/server_cert.pem
    verifyChain = yes
    CAfile = {cfg.certdir}/CACert.pem
    CRLfile = {cfg.certdir}/CACertCRL.pem
    """
        cfgfile = cfg.tempd / "stunnel_server.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile


class FailureVerifyCRL(StunnelTest):
    """Checking if the CRL is verified.
       The verifyChain option verifies the peer certificate starting from the root CA.
       The self-signed root CA certificate is stored in the file specified with CAfile.
       Certificate Revocation Lists file is stored in the file specified with CRLfile.
       The failure is expected because the python client presents the revoked certificate.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '052. CRL file with revoked certificate'
        self.params.context = 'load_revoked_cert'
        self.events.count = 1
        self.events.success = [
            "certificate verify failed"
        ]
        self.events.failure = [
            "peer did not return a certificate",
            "bad certificate",
            #"certificate verify failed",
            "unsupported protocol",
            "TLS accepted: previous session reused",
            "Redirecting connection",
            #"Connection reset by peer",
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
    pid = {cfg.tempd}/stunnel_{service}.pid
    foreground = yes
    debug = debug
    syslog = no

    [{service}]
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{port}
    cert = {cfg.certdir}/server_cert.pem
    verifyChain = yes
    CAfile = {cfg.certdir}/CACert.pem
    CRLfile = {cfg.certdir}/CACertCRL.pem
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
        self.description = 'Verify CRL file'


    async def perform_operation(self, cfg: Config, logger: logging.Logger) -> None:
        """Run tests"""
        stunnel = VerifyCRL(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = FailureVerifyCRL(cfg, logger)
        await stunnel.test_stunnel(cfg)
