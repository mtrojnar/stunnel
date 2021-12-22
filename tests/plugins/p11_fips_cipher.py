"""stunnel server tests"""

import logging
import pathlib
from plugin_collection import Plugin
from maketest import (
    Config,
    ExpectedConfigurationFailure
)


class StunnelTest(ExpectedConfigurationFailure):
    """Base class for stunnel server tests."""

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.ssl_client = True
        self.params.services = ['server']


class FailureCipherFIPS(StunnelTest):
    """Checking FIPS mode.
       The cipher "CAMELLIA256-SHA" (TLS1_TXT_RSA_WITH_CAMELLIA_256_CBC_SHA256)
       is unavailable if FIPS is enabled.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '111. Failure FIPS mode with unavailable cipher'
        self.events.skip = [
            "FIPS provider not available",
            "fips mode not supported",
            r"FIPS PROVIDER.*could not load the shared library"
        ]
        self.events.count = 1
        self.events.success = [
            "no cipher match"
        ]
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
            #"Something went wrong: stunnel 'server' failed",
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

    fips = yes
    ciphers = CAMELLIA256-SHA

    [{service}]
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{port}
    cert = {cfg.certdir}/server_cert.pem
    """
        cfgfile = cfg.tempd / "stunnel_server.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile


class FailureCiphersuitesFIPS(StunnelTest):
    """Checking FIPS mode.
       The ciphersuite "TLS_CHACHA20_POLY1305_SHA256" is unavailable if FIPS is enabled.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '112. Failure FIPS mode with unavailable ciphersuite'
        self.events.skip = [
            "FIPS provider not available",
            "fips mode not supported",
            r"FIPS PROVIDER.*could not load the shared library"
        ]
        self.events.count = 1
        self.events.success = [
            "disabled for FIPS",
            "no ciphers available"
        ]
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

    fips = yes
    ciphersuites = TLS_CHACHA20_POLY1305_SHA256

    [{service}]
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{port}
    cert = {cfg.certdir}/server_cert.pem
    """
        cfgfile = cfg.tempd / "stunnel_server.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile




class FailureEllipticCurveFIPS(StunnelTest):
    """ Checking FIPS mode.
        The elliptic curve "sect163r1" is unavailable if FIPS is enabled.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '113. Failure FIPS mode with unavailable elliptic curve'
        self.events.skip = [
            "FIPS provider not available",
            "fips mode not supported",
            r"FIPS PROVIDER.*could not load the shared library"
        ]
        self.events.count = 1
        self.events.success = [
            "no suitable key share",
            "Invalid groups list in 'curves'"
        ]
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

    fips = yes
    curves = sect163r1

    [{service}]
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{port}
    cert = {cfg.certdir}/server_cert.pem
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
        self.description = 'FIPS mode cipher'


    async def perform_operation(self, cfg: Config, logger: logging.Logger) -> None:
        """Run tests"""
        stunnel = FailureCipherFIPS(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = FailureCiphersuitesFIPS(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = FailureEllipticCurveFIPS(cfg, logger)
        await stunnel.test_stunnel(cfg)
