"""stunnel client-server tests"""

import logging
import os
import pathlib
from plugin_collection import Plugin, ERR_CONN_RESET
from maketest import (
    Config,
    StunnelAcceptConnect
)


class StunnelTest(StunnelAcceptConnect):
    """Base class for stunnel client-server tests."""
    # pylint: disable=too-few-public-methods

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.services = ['server', 'client']


class VerifyOCSPStapling(StunnelTest):
    """ Checking OCSP stapling certificate verification.
        OCSP stapling is always available in the server mode.
        Using "verifyChain" automatically enables OCSP stapling in the client mode.
        The success is expected because the server presents a valid certificate.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '271. Test OCSP stapling'
        self.events.count = 1
        self.events.success = [
            r"OCSP: Accepted \(good\)"
        ]
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


    async def prepare_client_cfgfile(
        self, cfg: Config, ports: list, service: str
    ) -> (pathlib.Path, pathlib.Path):
        """Create a configuration file for a stunnel client."""
        contents = f"""
    foreground = yes
    debug = debug
    syslog = no

    [{service}]
    client = yes
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{ports[1]}
    CAfile = {cfg.certdir}/CACert.pem
    verifyChain = yes
    """
        cfgfile = cfg.tempd / "stunnel_client.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile, os.devnull


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
    """
        cfgfile = cfg.tempd / "stunnel_server.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile


class VerifyOCSPClientDriven(StunnelTest):
    """ Checking OCSP stapling certificate verification.
        Using "OCSPaia" enables stunnel to validate certificates with the list of OCSP
        responder URLs retrieved from their AIA (Authority Information Access) extension.
        The success is expected because the client presents a valid certificate.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '272. Test OCSP client-driven'
        self.events.count = 1
        self.events.success = [
            r"OCSP: Accepted \(good\)"
        ]
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


    async def prepare_client_cfgfile(
        self, cfg: Config, ports: list, service: str
    ) -> (pathlib.Path, pathlib.Path):
        """Create a configuration file for a stunnel client."""
        contents = f"""
    foreground = yes
    debug = debug
    syslog = no

    [{service}]
    client = yes
    accept = 127.0.0.1:0
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
    foreground = yes
    debug = debug
    syslog = no

    [{service}]
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{port}
    cert = {cfg.certdir}/server_cert.pem
    CAfile = {cfg.certdir}/CACert.pem
    verifyChain = yes
    OCSPaia = yes
    """
        cfgfile = cfg.tempd / "stunnel_server.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile


class FailureVerifyOCSPStapling(StunnelTest):
    """ Checking OCSP stapling certificate verification.
        OCSP stapling is always available in the server mode.
        Using "verifyChain" automatically enables OCSP stapling in the client mode.
        The failure is expected because the server presents a revoked certificate.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '273. Failure test OCSP stapling'
        self.events.count = 1
        self.events.success = [
            r"OCSP: Rejected \(revoked\)"
        ]
        self.events.failure = [
            "peer did not return a certificate",
            #"bad certificate",
            "certificate verify failed",
            "unsupported protocol",
            "TLS accepted: previous session reused",
            "Redirecting connection",
            #ERR_CONN_RESET,
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
    foreground = yes
    debug = debug
    syslog = no

    [{service}]
    client = yes
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{ports[1]}
    CAfile = {cfg.certdir}/CACert.pem
    verifyChain = yes
    """
        cfgfile = cfg.tempd / "stunnel_client.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile, os.devnull


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
    cert = {cfg.certdir}/revoked_cert.pem
    """
        cfgfile = cfg.tempd / "stunnel_server.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile


class FailureVerifyOCSPClientDriven(StunnelTest):
    """ Checking OCSP stapling certificate verification.
        Using "OCSPaia" enables stunnel to validate certificates with the list of OCSP
        responder URLs retrieved from their AIA (Authority Information Access) extension.
        The failure is expected because client presents a revoked certificate.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '274. Failure test OCSP client-driven'
        self.events.count = 1
        self.events.success = [
            "Rejected by OCSP at depth=0"
        ]
        self.events.failure = [
            "peer did not return a certificate",
            "bad certificate",
            #"certificate verify failed",
            "unsupported protocol",
            "TLS accepted: previous session reused",
            "Redirecting connection",
            #ERR_CONN_RESET,
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
    foreground = yes
    debug = debug
    syslog = no

    [{service}]
    client = yes
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{ports[1]}
    cert = {cfg.certdir}/revoked_cert.pem
    """
        cfgfile = cfg.tempd / "stunnel_client.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile, os.devnull


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
    CAfile = {cfg.certdir}/CACert.pem
    verifyChain = yes
    OCSPaia = yes
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
        self.description = 'OCSP certificate verification'


    async def perform_operation(self, cfg: Config, logger: logging.Logger) -> None:
        """Run tests"""
        stunnel = VerifyOCSPStapling(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = VerifyOCSPClientDriven(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = FailureVerifyOCSPStapling(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = FailureVerifyOCSPClientDriven(cfg, logger)
        await stunnel.test_stunnel(cfg)
