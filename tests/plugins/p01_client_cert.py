"""stunnel client tests"""

import logging
import os
import pathlib
from plugin_collection import Plugin
from maketest import (
    Config,
    StunnelAcceptConnect
)


class StunnelTest(StunnelAcceptConnect):
    """Base class for stunnel client tests."""

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.ssl_server = True
        self.params.services = ['client']


class CertTest(StunnelTest):
    """ Checking if the cert option ensures a client certificate.
        The success is expected because the client presents a certificate.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '011. Test \"cert\" option'
        self.params.context = 'cert_required'
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
    connect = 127.0.0.1:{ports[0]}
    cert = {cfg.certdir}/client_cert.pem
    """
        cfgfile = cfg.tempd / "stunnel_client.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile, os.devnull



class FailureCertTest(StunnelTest):
    """ Checking if the cert option ensures a client certificate.
        The failure is expected because the client does not present any certificate.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '012. Test no \"cert\" option'
        self.params.context = 'cert_required'
        self.events.count = 1
        self.events.success = [
            "Client received unexpected message",
            "Connection reset by peer"
        ]
        self.events.failure = [
            "peer did not return a certificate",
            "bad certificate",
            "certificate verify failed",
            "unsupported protocol",
            "TLS accepted: previous session reused",
            "Redirecting connection",
            #"Connection reset by peer",
            #"Connection lost",
            #"Client received unexpected message",
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
    connect = 127.0.0.1:{ports[0]}
    ;client does not present any certificate
    ;cert = {cfg.certdir}/client_cert.pem
    """
        cfgfile = cfg.tempd / "stunnel_client.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile, os.devnull



class StunnelClientTest(Plugin):
    """Stunnel client tests
       HTTP client --> stunnel client --> HTTPS server
    """
    # pylint: disable=too-few-public-methods

    def __init__(self):
        super().__init__()
        self.description = 'Existing certificate'


    async def perform_operation(self, cfg: Config, logger: logging.Logger) -> None:
        """Run tests"""
        stunnel = CertTest(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = FailureCertTest(cfg, logger)
        await stunnel.test_stunnel(cfg)
