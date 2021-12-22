"""stunnel client tests"""

import logging
import os
import pathlib
from plugin_collection import Plugin
from maketest import (
    Config,
    ExpectedConfigurationFailure
)


class StunnelTest(ExpectedConfigurationFailure):
    """Base class for stunnel client tests."""

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.ssl_server = True
        self.params.services = ['client']


class WrongClientTest(StunnelTest):
    """Checking the wrong client configuration.
       The failure is expected because there is no connect option in the client service.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '251. Wrong client configuration'
        self.events.count = 1
        self.events.success = [
            "Each service must define two endpoints"
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
            #"Something went wrong: stunnel 'client' failed",
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
    ;*** error ***
    ;connect = 127.0.0.1:{ports[0]}
    cert = {cfg.certdir}/client_cert.pem
    """
        cfgfile = cfg.tempd / "stunnel_client.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile, os.devnull


class StunnelClientTest(Plugin):
    """Stunnel client tests:
       HTTP client --> stunnel client --> HTTPS server
    """
    # pylint: disable=too-few-public-methods

    def __init__(self):
        super().__init__()
        self.description = 'Wrong configuration'


    async def perform_operation(self, cfg: Config, logger: logging.Logger) -> None:
        """Run tests"""
        stunnel = WrongClientTest(cfg, logger)
        await stunnel.test_stunnel(cfg)
