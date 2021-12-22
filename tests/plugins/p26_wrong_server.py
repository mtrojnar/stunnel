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


class WrongServerTest(StunnelTest):
    """Checking the wrong server configuration.
       The failure is expected because there is no accept option in the server service.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '261. Wrong server configuration'
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

    [{service}]
    accept = 127.0.0.1:0
    ;*** error ***
    ;connect = 127.0.0.1:{port}
    cert = {cfg.certdir}/server_cert.p12
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
        self.description = 'Wrong configuration'


    async def perform_operation(self, cfg: Config, logger: logging.Logger) -> None:
        """Run tests"""
        stunnel = WrongServerTest(cfg, logger)
        await stunnel.test_stunnel(cfg)
