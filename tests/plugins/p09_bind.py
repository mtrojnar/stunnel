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


class BindingTest(StunnelTest):
    """Checking if the service does't refuse to start if binding fails for some addresses:ports.
       Sample log expected:
       LOG5[ui]: Binding service [server] to 127.0.0.1:43293: Address already in use (98)
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '091. Binding server'
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
    accept = 127.0.0.1:{port}
    accept = 127.0.0.1:0
    accept = 127.0.0.1:{port}
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
        self.description = 'Binding service'


    async def perform_operation(self, cfg: Config, logger: logging.Logger) -> None:
        """Run tests"""
        stunnel = BindingTest(cfg, logger)
        await stunnel.test_stunnel(cfg)
