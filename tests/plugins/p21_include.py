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


class IncludedConfiguration(StunnelTest):
    """Checking if stunnel works with the configuration placed in a few files.
       All configuration file parts are located in the directory specified with include.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '211. Included configuration files'
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

        with open(f"{cfg.tempd}/conf.d/00-global.conf", "w") as conf:
            conf.write(f"""
    pid = {cfg.tempd}/stunnel_{service}.pid
    foreground = yes
    debug = debug
    syslog = no
    """
            )
        with open(f"{cfg.tempd}/conf.d/01-service.conf", "w") as conf:
            conf.write(f"""
    [{service}]
    client = yes
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{ports[1]}
    """)

        contents = f"""
    include = {cfg.tempd}/conf.d
    """
        cfgfile = cfg.tempd / "stunnel_client.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile, os.devnull


    async def prepare_server_cfgfile(
        self, cfg: Config, port: int, service: str
    ) -> pathlib.Path:
        """Create a configuration file for a stunnel server."""
        os.mkdir(f"{cfg.tempd}/conf.d")
        with open(f"{cfg.tempd}/conf.d/00-global.conf", "w") as conf:
            conf.write(f"""
    pid = {cfg.tempd}/stunnel_{service}.pid
    foreground = yes
    debug = debug
    syslog = no
    """)
        with open(f"{cfg.tempd}/conf.d/01-service.conf", "w") as conf:
            conf.write(f"""
    [{service}]
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{port}
    cert = {cfg.certdir}/server_cert.pem
    """)
        contents = f"""
    include = {cfg.tempd}/conf.d
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
        self.description = 'Included configuration'


    async def perform_operation(self, cfg: Config, logger: logging.Logger) -> None:
        """Run tests"""
        stunnel = IncludedConfiguration(cfg, logger)
        await stunnel.test_stunnel(cfg)
