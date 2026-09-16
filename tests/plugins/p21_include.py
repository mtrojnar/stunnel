"""stunnel client-server tests"""

import logging
import os
import pathlib
from plugin_collection import Plugin, ERR_CONN_RESET
from maketest import (
    Config,
    ExpectedConfigurationFailure,
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

        nested_dir = cfg.tempd / "nested-conf.d"
        nested_dir.mkdir(exist_ok=True)
        (nested_dir / "00-debug.conf").write_text(
            "debug = debug\n", encoding="UTF-8"
        )
        with open(f"{cfg.tempd}/conf.d/00-global.conf", "w") as conf:
            conf.write(f"""
    foreground = yes
    syslog = no
    include = {nested_dir}
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
        nested_dir = cfg.tempd / "nested-conf.d"
        nested_dir.mkdir(exist_ok=True)
        (nested_dir / "00-debug.conf").write_text(
            "debug = debug\n", encoding="UTF-8"
        )
        with open(f"{cfg.tempd}/conf.d/00-global.conf", "w") as conf:
            conf.write(f"""
    foreground = yes
    syslog = no
    include = {nested_dir}
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


class IncludeStackOverflow(ExpectedConfigurationFailure):
    """Reject a configuration with an excessive include depth."""

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.ssl_client = True
        self.params.services = ['server']
        self.params.description = '212. Configuration include stack overflow'
        self.events.count = 1
        self.events.success = [
            r"Include stack overflow.*recursive includes suspected"
        ]
        self.events.failure = [
            "Configuration successful",
            "Each service must define two endpoints",
            "Something went wrong",
            "INTERNAL ERROR"
        ]


    async def prepare_server_cfgfile(
        self, cfg: Config, port: int, service: str
    ) -> pathlib.Path:
        """Create a configuration exceeding the include stack limit."""
        del port, service
        include_dir = cfg.tempd / "include-overflow"
        include_dir.mkdir()
        include_file = include_dir / "00-include.conf"
        include_file.write_text(
            f"include = {include_dir}\n", encoding="UTF-8"
        )

        contents = f"""
    foreground = yes
    debug = debug
    syslog = no
    include = {include_dir}
    """
        cfgfile = cfg.tempd / "stunnel_include_overflow.conf"
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

        stunnel = IncludeStackOverflow(cfg, logger)
        await stunnel.test_stunnel(cfg)
