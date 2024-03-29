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

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.services = [
            'server1',
            'server2',
            'server3',
            'client'
        ]
        self.params.conn_num = 3


class FailoverRoundRobin(StunnelTest):
    """Checking if the failover strategy  for multiple "connect" targets.
       The round robin (rr) strategy ensures fair load distribution.
       Exactly one connection with each service is expected,
       so "TLS accepted: previous session reused" message shows an error.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '201. Failover round robin (rr) strategy'
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

    failover = rr

    [{service}]
    client = yes
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{ports[1]}
    connect = 127.0.0.1:{ports[2]}
    connect = 127.0.0.1:{ports[3]}
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


class FailoverPriority(StunnelTest):
    """Checking if the failover strategy  for multiple "connect" targets.
       The priority (prio) strategy uses the order specified in the config file.
       All connections to the [server1] service are expected.
       "TLS accepted: previous session reused" is not achievable with
       the FORK threading model.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.description = '202. Failover priority (prio) strategy'
        self.events.count = 2
        self.events.success = [
            r"\[server1\].*TLS accepted"
        ]
        self.events.failure = [
            r"\[server2\].*TLS accepted",
            r"\[server3\].*TLS accepted",
            "peer did not return a certificate",
            "bad certificate",
            "certificate verify failed",
            "unsupported protocol",
            #"TLS accepted: previous session reused",
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

    failover = prio

    [{service}]
    client = yes
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{ports[1]}
    connect = 127.0.0.1:{ports[2]}
    connect = 127.0.0.1:{ports[3]}
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


class StunnelClientServerTest(Plugin):
    """Stunnel client-server tests
       HTTP client --> stunnel client --> stunnel server --> HTTP server
    """
    # pylint: disable=too-few-public-methods

    def __init__(self):
        super().__init__()
        self.description = 'Failover strategy'


    async def perform_operation(self, cfg: Config, logger: logging.Logger) -> None:
        """Run tests"""
        stunnel = FailoverRoundRobin(cfg, logger)
        await stunnel.test_stunnel(cfg)

        stunnel = FailoverPriority(cfg, logger)
        await stunnel.test_stunnel(cfg)
