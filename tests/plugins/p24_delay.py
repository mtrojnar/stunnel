"""stunnel client-server tests"""

import logging
import os
import pathlib
from plugin_collection import Plugin
from maketest import (
    Config,
    ClientConnectExec
)


class StunnelTest(ClientConnectExec):
    """Base class for stunnel client-server tests."""

    def __init__(self, cfg: Config, logger: logging.Logger, path:pathlib.Path):
        super().__init__(cfg, logger, path)
        self.params.services = [
            'server1',
            'server2',
            'server3',
            'client'
        ]
        self.params.conn_num = 3


class RetryDelay(StunnelTest):
    """Checking if the delay option works properly when the session is resumed.
       This option delays DNS lookup for the connect option.
       Delayed resolver inflicts failover = prio.
       We expect exactly 2 "TLS accepted: previous session reused" to be
       logged by the [server] service.
       The resumption of the session does not work for the FORK model.
    """

    def __init__(self, cfg: Config, logger: logging.Logger, path:pathlib.Path):
        super().__init__(cfg, logger, path)
        self.params.description = '241. Resume session with delay option'
        self.events.skip = [
            "FORK"
        ]
        self.events.count = 2
        self.events.success = [
            r"\[server1\].*TLS accepted: previous session reused"
        ]
        self.events.failure = [
            "peer did not return a certificate",
            "bad certificate",
            "certificate verify failed",
            "unsupported protocol",
            #"TLS accepted: previous session reused",
            "Redirecting connection",
            "Connection reset by peer",
            "Connection lost",
            "Client received unexpected message",
            "Server received unexpected message",
            "Something went wrong",
            "INTERNAL ERROR"
        ]
        self.path = path


    async def prepare_client_cfgfile(
        self, cfg: Config, ports: list, service: str
    ) -> pathlib.Path:
        """Create a configuration file for a stunnel client."""
        contents = f"""
    pid = {cfg.tempd}/stunnel_{service}.pid
    foreground = yes
    debug = debug
    syslog = no

    delay = yes
    retry = yes

    [{service}]
    client = yes
    exec = {cfg.pythondir}
    execArgs = python3 {cfg.scriptdir}/reader.py {self.path}
    connect = 127.0.0.1:{ports[1]}
    connect = 127.0.0.1:{ports[2]}
    connect = 127.0.0.1:{ports[3]}
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
    pid = {cfg.tempd}/stunnel_{service}.pid
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


class RetryNoDelay(StunnelTest):
    """Checking if disable delay option works properly when the session is resumed.
       This option delays DNS lookup for the connect option.
       We expect exactly 3 "TLS accepted: new session negotiated" to be
       logged by all services, because failover = rr.
       The resumption of the session does not work for the FORK model.
    """

    def __init__(self, cfg: Config, logger: logging.Logger, path:pathlib.Path):
        super().__init__(cfg, logger, path)
        self.params.description = '242. Resume session with disable delay option'
        self.events.skip = [
            "FORK"
        ]
        self.events.count = 2
        self.events.success = [
            "TLS accepted: new session negotiated"
        ]
        self.events.failure = [
            "peer did not return a certificate",
            "bad certificate",
            "certificate verify failed",
            "unsupported protocol",
            #"TLS accepted: previous session reused",
            "Redirecting connection",
            "Connection reset by peer",
            "Connection lost",
            "Client received unexpected message",
            "Server received unexpected message",
            "Something went wrong",
            "INTERNAL ERROR"
        ]
        self.path = path


    async def prepare_client_cfgfile(
        self, cfg: Config, ports: list, service: str
    ) -> pathlib.Path:
        """Create a configuration file for a stunnel client."""
        contents = f"""
    pid = {cfg.tempd}/stunnel_{service}.pid
    foreground = yes
    debug = debug
    syslog = no

    delay = no
    failover = rr
    retry = yes

    [{service}]
    client = yes
    exec = {cfg.pythondir}
    execArgs = python3 {cfg.scriptdir}/reader.py {self.path}
    connect = 127.0.0.1:{ports[1]}
    connect = 127.0.0.1:{ports[2]}
    connect = 127.0.0.1:{ports[3]}
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
    pid = {cfg.tempd}/stunnel_{service}.pid
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
        self.description = 'Delay option vs resumed session'


    async def perform_operation(self, cfg: Config, logger: logging.Logger) -> None:
        """Run tests"""
        path = os.path.join(cfg.tempd, 'unix.sock')
        stunnel = RetryDelay(cfg, logger, path)
        await stunnel.test_stunnel(cfg)

        stunnel = RetryNoDelay(cfg, logger, path)
        await stunnel.test_stunnel(cfg)
