"""Run stunnel with a test configuration, see if it works."""
# pylint: disable=too-many-lines

from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import logging
import os
import pathlib
import re
import signal
import shlex
import ssl
import subprocess
import sys
import tempfile

from typing import (
    Any,
    Callable,
    Coroutine,
    Dict,
    List,
    NamedTuple,
    Optional,
    TypeVar
)

from plugin_collection import PluginCollection

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_SKIP = 125

RESULT_PATH = os.getcwd()
DEFAULT_PROG = os.path.join(RESULT_PATH, "../src/stunnel")
DEFAULT_CERTS = os.path.join(RESULT_PATH, "certs")
DEFAULT_LOGS = os.path.join(RESULT_PATH, "logs")
DEFAULT_LEVEL = logging.INFO

RE_STUNNEL_VERSION = re.compile(
    r""" ^
    stunnel\s+
    (?P<version> (?: [5-9] | [1-9][0-9]* ) \. \S+ )
    (?: \s .* )?
    $ """,
    re.X
)

RE_OPENSSL_VERSION = re.compile(
    r""" ^
    Compiled\/running\swith\sOpenSSL\s+
    (?P<version> (?: [0-3]\.[0-9]\.[0-9]* ) \S+)
    (?: \s .* )?
    $ """,
    re.X
)

RE_LINE_IDX = re.compile(r" ^ Hello \s+ (?P<idx> 0 | [1-9][0-9]* ) $ ", re.X)


@dataclasses.dataclass(frozen=True)
class LogEvent():
    """The base class for an event."""
    etype: str
    level: int
    log: str


TLogEvent = TypeVar("TEvent", bound=LogEvent)


@dataclasses.dataclass(frozen=True)
class ResultEvent(LogEvent):
    """The event to determine the test result."""

    result: bool


@dataclasses.dataclass(frozen=True)
class ListenerClientEvent(LogEvent):
    """The listener task handled a connected client event."""

    peer: str
    conns: TestConnection


@dataclasses.dataclass(frozen=True)
class ClientSendDataEvent(ListenerClientEvent):
    """The specified client sent some data to server."""

    idx: int


@dataclasses.dataclass(frozen=True)
class ConnectionDoneEvent(LogEvent):
    """A test connection was completed."""

    idx: int
    conns: TestConnection
    prefix: str
    conn_num: int
    task: bool


@dataclasses.dataclass(frozen=True)
class StunnelEvent(LogEvent):
    """The event from the stunnel output pipe."""

    service: str
    port: int


@dataclasses.dataclass
class TestConnection:
    """A single connection to the listener via stunnel."""

    idx: int
    port: int
    peer: Optional[str]


@dataclasses.dataclass
class TestParameters():
    """The various states of the test connections."""

    ssl_client: bool
    ssl_server: bool
    description: str
    context: str
    services: List[str]
    conn_num: int


@dataclasses.dataclass
class TestEvents():
    """The various states of the test events."""

    skip: List[str]
    success: List[str]
    failure: List[str]
    count: int


class Keys(NamedTuple):
    """Dictionary key tuple."""

    pid: int
    service: str


class Config(NamedTuple):
    """Runtime configuration for the stunnel test."""
    # pylint: disable=too-few-public-methods

    scriptdir: pathlib.Path
    pythondir: pathlib.Path
    certdir: pathlib.Path
    children: Dict[
        Keys, asyncio.subprocess.Process  # pylint: disable=no-member
    ]
    mainq: asyncio.Queue[LogEvent]
    logsq: asyncio.Queue[LogEvent]
    resq: asyncio.Queue[LogEvent]
    program: pathlib.Path
    tasks: Dict[str, asyncio.Task[None]]
    tempd: pathlib.Path
    utf8_env: Dict[str, str]
    results: pathlib.Path
    summary: pathlib.Path
    debug: int


class TestConnections(NamedTuple):
    """The various states of the test connections."""
    # pylint: disable=too-few-public-methods

    by_id: Dict[int, TestConnection]
    pending: Dict[str, List[ListenerClientEvent]]


class PrintLogs():
    """Base class to handle logging"""

    @classmethod
    def setup_logger(
        cls, name: str, formats:str, log_file:pathlib.Path, debug: int
    ) -> logging.Logger:
        """To setup as many loggers as you want"""
        formatter = logging.Formatter(formats)
        handler = logging.FileHandler(log_file)
        handler.setFormatter(formatter)
        logger = logging.getLogger(name)
        logger.setLevel(debug)
        logger.addHandler(handler)
        return logger


    @classmethod
    def transcript_logs(cls, name: str, format_str:str) -> None:
        """Direct print output to a file, in addition to the terminal."""
        formatter = logging.Formatter(format_str)
        console = logging.StreamHandler()
        console.setLevel(DEFAULT_LEVEL)
        console.setFormatter(formatter)
        logging.getLogger(name).addHandler(console)


    @classmethod
    def log_event(cls, evt: LogEvent, logger: logging.Logger) -> None:
        """Log a message with the given level."""
        if evt.level == 50:
            logger.critical(evt.log)
        elif evt.level == 40:
            logger.error(evt.log)
        elif evt.level == 30:
            logger.warning(evt.log)
        elif evt.level == 20:
            logger.info(evt.log)
        else:
            logger.debug(evt.log)


class TestLogs(PrintLogs):
    """Base class for a event logs."""

    def __init__(self, cfg: Config):
        self.cfg = cfg


    async def process_client(self, evt: ListenerClientEvent) -> None:
        """Shuffle things around the conns structure."""
        tag = "process_client"
        try:
            peer = evt.peer
            conns = evt.conns
            if peer in conns.pending:
                conns.pending[peer].append(evt)
                if evt.etype == "client_send_data":
                    conn = conns.by_id.get(evt.idx)
                    if conn is None:
                        raise Exception("Listener reported unknown connection")
                    if conn.peer is not None:
                        raise Exception(f"Listener reported bad conn {conn!r}")
                    conn.peer = peer
                return

            if evt.etype != "client_connected":
                raise Exception(f"Expected 'client connected' first, got {evt.etype}")
            conns.pending[peer] = [evt]

        except Exception as err:  # pylint: disable=broad-except
            await self.cfg.mainq.put(
                LogEvent(
                    etype="fatal_event",
                    level=50,
                    log=f"[{tag}] Something went wrong: {err}"
                )
            )


    async def remove_connection(self, evt: ConnectionDoneEvent, num: int) -> None:
        """Remove a connection from the structure."""
        tag = "remove_connection"
        try:
            conns = evt.conns
            conn = conns.by_id.get(evt.idx)
            if conn is None:
                raise Exception("No connection")
            del conns.by_id[evt.idx]
            if conn.peer is None:
                await self.cfg.mainq.put(
                    LogEvent(
                        etype="log",
                        level=30,
                        log=f"[{tag}] Warning: Connection #{evt.idx} done too early"
                    )
                )
            if evt.task:
                name = f"{evt.prefix}{evt.idx}"
                task = self.cfg.tasks.pop(name)
                await asyncio.gather(task, return_exceptions=True)
                await self.cfg.mainq.put(
                    LogEvent(
                        etype="log",
                        level=10,
                        log=f"[{tag}] Done with task '{name}'"
                    )
                )
            num += 1
            if num == evt.conn_num:
                num = 0
                await self.cfg.mainq.put(
                    LogEvent(
                        etype="all_connections_event",
                        level=10,
                        log=f"[{tag}] Testing connections done"
                    )
                )
            return num

        except Exception as err:  # pylint: disable=broad-except
            await self.cfg.mainq.put(
                LogEvent(
                    etype="fatal_event",
                    level=50,
                    log=f"[{tag}] Something went wrong: {err}"
                )
            )


    async def process_events(self, logger: logging.Logger) -> None:
        """Wait for all events to handle,
           return a summary of all test results.
        """
        num = 0
        succeeded = 0
        failed = 0
        skipped = 0
        while True:
            evt = await self.cfg.mainq.get()
            self.log_event(evt, logger)
            if  evt.etype == "cleanup_event" or evt.etype == "output_event" \
                or evt.etype == "fatal_event":
                await self.cfg.resq.put(evt)
            elif evt.etype == "stunnel_event" or evt.etype == "result_event" \
                or evt.etype == "all_connections_event":
                await self.cfg.logsq.put(evt)
            elif evt.etype == "client_connected" or evt.etype == "client_send_data" \
                or evt.etype == "client_done":
                await self.process_client(evt)
            elif evt.etype == "connection_done_event":
                await self.cfg.logsq.put(evt)
                num = await self.remove_connection(evt, num)
            elif evt.etype == "set_result_event":
                succeeded += 1 if evt.result=="succeeded" else 0
                failed += 1 if evt.result=="failed" else 0
                skipped += 1 if evt.result=="skipped" else 0
                await self.cfg.logsq.put(evt)
            elif evt.etype == "finish_event":
                await self.cfg.logsq.put(evt)
                return succeeded, failed, skipped


    async def check_version(self, cmd_str: str, p_err: str) -> None:
        """Check the version of stunnel and openssl"""
        tag = "check_version"
        lines = p_err.splitlines()
        if not lines:
            raise Exception(f"Expected at least one line of output from `{cmd_str}`")
        openssl_version = None
        stunnel_version = None
        for line in lines:
            match = RE_STUNNEL_VERSION.match(line)
            if match:
                stunnel_version = match.group("version")
            match = RE_OPENSSL_VERSION.match(line)
            if match:
                openssl_version = match.group("version")
        if not openssl_version:
            raise Exception("Stunnel was compiled and run with various OpenSSL versions")
        if openssl_version < "1.0.2":
            raise Exception(f"OpenSSL version {openssl_version} is deprecated and not supported")
        if not stunnel_version:
            raise Exception(
                f"Could not find the version line in the `{cmd_str}` output:\n"
                + "\n".join(lines)
            )
        await self.cfg.mainq.put(
            LogEvent(
                etype="log",
                level=20,
                log=f"[{tag}] Got stunnel version {stunnel_version}"
            )
        )

    async def get_version(self, logger:logging.Logger) -> str:
        """Obtain the version of stunnel."""
        tag = "get_version"
        await self.cfg.mainq.put(
            LogEvent(
                etype="log",
                level=10,
                log=f"[{tag}] Trying to obtain the version of {self.cfg.program}"
            )
        )
        cmd = [str(self.cfg.program), "-version"]
        cmd_str = " ".join(shlex.quote(word) for word in cmd)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self.cfg.utf8_env
            )
        except (OSError, subprocess.CalledProcessError) as err:
            await self.cfg.mainq.put(
                LogEvent(
                    etype="fatal_event",
                    level=50,
                    log=f"[{tag}] Could not start `{cmd_str}`: {err}"
                )
            )
            raise RuntimeError(err) from err
        await self.cfg.mainq.put(
            LogEvent(
                etype="log",
                level=10,
                log=f"[{tag}] Started `{cmd_str}` as process {proc.pid}"
            )
        )
        b_out, b_err = await proc.communicate()
        if b_out is None or b_err is None:
            raise Exception("proc.communicate() failed")
        p_out, p_err = b_out.decode("UTF-8"), b_err.decode("UTF-8")
        logger.info(p_err)
        rcode = await proc.wait()
        if rcode != 0:
            print(b_out.decode("UTF-8"))
            print(b_err.decode("UTF-8"), file=sys.stderr)
            raise Exception(f"`{cmd_str}` exited with code {rcode}")
        if p_out:
            raise Exception(f"`{cmd_str}` produced output on its stdout stream:\n{p_out}")
        await self.check_version(cmd_str, p_err)
        await self.cfg.mainq.put(
            LogEvent(
                etype="log",
                level=10,
                log=f"[{tag}] Using {self.cfg.tempd} as a temporary directory"
            )
        )


class TestResult():
    """Base class for test result."""

    def __init__(self, cfg: Config, logger: logging.Logger):
        self.cfg = cfg
        self.logger=logger
        self.events = TestEvents(
            skip=[],
            success=[],
            failure=[],
            count=0
        )


    async def parse_event(self, evt: LogEvent) -> str:
        """Parse the event log and send the appropriate event."""
        for event in self.events.skip:
            if re.search(event, evt.log):
                return "skipped"
        for event in self.events.success:
            if re.search(event, evt.log):
                self.events.count -= 1
                if self.events.count == 0:
                    return "succeeded"
        for event in self.events.failure:
            if re.search(event, evt.log):
                self.logger.info(evt.log)
                return "failed"
        return "UNKNOWN"


    async def set_result(self) -> str:
        """Determine the test result."""
        tag = "set_result"
        result = "UNKNOWN"
        while True:
            evt = await self.cfg.resq.get()
            if evt.etype == "output_event" or evt.etype == "fatal_event":
                if result != "skipped":
                    parsed = await self.parse_event(evt)
                if result == "UNKNOWN":
                    result = parsed
            elif evt.etype == "cleanup_event":
                await self.cfg.mainq.put(
                    LogEvent(
                        etype="result_event",
                        level=10,
                        log=f"[{tag}] The test result has been set"
                    )
                )
                if self.events.count > 0 and result != "skipped":
                    self.logger.info(f"Error: {self.events.count}"
                        + f" of {self.events.success} event(s) not found")
                    result = "failed"
                if result == "UNKNOWN":
                    result = "succeeded"
                break
        dots = "."
        for dummy in range(70):
            dots = dots + "."
        self.logger.info(dots + result)
        return result


class TestSuite(TestResult):
    """Base class for test suite"""

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.logger=logger
        self.conns = TestConnections(
            by_id={},
            pending={}
        )
        self.params = TestParameters(
            ssl_client=False,
            ssl_server=False,
            description='UNKNOWN',
            context={},
            services=[],
            conn_num=1
        )


    async def expect_event(self, msgq: asyncio.Queue[LogEvent], pattern: str) -> TLogEvent:
        """Make sure the next event in the logsq queue is of that etype."""
        evt = await msgq.get()
        if evt.etype != pattern:
            raise Exception(f"Expected {pattern}, got {evt.etype}")
        return evt


    async def prepare_server_cfgfile(
        self, cfg: Config, port: int, service: str
    ) -> pathlib.Path:
        """Create a configuration file for a stunnel server."""


    async def prepare_additional_server_cfgfile(
        self, cfg: Config, ports: int, lport: int
    ) -> pathlib.Path:
        """Create a configuration file for additional stunnel server."""


    async def prepare_client_cfgfile(
        self, cfg: Config, ports: list, service: str
    ) -> (pathlib.Path, pathlib.Path):
        """Create a configuration file for a stunnel client."""


    async def start_socket_connections(self) -> None:
        """Start the socket unix server and create the listener task for serve_forever"""


    async def start_connections(self, cfgfile: pathlib.Path, port: int) -> None:
        """Start a group of similar connections, wait for all the connections to complete"""


    async def test_stunnel(self, cfg: Config) -> None:
        """Make a single test of the given stunnel configuration"""
        try:
            tag = "test_stunnel"
            self.logger.info(self.params.description)
            await self.cfg.mainq.put(LogEvent(etype="log", level=30, log=""))
            await self.cfg.mainq.put(
                LogEvent(
                    etype="log",
                    level=30,
                    log=f"[{tag}] ***** Start '{self.params.description}' *****"
                )
            )
            task = asyncio.create_task(self.set_result())
            lport = await self.start_listener()
            ports = [lport]
            await self.start_socket_connections()
            for service in self.params.services:
                if re.search("server", service):
                    cfgfile = await self.prepare_server_cfgfile(cfg, lport, service)
                    port = await self.start_stunnel(cfgfile, service)
                    ports.append(port)
                elif service == "client":
                    cfgfile, cfgnew = await self.prepare_client_cfgfile(cfg, ports, service)
                    port = await self.start_stunnel(cfgfile, service)
                    if cfgnew is not os.devnull:
                        port = await self.reload_stunnel(cfgfile, cfgnew)
                else:
                    raise Exception(f"Unknown '{service}' service")

            cfgfile = await self.prepare_additional_server_cfgfile(cfg, ports, lport)
            await self.start_connections(cfgfile, port)

        except Exception as err:  # pylint: disable=broad-except
            await cfg.mainq.put(
                LogEvent(
                    etype="fatal_event",
                    level=50,
                    log=f"[{tag}] Something went wrong: {err}"
                )
            )
        finally:
            await self.cleanup_stunnels()
            await self.cleanup_tasks()
            await self.expect_event(self.cfg.logsq, "result_event")
            result = task.result()
            await self.cfg.mainq.put(
                ResultEvent(
                    etype="set_result_event",
                    level=30,
                    log=f"[{tag}] Test {result}",
                    result=result
                )
            )
            await self.expect_event(self.cfg.logsq, "set_result_event")


    async def stunnel_output(self, p_out: asyncio.StreamReader, service: str) -> None:
        """Pipe the stunnel output thing."""
        tag = "stunnel_output"
        try:
            while True:
                data = await p_out.readline()
                if not data:
                    await self.cfg.mainq.put(
                        LogEvent(
                            etype="log",
                            level=20,
                            log=f"[{tag}] Done with task '{service} output'"
                        )
                    )
                    return

                line = data.decode("UTF-8").rstrip("\r\n")
                await self.cfg.mainq.put(
                    LogEvent(
                        etype="output_event",
                        level=20,
                        log=f"[{service}] Read {line!r}"
                    )
                )
                if re.search("bound to", line):
                    port = re.search(r"\:(\d{0,9})$", line).group(1)
                    text = re.search(r"]\:(.*)", line).group(1)
                    await self.cfg.mainq.put(
                        StunnelEvent(
                            etype="stunnel_event",
                            level=10,
                            log=f"[{tag}] {text}",
                            service=service,
                            port=port
                        )
                    )
                elif re.search(r"Service \[inetd\] started", line):
                    await self.cfg.mainq.put(
                        StunnelEvent(
                            etype="stunnel_event",
                            level=10,
                            log=f"[{tag}] Starting inetd mode",
                            service=service,
                            port=0
                        )
                    )
                elif re.search(r"Starting exec\+connect", line):
                    await self.cfg.mainq.put(
                        StunnelEvent(
                            etype="stunnel_event",
                            level=10,
                            log=f"[{tag}] Starting exec+connect mode",
                            service=service,
                            port=0
                        )
                    )
                elif re.search("Configuration failed", line):
                    await self.cfg.mainq.put(
                        StunnelEvent(
                            etype="stunnel_event",
                            level=30,
                            log=f"[{tag}] Stunnel '{service}' configuration failed",
                            service=service,
                            port=0
                        )
                    )

        except Exception as err:  # pylint: disable=broad-except
            await self.cfg.mainq.put(
                StunnelEvent(
                    etype="stunnel_event",
                    level=50,
                    log=f"[{tag}] Something went wrong: {err}",
                    service=service,
                    port=0
                )
            )


    async def run_stunnel(self, cfgfile: pathlib.Path, service: str) -> int:
        """Create the stunnel subprocess."""
        tag = "run_stunnel"
        proc = await asyncio.create_subprocess_exec(
            str(self.cfg.program),
            str(cfgfile),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            bufsize=0,
            env=self.cfg.utf8_env
        )
        await self.cfg.mainq.put(
            LogEvent(
                etype="log",
                level=10,
                log=f"[{tag}] Launching the stunnel '{service}' - got pid {proc.pid}"
            )
        )
        self.cfg.children[Keys(pid=proc.pid, service=service)] = proc
        asyncio.create_task(self.stunnel_output(proc.stderr, service))


    async def check_listening_port(self, port:int, service: str) -> int:
        """Raise exception if configuration failed."""
        tag = "check_listening_port"
        if port == 0:
            raise Exception(f"stunnel \'{service}\' failed")
        await self.cfg.mainq.put(
            LogEvent(
                etype="log",
                level=20,
                log=f"[{tag}] '{service}' is listening on port {port}"
            )
        )


    async def start_stunnel(self, cfgfile: pathlib.Path, service: str) -> int:
        """Launch the stunnel with the specified config file."""
        tag = "start_stunnel"
        await self.cfg.mainq.put(
            LogEvent(
                etype="log",
                level=20,
                log=f"[{tag}] Using config file {cfgfile}"
            )
        )
        for line in cfgfile.read_text(encoding="UTF-8").splitlines():
            await self.cfg.mainq.put(
                LogEvent(
                    etype="log",
                    level=20,
                    log=f"[{tag}] {line}"
                )
            )
        await self.run_stunnel(cfgfile, service)
        await self.cfg.mainq.put(
            LogEvent(
                etype="log",
                level=10,
                log=f"[{tag}] Waiting for the stunnel '{service}' to start up"
            )
        )
        evt = await self.expect_event(self.cfg.logsq, "stunnel_event")
        await self.check_listening_port(evt.port, evt.service)
        return evt.port


    async def reload_stunnel(
        self, cfgfile: pathlib.Path, cfgnew: pathlib.Path
    ) -> None:
        """Reload the stunnel with the specified config file."""
        tag = "reload_stunnel"
        os.replace(cfgnew, cfgfile)
        await self.cfg.mainq.put(
            LogEvent(
                etype="log",
                level=20,
                log=f"[{tag}] Reload using config file {cfgfile}"
            )
        )
        for line in cfgfile.read_text(encoding="UTF-8").splitlines():
            await self.cfg.mainq.put(
                LogEvent(
                    etype="log",
                    level=20,
                    log=f"[{tag}] {line}"
                )
            )
        for key, dummy in self.cfg.children.items():
            os.kill(key.pid, signal.SIGHUP)
            await self.cfg.mainq.put(
                LogEvent(
                    etype="log",
                    level=10,
                    log=f"[{tag}] Reload stunnel '{key.service}' PID {key.pid}"
                )
            )
        await self.cfg.mainq.put(
            LogEvent(
                etype="log",
                level=10,
                log=f"[{tag}] Waiting for the stunnel to start up"
            )
        )
        evt = await self.expect_event(self.cfg.logsq, "stunnel_event")
        await self.check_listening_port(evt.port, evt.service)
        return evt.port


    async def start_socket_server(self,
        callback: Callable[
            [asyncio.StreamReader, asyncio.StreamWriter], Coroutine[Any, Any, None]
        ]
    ) -> asyncio.AbstractServer:
        """Get a first available listening port,
           create a new SSL context if necessary and start a socket server.
           The ctx.load_verify_locations method must be specified
           when ctx.verify_mode is other than CERT_NONE.
        """
        tag = "start_socket_server"
        await self.cfg.mainq.put(
            LogEvent(
                etype="log",
                level=20,
                log=f"[{tag}] Server starts on a first available port"
            )
        )
        try:
            if self.params.ssl_server:
                await self.cfg.mainq.put(
                    LogEvent(
                        etype="log",
                        level=20,
                        log=f"[{tag}] Creating a SSL context"
                    )
                )
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                await self.cfg.mainq.put(
                    LogEvent(
                        etype="log",
                        level=20,
                        log=f"[{tag}] Load server certificate"
                    )
                )
                ctx.load_cert_chain(
                    certfile=str(self.cfg.certdir / "server_cert.pem")
                )
                if self.params.context == "cert_required":
                    await self.cfg.mainq.put(
                        LogEvent(
                            etype="log",
                            level=20,
                            log=f"[{tag}] Set verify mode: cert required"
                        )
                    )
                    ctx.verify_mode = ssl.CERT_REQUIRED
                    await self.cfg.mainq.put(
                        LogEvent(
                            etype="log",
                            level=20,
                            log=f"[{tag}] Load Certificate Authority file"
                        )
                    )
                    ctx.load_verify_locations(
                        cafile=str(self.cfg.certdir / "CACert.pem")
                    )
            else:
                ctx=None

            protocol = "HTTPS" if self.params.ssl_server else "HTTP"
            await self.cfg.mainq.put(
                LogEvent(
                    etype="log",
                    level=20,
                    log=f"[{tag}] Start {protocol} server"
                )
            )
            return await asyncio.start_server(
                callback,
                host='127.0.0.1',
                port=0,
                ssl=ctx,
                reuse_address=True,
            )

        except OSError as err:
            await self.cfg.mainq.put(
                LogEvent(
                    etype="fatal_event",
                    level=50,
                    log=f"[{tag}] Start server failed: {err}"
                )
            )


    async def client_connected_cb(
        self,
        server_reader: asyncio.StreamReader,
        server_writer: asyncio.StreamWriter
    ) -> None:
        """Receive something from the client, write something back the client,
           close down sockets, send event "client_done"
        """
        peer_addr, peer_port = server_writer.get_extra_info("peername")[:2]
        peer = f"[{peer_addr}]:{peer_port}"
        tag = f"client_connected_cb {peer}"
        await self.cfg.mainq.put(
            ListenerClientEvent(
                etype="client_connected",
                level=20,
                log=f"[{tag}] The 'listener' task accepted a connection from a client",
                peer=peer,
                conns=self.conns
            )
        )
        while not server_writer.is_closing():
            line = await server_reader.readline()
            if re.search("PROXY TCP4 127.0.0.1", line.decode("UTF-8")):
                await self.cfg.mainq.put(
                    LogEvent(
                        etype="log",
                        level=10,
                        log=f"[{tag}] The listener get the original client IP address"
                        + " with HAProxy PROXY protocol"
                    )
                )
            else:
                try:
                    match = RE_LINE_IDX.match(line.decode("UTF-8"))
                    if not match:
                        raise Exception(f"Server received unexpected message: {line!r}")
                    idx = int(match.group("idx"))
                    await self.cfg.mainq.put(
                        ClientSendDataEvent(
                            etype="client_send_data",
                            level=20,
                            log=f"[{tag}] The client #{idx} sent data to the server: {line!r}",
                            peer=peer,
                            conns=self.conns,
                            idx=idx
                        )
                    )
                    line = "There!\n".encode("UTF-8")
                    server_writer.write(line)
                    await server_writer.drain()
                    await self.cfg.mainq.put(
                        LogEvent(
                            etype="log",
                            level=20,
                            log=f"[{tag}] The server sent data to the client #{idx}: {line!r}",
                        )
                    )
                except Exception as err:  # pylint: disable=broad-except
                    await self.cfg.mainq.put(
                        LogEvent(
                            etype="fatal_event",
                            level=50,
                            log=f"[{tag}] Handling {peer}: {err}"
                        )
                    )
                finally:
                    await self.cfg.mainq.put(
                        LogEvent(
                            etype="log",
                            level=10,
                            log=f"[{tag}] Closing down the server writer socket"
                        )
                    )
                    server_writer.close()
                    await server_writer.wait_closed()
                    await self.cfg.mainq.put(
                        ListenerClientEvent(
                            etype="client_done",
                            level=10,
                            log=f"[{tag}] The 'listener' task closed a connection to the client",
                            peer=peer,
                            conns=self.conns
                        )
                    )


    async def start_listener(self) -> int:
        """Start the socket server, create the listener task for serve_forever
           and return a listening port.
        """
        tag = "start_listener"
        protocol = "HTTPS" if self.params.ssl_server else "HTTP"
        await self.cfg.mainq.put(
            LogEvent(
                etype="log",
                level=20,
                log=f"[{tag}] Awaiting the {protocol} server started..."
            )
        )
        srv = await self.start_socket_server(self.client_connected_cb)
        if not srv:
            raise Exception(f"The listening {protocol} socket server failed")
        if not srv.sockets:
            raise Exception(f"Expected a listening socket, got {srv.sockets!r}")
        hostname, port = srv.sockets[0].getsockname()[:2]
        await self.cfg.mainq.put(
            LogEvent(
                etype="log",
                level=20,
                log=f"[{tag}] {protocol} server is listening on [{hostname}]:{port}"
            )
        )
        await self.cfg.mainq.put(
            LogEvent(
                etype="log",
                level=20,
                log=f"[{tag}] Awaiting client connections..."
            )
        )
        # Start accepting connections until the coroutine is cancelled.
        # Cancellation of serve_forever task causes the server to be closed.
        self.cfg.tasks["listener"] = asyncio.create_task(srv.serve_forever())
        return port


    async def  cleanup_tasks(self) -> None:
        """Cancel and remove all tasks."""
        tag = "cleanup_tasks"
        try:
            tasks = []
            for name, task in self.cfg.tasks.items():
                tasks.append(name)
                task.cancel()
                await self.cfg.mainq.put(
                    LogEvent(
                        etype="log",
                        level=10,
                        log=f"[{tag}] Waiting for the '{name}' task to hopefully finish"
                    )
                )
                await asyncio.gather(task, return_exceptions=True)
                await self.cfg.mainq.put(
                    LogEvent(
                        etype="log",
                        level=10,
                        log=f"[{tag}] Done with the '{name}' task"
                    )
                )
            for name in tasks:
                self.cfg.tasks.pop(name)
            await self.cfg.mainq.put(
                LogEvent(
                    etype="cleanup_event",
                    level=10,
                    log=f"[{tag}] Done with all tasks"
                )
            )

        except Exception as err:  # pylint: disable=broad-except
            await self.cfg.mainq.put(
                LogEvent(
                    etype="cleanup_event",
                    level=20,
                    log=f"[{tag}] Cleanup '{name}' task failed: {err}"
                )
            )


    async def cleanup_stunnels(self) -> None:
        """Terminate and remove any remaining stunnel processes."""
        try:
            tag = "cleanup_stunnels"
            num = len(self.cfg.children)
            await self.cfg.mainq.put(
                LogEvent(
                    etype="log",
                    level=10,
                    log=f"[{tag}] About to kill and wait for {num} stunnel process(es)"
                )
            )
            waiters = [asyncio.create_task(proc.wait()) for proc in self.cfg.children.values()]
            children = []
            for key, proc in self.cfg.children.items():
                await self.cfg.mainq.put(
                    LogEvent(
                        etype="log",
                        level=10,
                        log=f"[{tag}] Waiting for the '{key.service}' PID {key.pid} to exit..."
                    )
                )
                children.append(key)
                try:
                    proc.terminate()
                except ProcessLookupError:
                    await self.cfg.mainq.put(
                        LogEvent(
                            etype="log",
                            level=10,
                            log=f"[{tag}] PID {key.pid} already finished"
                        )
                    )
                except Exception as err:  # pylint: disable=broad-except
                    await self.cfg.mainq.put(
                        LogEvent(
                            etype="log",
                            level=30,
                            log=f"[{tag}] PID {key.pid} termination error: {err!r}"
                        )
                    )
            for key in children:
                self.cfg.children.pop(key)

            wait_res = await asyncio.gather(*waiters)
            await self.cfg.mainq.put(
                LogEvent(
                    etype="log",
                    level=20,
                    log=f"[{tag}] Got stunnel processes' exit status: {wait_res!r}",
                )
            )

        except Exception as err:  # pylint: disable=broad-except
            await self.cfg.mainq.put(
                LogEvent(
                    etype="fatal_event",
                    level=50,
                    log=f"[{tag}] Something went wrong: {err}"
                )
            )


    async def cleanup_stunnel(self, service: str) -> None:
        """Terminate and remove a stunnel processe."""
        tag = f"cleanup_stunnel {service}"
        try:
            for key, proc in self.cfg.children.items():
                if key.service is service:
                    await self.cfg.mainq.put(
                        LogEvent(
                            etype="log",
                            level=10,
                        log=f"[{tag}] Waiting for the '{key.service}' PID {key.pid} to exit..."
                        )
                    )
                    finished = key
                    try:
                        proc.terminate()
                    except ProcessLookupError:
                        await self.cfg.mainq.put(
                            LogEvent(
                                etype="log",
                                level=30,
                                log=f"[{tag}] - already finished, it seems"
                            )
                        )
                    except Exception as err:  # pylint: disable=broad-except
                        await self.cfg.mainq.put(
                            LogEvent(
                                etype="log",
                                level=30,
                                log=f"[{tag}] - {err!r}"
                            )
                        )
                    wait_res = await asyncio.gather(proc.wait())
                    await self.cfg.mainq.put(
                        LogEvent(
                            etype="log",
                            level=20,
                            log=f"[{tag}] Got stunnel processes' exit status: {wait_res!r}",
                        )
                    )
            self.cfg.children.pop(finished)

        except Exception as err:  # pylint: disable=broad-except
            await self.cfg.mainq.put(
                LogEvent(
                    etype="fatal_event",
                    level=50,
                    log=f"[{tag}] Something went wrong: {err}"
                )
            )


class StunnelAcceptConnect(TestSuite):
    """Base class for connection tests"""

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.cfg = cfg


    async def reopen_stunnel(self, cfgfile: pathlib.Path, idx: int, service: str) -> None:
        """Shut stunnel down and run new stunnel subprocess."""


    async def start_connections(
        self, cfgfile: pathlib.Path, port: int
    ) -> None:
        """Start a group of similar connections, wait for all the connections to complete"""
        tag = "start_connections"
        await self.cfg.mainq.put(
            LogEvent(
                etype="log",
                level=10,
                log=f"[{tag}] Testing connections..."
            )
        )
        for idx in range(self.params.conn_num):
            conn = TestConnection(idx=idx, port=port, peer=None)
            self.conns.by_id[idx] = conn
            prefix = "encr-" if self.params.ssl_client else "plain-"
            await self.cfg.mainq.put(
                LogEvent(
                    etype="log",
                    level=10,
                    log=f"[{tag}] Create task {prefix}{idx}"
                )
            )
            await self.reopen_stunnel(cfgfile, idx, "server")
            self.cfg.tasks[f'{prefix}{idx}'] = asyncio.create_task(self.test_connect(conn))
            await self.expect_event(self.cfg.logsq, "connection_done_event")

        await self.expect_event(self.cfg.logsq, "all_connections_event")


    async def establish_connection(
        self, conn: TestConnection
    ) -> (asyncio.StreamReader, asyncio.StreamWriter):
        """Establish a network connection and return a pair of (reader, writer) objects"""
        tag = f"establish_connection [127.0.0.1]:{conn.port} #{conn.idx}"
        try:
            if self.params.ssl_client:
                await self.cfg.mainq.put(
                    LogEvent(
                        etype="log",
                        level=20,
                        log=f"[{tag}] Creating a SSL context"
                    )
                )
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)

                if self.params.context == "load_correct_cert":
                    await self.cfg.mainq.put(
                        LogEvent(
                            etype="log",
                            level=20,
                            log=f"[{tag}] Load the correct certificate"
                        )
                    )
                    ctx.load_cert_chain(
                        certfile=str(self.cfg.certdir / "client_cert.pem")
                    )
                if self.params.context == "load_revoked_cert":
                    await self.cfg.mainq.put(
                        LogEvent(
                            etype="log",
                            level=20,
                            log=f"[{tag}] Load the revoked certificate"
                        )
                    )
                    ctx.load_cert_chain(
                        certfile=str(self.cfg.certdir / "revoked_cert.pem")
                    )
                if self.params.context == "load_wrong_cert":
                    await self.cfg.mainq.put(
                        LogEvent(
                            etype="log",
                            level=20,
                            log=f"[{tag}] Load the wrong certificate"
                        )
                    )
                    ctx.load_cert_chain(
                        certfile=str(self.cfg.certdir / "stunnel.pem")
                    )
                if self.params.context == "load_verify_locations":
                    await self.cfg.mainq.put(
                        LogEvent(
                            etype="log",
                            level=20,
                            log=f"[{tag}] Load Certificate Authority file"
                        )
                    )
                    ctx.load_verify_locations(
                        cafile=str(self.cfg.certdir / "CACert.pem")
                    )
                await self.cfg.mainq.put(
                    LogEvent(
                        etype="log",
                        level=20,
                        log=f"[{tag}] Opening a SSL connection"
                    )
                )
            else:
                # self.params.ssl_client is False
                await self.cfg.mainq.put(
                    LogEvent(
                        etype="log",
                        level=20,
                        log=f"[{tag}] Opening an unencrypted connection"
                    )
                )
                ctx = None

            return await asyncio.open_connection('127.0.0.1', conn.port, ssl=ctx)

        except OSError as err:  # pylint: disable=broad-except
            await self.cfg.mainq.put(
                LogEvent(
                    etype="log",
                    level=30,
                    log=f"[{tag}] Failed to connect to 127.0.0.1:{conn.port}: {err}"
                )
            )
            return None, None


    async def get_io_stream(
        self, conn: TestConnection
    ) -> (asyncio.StreamReader, asyncio.StreamWriter):
        """Start a network connection and return a pair of (reader, writer) objects."""
        client_reader, client_writer = await self.establish_connection(conn)
        if not client_reader or not client_writer:
            raise Exception("Establish connection failed")
        return client_reader, client_writer


    async def test_connect(self, conn: TestConnection) -> None:
        """Make a connection, send something to the server, receive data from the server,
           close down sockets, send event "connection_done_event"
        """
        tag = f"test_connect [127.0.0.1]:{conn.port} #{conn.idx}"
        try:
            await self.cfg.mainq.put(
                LogEvent(
                    etype="log",
                    level=20,
                    log=f"[{tag}] Trying port {conn.port} encrypted {self.params.ssl_client}"
                )
            )
            client_reader, client_writer = await self.get_io_stream(conn)
            if client_writer.is_closing():
                raise Exception("Client writer is closing")

            line = f"Hello {conn.idx}\n".encode("UTF-8")
            await self.cfg.mainq.put(
                LogEvent(
                    etype="log",
                    level=10,
                    log=f"[{tag}] Sending 'Hello {conn.idx}' to the server"
                )
            )
            client_writer.write(line)
            await client_writer.drain()

            line = await client_reader.readline()
            await self.cfg.mainq.put(
                LogEvent(
                    etype="log",
                    level=10,
                    log=f"[{tag}] Client received '{line!r}' from the server"
                )
            )
            if line != "There!\n".encode("UTF-8"):
                raise Exception(f"Client received unexpected message: {line!r}")

            await self.cfg.mainq.put(
                LogEvent(
                    etype="log",
                    level=10,
                    log=f"[{tag}] Closing down the client writer socket"
                )
            )
            client_writer.close()
            await client_writer.wait_closed()
            await self.cfg.mainq.put(
                LogEvent(
                    etype="log",
                    level=10,
                    log=f"[{tag}] Waiting for an EOF on the client reader socket"
                )
            )
            line = await client_reader.read(1)
            if line:
                raise Exception(f"Did not expect to read {line!r}")

        except Exception as err:  # pylint: disable=broad-except
            await self.cfg.mainq.put(
                LogEvent(
                    etype="fatal_event",
                    level=20,
                    log=f"[{tag}] {err}",
                )
            )
        finally:
            await self.cfg.mainq.put(
                ConnectionDoneEvent(
                    etype="connection_done_event",
                    level=20,
                    log=f"[{tag}] Test connection #{conn.idx} has been completed",
                    idx=conn.idx,
                    conns=self.conns,
                    prefix="encr-" if self.params.ssl_client else "plain-",
                    conn_num=self.params.conn_num,
                    task=True
                )
            )


class ExpectedConfigurationFailure(StunnelAcceptConnect):
    """Raise when a specific error occurs."""

    async def check_listening_port(self, port:int, service: str) -> int:
        """Configuration failed as expected."""


class ClientInetd(StunnelAcceptConnect):
    """Base class for inetd mode tests.
       Some other program accept incoming connections and launch stunnel.
    """

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.cfg = cfg
        self.reader=subprocess.DEVNULL
        self.writer=subprocess.DEVNULL


    async def check_listening_port(self, port:int, service: str) -> int:
        """You do not want stunnel to have any accept option."""


    async def run_stunnel(self, cfgfile: pathlib.Path, service: str) -> int:
        """Create the stunnel subprocess."""
        tag = "run_stunnel"
        proc = await asyncio.create_subprocess_exec(
            str(self.cfg.program),
            str(cfgfile),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            env=self.cfg.utf8_env
        )
        self.writer = proc.stdin
        self.reader = proc.stdout
        await self.cfg.mainq.put(
            LogEvent(
                etype="log",
                level=10,
                log=f"[{tag}] Launching the stunnel '{service}' - got pid {proc.pid}"
            )
        )
        self.cfg.children[Keys(pid=proc.pid, service=service)] = proc
        asyncio.create_task(self.stunnel_output(proc.stderr, service))


    async def get_io_stream(
        self, conn: TestConnection
    ) -> (asyncio.StreamReader, asyncio.StreamWriter):
        """Return a pair of (reader, writer) objects."""
        return self.reader, self.writer


class ClientConnectExec(TestSuite):
    """Base class for connect+exec tests.
       Execute a local inetd-type program.
    """

    def __init__(self, cfg: Config, logger: logging.Logger, path:pathlib.Path):
        super().__init__(cfg, logger)
        self.cfg = cfg
        self.path = path
        self.idx=0


    async def check_listening_port(self, port:int, service: str) -> int:
        """You do not want stunnel to have any accept option."""


    async def socket_connected_cb(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a socket connection."""
        tag = f"socket_connected_cb #{self.idx}"
        conn = TestConnection(idx=self.idx, port=0, peer=None)
        self.conns.by_id[self.idx] = conn
        line = f"Hello {self.idx}\n".encode("UTF-8")
        try:
            await self.cfg.mainq.put(
                LogEvent(
                    etype="log",
                    level=10,
                    log=f"[{tag}] Sending 'Hello {self.idx}' to the server"
                )
            )
            writer.write(line)
            await writer.drain()
            line = await reader.readline()
            await self.cfg.mainq.put(
                LogEvent(
                    etype="log",
                    level=20,
                    log=f"[{tag}] Client received '{line}' from the server"
                )
            )
            if line != "There!\n".encode("UTF-8"):
                raise Exception(f"Client received unexpected message: {line!r}")
            await self.cfg.mainq.put(
                LogEvent(
                    etype="log",
                    level=10,
                    log=f"[{tag}] Closing down the 'unix server' writer socket"
                )
            )
            writer.close()
            await writer.wait_closed()
            await self.cfg.mainq.put(
                LogEvent(
                    etype="log",
                    level=10,
                    log=f"[{tag}] Waiting for an EOF on the 'unix server' reader socket"
                )
            )
            line = await reader.read(1)
            if line:
                raise Exception(f"Did not expect to read {line!r}")

        except Exception as err:  # pylint: disable=broad-except
            await self.cfg.mainq.put(
                LogEvent(
                    etype="fatal_event",
                    level=20,
                    log=f"[{tag}] {err}",
                )
            )
        finally:
            await self.cfg.mainq.put(
                ConnectionDoneEvent(
                    etype="connection_done_event",
                    level=20,
                    log=f"[{tag}] Test connection #{self.idx} has been completed",
                    idx=self.idx,
                    conns=self.conns,
                    prefix="encr-" if self.params.ssl_client else "plain-",
                    conn_num=self.params.conn_num,
                    task=False
                )
            )
            self.idx +=1


    async def start_socket_connections(self) -> None:
        """Start the socket unix server and create the listener task for serve_forever"""
        tag = "start_socket_connections"
        await self.cfg.mainq.put(
            LogEvent(
                etype="log",
                level=20,
                log=f"[{tag}] Awaiting the 'unix server' with {self.path} started..."
                )
            )
        srv = await asyncio.start_unix_server(self.socket_connected_cb, self.path)
        self.cfg.tasks["unix server"] = asyncio.create_task(srv.serve_forever())


    async def start_connections(self, cfgfile: pathlib.Path, port: int) -> None:
        """Wait for all the connections to complete."""
        for dummy in range(self.params.conn_num):
            await self.expect_event(self.cfg.logsq, "connection_done_event")
        await self.expect_event(self.cfg.logsq, "all_connections_event")


class ServerReopen(ClientConnectExec):
    """Base class for shut down tests"""

    def __init__(self, cfg: Config, logger: logging.Logger, path:pathlib.Path):
        super().__init__(cfg, logger, path)
        self.cfg = cfg


    async def reopen_stunnel(self, cfgfile: pathlib.Path, idx: int, service: str) -> None:
        """Shut stunnel down and run new stunnel subprocess."""
        if idx == 3:
            await self.cleanup_stunnel(service)
            await self.start_stunnel(cfgfile, service)


@contextlib.contextmanager
def parse_args() -> Config:
    """Parse the command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--certs",
        type=pathlib.Path,
        default=DEFAULT_CERTS,
        metavar="CERTDIR",
        help="the path to the test certificates directory "
        f"(default: {DEFAULT_CERTS})",
    )
    parser.add_argument(
        "--program",
        type=pathlib.Path,
        default=DEFAULT_PROG,
        help=f"the path to the stunnel executable to use "
        f"(default: {DEFAULT_PROG})",
    )
    parser.add_argument(
        "--logs",
        type=pathlib.Path,
        default=DEFAULT_LOGS,
        metavar="LOGDIR",
        help=f"the path to the test logs directory "
        f"(default: {DEFAULT_LOGS})",
    )
    parser.add_argument(
        "--debug",
        type=int,
        default=DEFAULT_LEVEL,
        metavar="LEVEL",
        help="the logging level "
        "(default: INFO)",
    )
    args = parser.parse_args()
    utf8_env = dict(os.environ)
    utf8_env.update({"LC_ALL": "C.UTF-8", "LANGUAGE": ""})
    if not os.path.isdir(args.logs):
        os.mkdir(args.logs)
    with os.scandir(args.logs) as entries:
        for entry in entries:
            os.remove(entry)

    with tempfile.TemporaryDirectory(prefix="stunnel_tests.") as tempd_name:
        yield Config(
            scriptdir=os.path.dirname(os.path.abspath(__file__)),
            pythondir=sys.executable,
            certdir=args.certs,
            children={},
            mainq=asyncio.Queue(),
            logsq=asyncio.Queue(),
            resq=asyncio.Queue(),
            program=args.program,
            tasks={},
            tempd=pathlib.Path(tempd_name),
            utf8_env=utf8_env,
            results=os.path.join(args.logs, "results.log"),
            summary=os.path.join(args.logs, "summary.log"),
            debug=args.debug
        )


async def main() -> None:
    """Main program: parse arguments, prepare an environment, run tests."""
    if not (sys.version_info.major == 3 and sys.version_info.minor >= 7):
        print("Python 3.7 or higher is required.\n"
            + "You are using Python {}.{}.".format(sys.version_info.major, sys.version_info.minor))
        sys.exit(EXIT_SKIP)
    tag = "main"
    omitted = False
    with parse_args() as cfg:
        try:
            rlogs = TestLogs(cfg)
            formats = "%(levelname)s: %(asctime)s: %(message)s"
            rlogger = rlogs.setup_logger("results", formats, cfg.results, cfg.debug)
            task = asyncio.create_task(rlogs.process_events(rlogger))

            slogs = TestLogs(cfg)
            formats = "%(message)s"
            slogger = slogs.setup_logger("summary", formats, cfg.summary, DEFAULT_LEVEL)
            await slogs.get_version(slogger)
            slogs.transcript_logs("summary", formats)

            await PluginCollection(cfg, slogger, 'plugins')
            await cfg.mainq.put(
                LogEvent(
                    etype="finish_event",
                    level=20,
                    log=f"[{tag}] Stunnel tests completed"
                )
            )
        except Exception as err:  # pylint: disable=broad-except
            await cfg.mainq.put(
                LogEvent(
                    etype="finish_event",
                    level=50,
                    log=f"[{tag}] Something went wrong: {err}"
                )
            )
            print(err)
            omitted = True

        finally:
            evt = await cfg.logsq.get()
            log_error = 0 if evt.etype == "finish_event" else 1
            succeeded, failed, skipped = task.result()
            slogger.info("Stunnel tests skipped" if omitted else
                 f"\nSummary:\n   success: {succeeded}\n   fail: {failed}\n   skipped: {skipped}\n"
                 + f"\nFile {cfg.results} " "done" if not log_error else
                 "failed (Expected 'finish_event')")
            if omitted:
                sys.exit(EXIT_SKIP)
            sys.exit(EXIT_SUCCESS if not failed else EXIT_FAILURE)


if __name__ == "__main__":
    asyncio.run(main())
