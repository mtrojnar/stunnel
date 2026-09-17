"""Half-closed TCP connection regression tests.

A plaintext peer that sends a request and half-closes its write side
(shutdown(SHUT_WR)) must still receive the response forwarded through
stunnel.  On macOS, poll() is emulated with kqueue and reports POLLHUP
as soon as the peer half-closes the connection; transfer_tcp() used to
misinterpret that as a closed write direction and dropped the remaining
data (see s_poll_hup() in src/network.c).
"""

import asyncio
import logging
import socket

from plugin_collection import Plugin
from maketest import (
    Config,
    LogEvent,
    ResultEvent,
    StunnelAcceptConnect,
)

REQ_TEXT = b"half-close request from the plaintext peer\n"
RESP_TEXT = b"half-close response from the former TLS peer\n"
REQUEST = REQ_TEXT*4096  # far larger than one stunnel buffer
RESPONSE = RESP_TEXT*4096  # far larger than one stunnel buffer
IO_TIMEOUT = 15
CASE_TIMEOUT = 60


def payload_text(data):
    """Return a compact, safe representation of public test data."""
    if len(data) <= 80:
        return repr(data)
    return f"{len(data)} bytes starting with {data[:32]!r}"


async def wait_for(awaitable, timeout, phase):
    """Wait for an operation and identify it in timeout diagnostics."""
    try:
        return await asyncio.wait_for(awaitable, timeout=timeout)
    except asyncio.TimeoutError as err:
        raise RuntimeError(
            f"timed out after {timeout} seconds during {phase}") from err


async def recv_exact(sock, size, phase, timeout=IO_TIMEOUT):
    """Read exactly *size* bytes from a non-blocking socket."""
    loop = asyncio.get_running_loop()
    deadline = loop.time()+timeout
    data = bytearray()
    while len(data) < size:
        remaining = deadline-loop.time()
        if remaining <= 0:
            raise RuntimeError(
                f"timed out after {timeout} seconds during {phase}; "
                f"received {len(data)} of {size} bytes")
        try:
            chunk = await asyncio.wait_for(
                loop.sock_recv(sock, size-len(data)), timeout=remaining)
        except asyncio.TimeoutError as err:
            raise RuntimeError(
                f"timed out after {timeout} seconds during {phase}; "
                f"received {len(data)} of {size} bytes") from err
        if not chunk:
            raise RuntimeError(
                f"unexpected EOF during {phase}; received {len(data)} "
                f"of {size} bytes")
        data.extend(chunk)
    return bytes(data)


async def recv_eof(sock, phase, timeout=IO_TIMEOUT):
    """Read from a socket until EOF and return any trailing bytes."""
    trailing = bytearray()
    loop = asyncio.get_running_loop()
    deadline = loop.time()+timeout
    while True:
        remaining = deadline-loop.time()
        if remaining <= 0:
            raise RuntimeError(
                f"timed out after {timeout} seconds during {phase}; "
                f"received {len(trailing)} trailing byte(s)")
        try:
            chunk = await asyncio.wait_for(
                loop.sock_recv(sock, 65536), timeout=remaining)
        except asyncio.TimeoutError as err:
            raise RuntimeError(
                f"timed out after {timeout} seconds during {phase}; "
                f"received {len(trailing)} trailing byte(s)") from err
        if not chunk:
            return bytes(trailing)
        trailing.extend(chunk)


async def send_all(sock, data, phase, timeout=IO_TIMEOUT):
    """Send data on a non-blocking socket with a finite timeout."""
    loop = asyncio.get_running_loop()
    await wait_for(loop.sock_sendall(sock, data), timeout, phase)


async def recv_once(sock, size, phase, timeout=IO_TIMEOUT):
    """Receive once from a non-blocking socket with a finite timeout."""
    loop = asyncio.get_running_loop()
    return await wait_for(loop.sock_recv(sock, size), timeout, phase)


def assert_payload(phase, endpoint, expected, actual):
    """Raise a payload mismatch with enough context for the result log."""
    if actual != expected:
        raise RuntimeError(
            f"{phase} payload mismatch at {endpoint}: expected "
            f"{payload_text(expected)}, got {payload_text(actual)}")


class BackendHelper:
    """One-shot asynchronous TCP endpoint with diagnostic logging."""

    def __init__(self, owner, tag, listener, handler):
        self.owner = owner
        self.tag = tag
        self.listener = listener
        self.handler = handler
        self.conn = None
        self.port = listener.getsockname()[1]
        self.task = asyncio.create_task(self._run())

    @classmethod
    async def start(cls, owner, tag, handler):
        """Bind an ephemeral loopback port and start accepting one client."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.setblocking(False)
        listener.bind(("127.0.0.1", 0))
        listener.listen(5)
        helper = cls(owner, tag, listener, handler)
        await owner._log(tag, f"Backend listening on TCP 127.0.0.1:{helper.port}")
        return helper

    async def _run(self):
        loop = asyncio.get_running_loop()
        endpoint = f"127.0.0.1:{self.port}"
        try:
            self.conn, peer = await wait_for(
                loop.sock_accept(self.listener), IO_TIMEOUT,
                f"{self.tag} backend accepting at {endpoint}")
            self.conn.setblocking(False)
            self.listener.close()
            self.listener = None
            peer_endpoint = f"{peer[0]}:{peer[1]}"
            await self.owner._log(self.tag, f"Backend accepted {peer_endpoint}")
            await self.handler(self.conn, peer_endpoint)
            await self.owner._log(self.tag, "Backend completed the connection")
        except asyncio.CancelledError:
            await self.owner._log(self.tag, "Backend task cancelled", level=10)
            raise
        except Exception as err:  # pylint: disable=broad-except
            await self.owner._log(
                self.tag,
                f"Backend failed: {type(err).__name__}: {err}", level=40)
            raise
        finally:
            if self.conn is not None:
                self.conn.close()
                self.conn = None
                await self.owner._log(
                    self.tag, "Backend closed the connection", level=10)

    async def wait(self):
        """Wait for the endpoint and propagate its exception."""
        await wait_for(
            asyncio.shield(self.task), IO_TIMEOUT,
            f"{self.tag} backend completion")

    async def stop(self):
        """Close sockets and cancel an unfinished endpoint task."""
        if self.listener is not None:
            self.listener.close()
            self.listener = None
        if not self.task.done():
            self.task.cancel()
        result = await asyncio.gather(self.task, return_exceptions=True)
        error = result[0]
        if isinstance(error, Exception) and not isinstance(
                error, asyncio.CancelledError):
            await self.owner._log(
                self.tag,
                f"Backend cleanup retained {type(error).__name__}: {error}",
                level=30)
        await self.owner._log(self.tag, "Backend stopped", level=10)


class HalfCloseTest(StunnelAcceptConnect):
    """Data transfer across half-closed TCP connections through stunnel."""

    def __init__(self, cfg, logger):
        super().__init__(cfg, logger)
        self.params.description = "331. Half-closed connection data transfer"
        self.events.count = 2
        self.events.success = [r"\[half-close.*\] Case .* passed"]
        self.events.failure = [r"\[half-close\] Something went wrong"]
        self.cert = cfg.certdir / "server_cert.pem"
        self.counter = 0

    async def _log(self, tag, message, level=20, etype="log"):
        """Write a diagnostic message through the harness event queue."""
        await self.cfg.mainq.put(LogEvent(
            etype=etype, level=level, log=f"[{tag}] {message}"))

    def _identity(self, name):
        """Return unique harness service names."""
        self.counter += 1
        return f"hc-{self.counter}a-{name}", f"hc-{self.counter}b-{name}"

    async def _connect(self, tag, port):
        """Open one non-blocking TCP connection with endpoint diagnostics."""
        endpoint = f"127.0.0.1:{port}"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        await self._log(
            tag, f"Connecting to {endpoint} with a {IO_TIMEOUT}-second timeout")
        try:
            await wait_for(
                asyncio.get_running_loop().sock_connect(
                    sock, ("127.0.0.1", port)),
                IO_TIMEOUT, f"{tag} connecting to {endpoint}")
        except Exception:
            sock.close()
            raise
        local = sock.getsockname()
        await self._log(
            tag, f"Connected {local[0]}:{local[1]} to {endpoint}")
        return sock

    async def _start_stunnel(self, cfgfile, service):
        """Start stunnel with a configuration prepared by the test suite."""
        port = await wait_for(
            super().start_stunnel(cfgfile, service), 15,
            f"starting stunnel service {service}")
        await self._log(
            service, f"Observed listener at 127.0.0.1:{port}")
        return int(port)

    async def _run_case(self, name, client_flow, backend_flow):
        """Run and time-bound one named scenario over the chained topology."""
        tag = f"half-close/{name}"
        service_client, service_server = self._identity(name)
        await self._log(tag, f"***** Start '{name}' *****", level=30)
        await self._log(tag,
            "Topology: plaintext actor <-> stunnel (client mode) <-> TLS"
            " <-> stunnel (server mode) <-> plaintext backend actor")
        helper = await BackendHelper.start(self, tag, backend_flow)
        net = None
        try:
            server_conf = self.cfg.tempd / "stunnel_hc_server.conf"
            server_conf.write_text(f"""
foreground = yes
debug = debug
syslog = no

[{service_server}]
accept = 127.0.0.1:0
connect = 127.0.0.1:{helper.port}
cert = {self.cert}
key = {self.cert}
TIMEOUTclose = 3
TIMEOUTidle = 10
""", encoding="UTF-8")
            server_port = await self._start_stunnel(server_conf, service_server)
            client_conf = self.cfg.tempd / "stunnel_hc_client.conf"
            client_conf.write_text(f"""
foreground = yes
debug = debug
syslog = no

[{service_client}]
client = yes
accept = 127.0.0.1:0
connect = 127.0.0.1:{server_port}
verifyChain = no
TIMEOUTclose = 3
TIMEOUTidle = 10
""", encoding="UTF-8")
            client_port = await self._start_stunnel(client_conf, service_client)
            net = await self._connect(tag, client_port)
            await client_flow(self, tag, net)
            await helper.wait()
            await self._log(tag, f"Case {name} passed", etype="output_event")
        finally:
            if net is not None:
                net.close()
            await helper.stop()
            await self.cleanup_stunnels()

    async def case_response_after_half_close(self):
        """Send a request, half-close, then read the full response and EOF."""
        tag = "half-close/client-half-close"

        async def client_flow(test, tag, net):
            await test._log(tag,
                f"Plain actor queues greeting: {payload_text(REQUEST)}")
            await send_all(net, REQUEST, f"{tag} queueing greeting")
            net.shutdown(socket.SHUT_WR)
            await test._log(tag,
                "Plain actor half-closed; waiting for response and EOF")
            actual = await recv_exact(net, len(RESPONSE),
                f"{tag} raw response")
            assert_payload("response transfer", "plaintext actor",
                RESPONSE, actual)
            trailing = await recv_eof(net, f"{tag} plaintext EOF")
            assert_payload("plaintext EOF", "plaintext actor", b"", trailing)
            await test._log(tag,
                f"Plain actor received {len(RESPONSE)} bytes and EOF")

        async def backend_flow(net, endpoint):
            await self._log(tag, "Backend waits for the full request and EOF")
            actual = await recv_exact(net, len(REQUEST),
                f"{tag} encrypted greeting")
            assert_payload("request transfer", "backend", REQUEST, actual)
            trailing = await recv_eof(net, f"{tag} request EOF")
            assert_payload("request EOF", "backend", b"", trailing)
            await self._log(tag, f"Backend observed request EOF; sending the "
                f"{len(RESPONSE)}-byte response")
            await send_all(net, RESPONSE, f"{tag} raw response")
            net.shutdown(socket.SHUT_WR)

        await self._run_case("client-half-close", client_flow, backend_flow)

    async def case_request_after_backend_half_close(self):
        """Serve a large request to a backend that half-closes on accept."""
        tag = "half-close/backend-early-half-close"

        async def client_flow(test, tag, net):
            await test._log(tag,
                f"Plain actor queues greeting: {payload_text(REQUEST)}")
            await send_all(net, REQUEST, f"{tag} queueing greeting")
            net.shutdown(socket.SHUT_WR)
            await test._log(tag, "Plain actor half-closed; waiting for EOF")
            trailing = await recv_eof(net, f"{tag} plaintext EOF")
            assert_payload("plaintext EOF", "plaintext actor", b"", trailing)
            await test._log(tag, "Plain actor observed EOF")

        async def backend_flow(net, endpoint):
            # Half-close immediately: the backend stops sending but keeps
            # reading, which is a fully valid TCP endpoint state.
            await self._log(tag, "Backend half-closes its write side upon "
                f"accept and waits for the {len(REQUEST)}-byte request")
            net.shutdown(socket.SHUT_WR)
            actual = await recv_exact(net, len(REQUEST),
                f"{tag} request after the backend half-close")
            assert_payload("request transfer", "backend", REQUEST, actual)
            trailing = await recv_eof(net, f"{tag} request EOF")
            assert_payload("request EOF", "backend", b"", trailing)
            await self._log(tag,
                "Backend received the full request after its early half-close")

        await self._run_case("backend-early-half-close", client_flow,
            backend_flow)

    async def test_stunnel(self):
        """Run all cases and publish one standard test-suite result."""
        tag = "half-close"
        task = asyncio.create_task(self.set_result())
        try:
            self.logger.info(self.params.description)
            await self.cfg.mainq.put(LogEvent(etype="log", level=30, log=""))
            await self._log(tag,
                f"***** Start '{self.params.description}' *****", level=30)
            await self.case_response_after_half_close()
            await self.case_request_after_backend_half_close()
        except asyncio.CancelledError:
            await self.cfg.mainq.put(LogEvent(
                etype="fatal_event", level=50,
                log=f"[{tag}] Something went wrong: test task was cancelled"))
        except Exception as err:  # pylint: disable=broad-except
            await self.cfg.mainq.put(LogEvent(
                etype="fatal_event", level=50,
                log=f"[{tag}] Something went wrong: "
                    f"{type(err).__name__}: {err}"))
        finally:
            await self.cleanup_stunnels()
            await self.cleanup_tasks()
            await self.expect_event(self.cfg.logsq, "result_event")
            result = task.result()
            await self.cfg.mainq.put(ResultEvent(
                etype="set_result_event", level=20,
                log=f"[{tag}] Test {result}", result=result))
            await self.expect_event(self.cfg.logsq, "set_result_event")


class HalfCloseTestPlugin(Plugin):
    """Half-closed connection regression plugin."""

    def __init__(self):
        super().__init__()
        self.description = "Half-closed connection data transfer"

    async def perform_operation(self, cfg: Config, logger: logging.Logger):
        """Run the half-close tests."""
        await HalfCloseTest(cfg, logger).test_stunnel()
