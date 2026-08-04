"""stunnel DTLS client mode test
   UDP client --> stunnel DTLS client --> openssl DTLS server"""

import asyncio
import logging
import os
import shlex
import socket
import subprocess
from plugin_collection import Plugin, ERR_CONN_RESET
from maketest import (
    Config, StunnelAcceptConnect, LogEvent, ResultEvent, openssl_dtls_args
)


class DTLSStunnelClientTest(StunnelAcceptConnect):
    """Test stunnel operating as a DTLS client."""

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.ssl_server = False
        self.params.description = '291. Test DTLS client mode'
        self.params.services = ['dtls-client']
        self.events.failure = [
            "peer did not return a certificate",
            "bad certificate", "certificate verify failed",
            "unsupported protocol", ERR_CONN_RESET,
            "Connection lost", "Something went wrong",
            "timed out", "INTERNAL ERROR"
        ]
        self._dtls_proc = None
        self._echo_tasks = []
        self._stderr_task = None

    async def _log(self, tag, message, level=20):
        """Write a diagnostic message through the test event queue."""
        await self.cfg.mainq.put(
            LogEvent(etype="log", level=level, log=f"[{tag}] {message}"))

    async def prepare_client_cfgfile(self, cfg, ports, service):
        dtls_port = ports[0]
        contents = f"""
    foreground = yes
    debug = debug
    syslog = no
    [{service}]
    client = yes
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{dtls_port}
    transport = udp
    """
        cfgfile = cfg.tempd / "stunnel_dtls_client.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile, os.devnull

    async def accepting_connections(self, port, service):
        """Override: consume any second stunnel_event from start_stunnel."""
        await self.check_listening_port(port, service)
        try:
            while True:
                evt = await asyncio.wait_for(self.cfg.logsq.get(), timeout=0.5)
                if evt.etype == "stunnel_event":
                    break
        except asyncio.TimeoutError:
            pass

    async def test_stunnel(self, cfg):
        tag = "test_stunnel_dtls_client"
        task = asyncio.create_task(self.set_result())
        try:
            self.logger.info(self.params.description)
            await cfg.mainq.put(LogEvent(etype="log", level=30, log=""))
            await self._log(
                tag, f"***** Start '{self.params.description}' *****", level=30)
            await self._log(
                tag,
                "Topology: UDP test client -> stunnel DTLS client"
                " -> openssl s_server echo backend")

            dtls_port = await self._start_dtls_echo(cfg)
            cfgfile, _ = await self.prepare_client_cfgfile(
                cfg, [dtls_port], 'dtls-client')
            stunnel_port = int(
                await self.start_stunnel(cfgfile, 'dtls-client'))
            await self._log(
                tag,
                f"stunnel forwards UDP 127.0.0.1:{stunnel_port}"
                f" to DTLS 127.0.0.1:{dtls_port}")

            await self._run_udp_client(stunnel_port)
        except Exception as err:  # pylint: disable=broad-except
            await cfg.mainq.put(LogEvent(
                etype="fatal_event",
                level=50,
                log=f"[{tag}] Something went wrong:"
                    f" {type(err).__name__}: {err}"))
        finally:
            await self._stop_dtls_echo()
            await self.cleanup_stunnels()
            await self.cleanup_tasks()
            await self.expect_event(self.cfg.logsq, "result_event")
            result = task.result()
            await self.cfg.mainq.put(
                ResultEvent(etype="set_result_event", level=20,
                            log=f"[{tag}] Test {result}", result=result))
            await self.expect_event(self.cfg.logsq, "set_result_event")

    async def _log_openssl_stderr(self, stream):
        """Record diagnostic output from the OpenSSL DTLS server."""
        async for data in stream:
            line = data.decode("UTF-8", errors="replace").rstrip("\r\n")
            await self._log("openssl-dtls-server", f"stderr: {line}")

    async def _wait_dtls_server_ready(self, proc, endpoint):
        """Allow s_server to bind before sending the first UDP datagram."""
        await asyncio.sleep(0.2)
        if proc.returncode is not None:
            stderr = await proc.stderr.read()
            detail = stderr.decode("UTF-8", errors="replace").strip()
            raise RuntimeError(
                f"OpenSSL DTLS server at {endpoint} exited with status"
                f" {proc.returncode} before becoming ready: {detail}")
        await self._log("openssl-dtls-server", f"Ready on {endpoint}")

    async def _start_dtls_echo(self, cfg):
        """Start an OpenSSL DTLS server and relay plaintext back to it."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
        sock.close()
        endpoint = f"127.0.0.1:{port}"
        command = ["openssl", "s_server"]
        command.extend(await openssl_dtls_args(self.cfg))
        command.extend([
            "-accept", endpoint,
            "-cert", str(cfg.certdir / "server_cert.pem"),
            "-key", str(cfg.certdir / "server_cert.pem"),
            "-quiet"
        ])
        cmd_str = " ".join(shlex.quote(word) for word in command)
        await self._log(
            "openssl-dtls-server", f"Launching `{cmd_str}`")
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        self._dtls_proc = proc
        await self._log(
            "openssl-dtls-server",
            f"Started process {proc.pid} for {endpoint}")
        await self._wait_dtls_server_ready(proc, endpoint)
        self._stderr_task = asyncio.create_task(
            self._log_openssl_stderr(proc.stderr))

        async def echo_relay():
            """Relay decrypted server output to its input as an echo."""
            tag = "openssl-dtls-server"
            try:
                while True:
                    data = await proc.stdout.read(4096)
                    if not data:
                        await self._log(
                            tag, "Plaintext stdout reached EOF", level=10)
                        break
                    await self._log(
                        tag,
                        f"Received plaintext ({len(data)} bytes)"
                        f" from stunnel: {data!r}")
                    proc.stdin.write(data)
                    await proc.stdin.drain()
                    await self._log(
                        tag,
                        f"Echoed plaintext ({len(data)} bytes)"
                        f" to stunnel: {data!r}")
            except asyncio.CancelledError:
                return
            except Exception as err:  # pylint: disable=broad-except
                await self.cfg.mainq.put(LogEvent(
                    etype="fatal_event",
                    level=50,
                    log=f"[{tag}] Something went wrong in echo relay:"
                        f" {type(err).__name__}: {err}"))

        self._echo_tasks = [asyncio.create_task(echo_relay())]
        return port

    async def _stop_dtls_echo(self):
        """Stop and report the OpenSSL echo helper."""
        for task in self._echo_tasks:
            task.cancel()
        if self._echo_tasks:
            await asyncio.gather(*self._echo_tasks, return_exceptions=True)
            self._echo_tasks.clear()

        proc = self._dtls_proc
        if proc is None:
            return
        if proc.returncode is None:
            await self._log(
                "openssl-dtls-server", f"Stopping process {proc.pid}")
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        returncode = await proc.wait()
        if self._stderr_task is not None:
            await self._stderr_task
            self._stderr_task = None
        await self._log(
            "openssl-dtls-server",
            f"Process {proc.pid} exited with status {returncode}")
        self._dtls_proc = None

    async def _run_udp_client(self, stunnel_port):
        """Send a UDP payload through stunnel and verify the echoed data."""
        tag = "udp-test-client"
        loop = asyncio.get_running_loop()
        endpoint = f"127.0.0.1:{stunnel_port}"
        test_data = b"HELLO_DTLS_CLIENT_TEST"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            sock.connect(('127.0.0.1', stunnel_port))
            local_addr, local_port = sock.getsockname()[:2]
            local_endpoint = f"{local_addr}:{local_port}"
            await self._log(
                tag, f"Connected UDP {local_endpoint} to {endpoint}")
            await self._log(
                tag,
                f"Sending payload #1 ({len(test_data)} bytes)"
                f" to {endpoint}: {test_data!r}")
            try:
                await asyncio.wait_for(
                    loop.sock_sendall(sock, test_data), timeout=10)
            except asyncio.TimeoutError as err:
                raise RuntimeError(
                    f"timed out after 10 seconds sending payload #1"
                    f" from {local_endpoint} to {endpoint}:"
                    f" {test_data!r}") from err
            await self._log(
                tag, "Payload #1 sent; waiting up to 10 seconds for its echo")
            try:
                response = await asyncio.wait_for(
                    loop.sock_recv(sock, 4096), timeout=10)
            except asyncio.TimeoutError as err:
                raise RuntimeError(
                    f"timed out after 10 seconds waiting for payload #1"
                    f" at {local_endpoint} from {endpoint};"
                    f" expected {test_data!r}") from err
            await self._log(
                tag,
                f"Received payload #1 ({len(response)} bytes)"
                f" from {endpoint}: {response!r}")
        finally:
            sock.close()
            await self._log(tag, "Closed UDP test socket", level=10)

        if test_data not in response:
            raise RuntimeError(
                f"payload #1 mismatch from {endpoint}:"
                f" expected {test_data!r}, got {response[:200]!r}")
        await self._log(
            tag,
            f"Verified payload #1 echo from {endpoint}: {test_data!r}")


class StunnelDTLSClientTestPlugin(Plugin):
    def __init__(self):
        super().__init__()
        self.description = 'DTLS client mode'

    async def perform_operation(self, cfg, logger):
        await DTLSStunnelClientTest(cfg, logger).test_stunnel(cfg)
