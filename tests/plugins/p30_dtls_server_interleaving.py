"""stunnel DTLS server mode interleaving test
   Two openssl DTLS clients --> stunnel DTLS server --> UDP echo server
   Packets from two clients are interleaved: A1, B1, A2, B2.
   Each client verifies its own echoed data, confirming stunnel
   correctly demultiplexes concurrent DTLS connections."""

import asyncio
import logging
import shlex
import socket
import subprocess
import threading
from plugin_collection import Plugin, ERR_CONN_RESET
from maketest import (
    Config, StunnelAcceptConnect, LogEvent, ResultEvent, openssl_dtls_args
)


class DTLSStunnelServerInterleavingTest(StunnelAcceptConnect):
    """Test stunnel DTLS server handling two interleaved clients."""

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.ssl_server = False
        self.params.description = '301. Test DTLS server with interleaved clients'
        self.params.services = ['dtls-server']
        self.events.failure = [
            "peer did not return a certificate",
            "bad certificate", "certificate verify failed",
            "unsupported protocol", ERR_CONN_RESET,
            "Connection lost", "Something went wrong",
            "timed out", "INTERNAL ERROR"
        ]
        self._udp_echo_socket = None
        self._udp_echo_thread = None
        self._udp_echo_stop = threading.Event()
        self._udp_echo_packets = []

    async def _log(self, tag, message, level=20):
        """Write a diagnostic message through the test event queue."""
        await self.cfg.mainq.put(
            LogEvent(etype="log", level=level, log=f"[{tag}] {message}"))

    async def prepare_server_cfgfile(self, cfg, port, service):
        contents = f"""
    foreground = yes
    debug = debug
    syslog = no
    [{service}]
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{port}
    transport = udp
    cert = {cfg.certdir}/server_cert.pem
    key = {cfg.certdir}/server_cert.pem
    """
        cfgfile = cfg.tempd / "stunnel_dtls_interleaving_server.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile

    async def accepting_connections(self, port, service):
        """Override: consume second stunnel_event."""
        await self.check_listening_port(port, service)
        try:
            while True:
                evt = await asyncio.wait_for(self.cfg.logsq.get(), timeout=0.5)
                if evt.etype == "stunnel_event":
                    break
        except asyncio.TimeoutError:
            pass

    async def test_stunnel(self, cfg):
        tag = "test_stunnel_dtls_server_interleaving"
        task = asyncio.create_task(self.set_result())
        try:
            self.logger.info(self.params.description)
            await cfg.mainq.put(LogEvent(etype="log", level=30, log=""))
            await self._log(
                tag, f"***** Start '{self.params.description}' *****", level=30)
            await self._log(
                tag,
                "Topology: openssl clients A/B -> stunnel DTLS server"
                " -> shared UDP echo backend; send order A1, B1, A2, B2")

            udp_port = self._start_udp_echo()
            await self._log(
                "udp-echo", f"Listening on 127.0.0.1:{udp_port}")

            cfgfile = await self.prepare_server_cfgfile(
                cfg, udp_port, 'dtls-server')
            stunnel_port = await self.start_stunnel(cfgfile, 'dtls-server')
            await self._log(
                tag,
                f"stunnel forwards DTLS 127.0.0.1:{stunnel_port}"
                f" to UDP 127.0.0.1:{udp_port}")

            await self._run_interleaved_clients(stunnel_port)
        except Exception as err:  # pylint: disable=broad-except
            await cfg.mainq.put(LogEvent(
                etype="fatal_event",
                level=50,
                log=f"[{tag}] Something went wrong:"
                    f" {type(err).__name__}: {err}"))
        finally:
            if self._udp_echo_socket is not None:
                thread_stopped = await self._stop_udp_echo()
                await self._log(
                    "udp-echo",
                    f"Stopped (thread joined: {thread_stopped}) after echoing"
                    f" {len(self._udp_echo_packets)} datagram(s):"
                    f" {self._udp_echo_packets!r}")
            await self.cleanup_stunnels()
            await self.cleanup_tasks()
            await self.expect_event(self.cfg.logsq, "result_event")
            result = task.result()
            await self.cfg.mainq.put(
                ResultEvent(etype="set_result_event", level=20,
                            log=f"[{tag}] Test {result}", result=result))
            await self.expect_event(self.cfg.logsq, "set_result_event")

    def _start_udp_echo(self):
        """Start a UDP echo server and retain its packet trace."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('127.0.0.1', 0))
        sock.settimeout(0.2)
        self._udp_echo_socket = sock
        self._udp_echo_stop.clear()
        self._udp_echo_packets.clear()
        port = sock.getsockname()[1]

        def echo():
            while not self._udp_echo_stop.is_set():
                try:
                    data, addr = sock.recvfrom(4096)
                    if data:
                        sock.sendto(data, addr)
                        self._udp_echo_packets.append(
                            (f"{addr[0]}:{addr[1]}", data))
                except socket.timeout:
                    continue
                except OSError:
                    break

        self._udp_echo_thread = threading.Thread(target=echo, daemon=True)
        self._udp_echo_thread.start()
        return port

    async def _stop_udp_echo(self):
        """Stop the UDP echo backend and join its thread."""
        self._udp_echo_stop.set()
        self._udp_echo_socket.close()
        self._udp_echo_socket = None
        thread = self._udp_echo_thread
        await asyncio.get_running_loop().run_in_executor(
            None, thread.join, 1.0)
        self._udp_echo_thread = None
        return not thread.is_alive()

    async def _log_openssl_stderr(self, stream, client):
        """Record diagnostic output from an OpenSSL helper."""
        async for data in stream:
            line = data.decode("UTF-8", errors="replace").rstrip("\r\n")
            await self._log(client, f"stderr: {line}")

    async def _run_interleaved_clients(self, port):
        """Send A1, B1, A2, B2 before validating each client's echoes."""
        endpoint = f"127.0.0.1:{port}"
        dtls_args = await openssl_dtls_args(self.cfg)

        async def launch_client(name):
            tag = f"openssl-dtls-client-{name}"
            command = ["openssl", "s_client"]
            command.extend(dtls_args)
            command.extend(["-connect", endpoint, "-quiet"])
            cmd_str = " ".join(shlex.quote(word) for word in command)
            await self._log(tag, f"Launching `{cmd_str}`")
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            stderr_task = asyncio.create_task(
                self._log_openssl_stderr(proc.stderr, tag))
            await self._log(
                tag, f"Started process {proc.pid} for {endpoint}")
            return proc, stderr_task

        async def send(proc, name, sequence, data):
            """Send and identify one interleaved application payload."""
            tag = f"openssl-dtls-client-{name}"
            await self._log(
                tag,
                f"Sending payload {name}{sequence} ({len(data)} bytes)"
                f" to {endpoint}: {data!r}")
            proc.stdin.write(data)
            await proc.stdin.drain()
            await self._log(tag, f"Payload {name}{sequence} sent")

        async def recv(proc, name, sequence, data, timeout=20):
            """Read and identify one echoed application payload."""
            tag = f"openssl-dtls-client-{name}"
            expected = data.strip()
            await self._log(
                tag,
                f"Waiting up to {timeout} seconds for payload"
                f" {name}{sequence}; expected {expected!r}")
            try:
                response = await asyncio.wait_for(
                    proc.stdout.readline(), timeout=timeout)
            except asyncio.TimeoutError as err:
                raise RuntimeError(
                    f"[{name}] timed out after {timeout} seconds waiting"
                    f" for payload {name}{sequence} from {endpoint};"
                    f" expected {expected!r}") from err
            await self._log(
                tag,
                f"Received payload {name}{sequence} ({len(response)} bytes)"
                f" from {endpoint}: {response!r}")
            if expected not in response:
                raise RuntimeError(
                    f"[{name}] payload {name}{sequence} mismatch"
                    f" from {endpoint}: expected {expected!r},"
                    f" got {response[:200]!r}")
            await self._log(
                tag, f"Verified payload {name}{sequence}: {expected!r}")

        clients = {}
        data = {
            "A": [b"DATA_A_PACKET_1\n", b"DATA_A_PACKET_2\n"],
            "B": [b"DATA_B_PACKET_1\n", b"DATA_B_PACKET_2\n"]
        }
        try:
            clients["A"] = await launch_client("A")
            clients["B"] = await launch_client("B")
            await send(clients["A"][0], "A", 1, data["A"][0])
            await send(clients["B"][0], "B", 1, data["B"][0])
            await send(clients["A"][0], "A", 2, data["A"][1])
            await send(clients["B"][0], "B", 2, data["B"][1])
            await self._log(
                "dtls-interleaving",
                "Queued all payloads in order A1, B1, A2, B2;"
                " now reading echoes")
            await recv(clients["A"][0], "A", 1, data["A"][0])
            await recv(clients["B"][0], "B", 1, data["B"][0])
            await recv(clients["A"][0], "A", 2, data["A"][1])
            await recv(clients["B"][0], "B", 2, data["B"][1])
            await self._log(
                "dtls-interleaving",
                "Verified A received only A1/A2 and B received only B1/B2")
        finally:
            for name, (proc, stderr_task) in clients.items():
                tag = f"openssl-dtls-client-{name}"
                if proc.returncode is None:
                    await self._log(
                        tag, f"Stopping process {proc.pid}")
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                returncode = await proc.wait()
                await stderr_task
                await self._log(
                    tag,
                    f"Process {proc.pid} exited with status {returncode}")


class StunnelDTLSServerInterleavingTestPlugin(Plugin):
    """DTLS server mode with interleaved clients."""

    def __init__(self):
        super().__init__()
        self.description = 'DTLS server mode with interleaved clients'

    async def perform_operation(self, cfg, logger):
        await DTLSStunnelServerInterleavingTest(cfg, logger).test_stunnel(cfg)
