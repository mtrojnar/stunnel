"""stunnel DTLS server mode interleaving test
   Two openssl DTLS clients --> stunnel DTLS server --> UDP echo server
   Packets from two clients are interleaved: A1, B1, A2, B2.
   Each client verifies its own echoed data, confirming stunnel
   correctly demultiplexes concurrent DTLS connections."""

import asyncio
import logging
import os
import pathlib
import socket
import subprocess
import threading
from plugin_collection import Plugin, ERR_CONN_RESET
from maketest import Config, StunnelAcceptConnect, LogEvent, ResultEvent


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
        tag = "test_stunnel_dtls_interleaving"
        task = asyncio.create_task(self.set_result())
        try:
            self.logger.info(self.params.description)
            # Step 1: UDP echo backend
            udp_port = self._start_udp_echo()
            # Step 2: start stunnel DTLS server
            cfgfile = await self.prepare_server_cfgfile(
                cfg, udp_port, 'dtls-server')
            stunnel_port = await self.start_stunnel(cfgfile, 'dtls-server')
            # Step 3: interleaved DTLS client test
            await self._run_interleaved_clients(stunnel_port)
        except Exception as err:
            await cfg.mainq.put(LogEvent(etype="fatal_event", level=50,
                log=f"[{tag}] {type(err).__name__}: {err}"))
        finally:
            await self.cleanup_stunnels()
            await self.cleanup_tasks()
            await self.expect_event(self.cfg.logsq, "result_event")
            result = task.result()
            await self.cfg.mainq.put(
                ResultEvent(etype="set_result_event", level=20,
                            log=f"[{tag}] Test {result}", result=result))
            await self.expect_event(self.cfg.logsq, "set_result_event")

    @staticmethod
    def _start_udp_echo():
        """Start a UDP echo server on a random port.
        Returns the listening port number."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]

        def echo():
            while True:
                try:
                    s.settimeout(1.0)
                    d, a = s.recvfrom(4096)
                    if d:
                        s.sendto(d, a)
                except socket.timeout:
                    continue
                except OSError:
                    break
        threading.Thread(target=echo, daemon=True).start()
        return port

    async def _run_interleaved_clients(self, port):
        """Launch two openssl DTLS clients.  Queue four packets:
        A sends P1, B sends P1, A sends P2, B sends P2.
        Responses are read afterwards to verify interleaved backlog."""
        async def launch_client(name):
            return await asyncio.create_subprocess_exec(
                "openssl", "s_client", "-dtls1_2",
                "-connect", f"127.0.0.1:{port}", "-quiet",
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)

        async def send(proc, data):
            """Send data to openssl DTLS client."""
            proc.stdin.write(data)
            await proc.stdin.drain()

        async def recv(proc, name, data, timeout=20):
            """Read echoed response and verify it."""
            expected = data.strip()
            response = await asyncio.wait_for(
                proc.stdout.readline(), timeout=timeout)
            if expected not in response:
                raise RuntimeError(
                    f"[{name}] Expected {expected!r},"
                    f" got {response[:200]!r}")

        proc_a = None
        proc_b = None
        data_a1 = b"DATA_A_PACKET_1\n"
        data_b1 = b"DATA_B_PACKET_1\n"
        data_a2 = b"DATA_A_PACKET_2\n"
        data_b2 = b"DATA_B_PACKET_2\n"
        try:
            proc_a = await launch_client("A")
            proc_b = await launch_client("B")
            await send(proc_a, data_a1)
            await send(proc_b, data_b1)
            await send(proc_a, data_a2)
            await send(proc_b, data_b2)
            await recv(proc_a, "A", data_a1)
            await recv(proc_b, "B", data_b1)
            await recv(proc_a, "A", data_a2)
            await recv(proc_b, "B", data_b2)
        finally:
            for p in (proc_a, proc_b):
                if p is not None:
                    try:
                        p.kill()
                        await p.wait()
                    except ProcessLookupError:
                        pass


class StunnelDTLSServerInterleavingTestPlugin(Plugin):
    """DTLS server mode with interleaved clients."""

    def __init__(self):
        super().__init__()
        self.description = 'DTLS server mode with interleaved clients'

    async def perform_operation(self, cfg, logger):
        await DTLSStunnelServerInterleavingTest(cfg, logger).test_stunnel(cfg)
