"""stunnel DTLS server mode test
   openssl DTLS client --> stunnel DTLS server --> UDP echo server"""

import asyncio
import logging
import os
import pathlib
import socket
import subprocess
import threading
import time
from plugin_collection import Plugin, ERR_CONN_RESET
from maketest import Config, StunnelAcceptConnect, LogEvent, ResultEvent


class DTLSStunnelServerTest(StunnelAcceptConnect):
    """Test stunnel operating as a DTLS server."""

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.ssl_server = False
        self.params.description = '281. Test DTLS server mode'
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
        cfgfile = cfg.tempd / "stunnel_dtls_server.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile

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
        tag = "test_stunnel_dtls_server"
        task = asyncio.create_task(self.set_result())
        try:
            self.logger.info(self.params.description)
            # Step 1: UDP echo backend
            udp_port = self._start_udp_echo()
            # Step 2: stunnel via framework's start_stunnel
            cfgfile = await self.prepare_server_cfgfile(cfg, udp_port, 'dtls-server')
            stunnel_port = await self.start_stunnel(cfgfile, 'dtls-server')
            # Step 3: DTLS client test
            await self._run_dtls_client(stunnel_port)
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
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]

        def echo():
            while True:
                try:
                    s.settimeout(1.0)
                    d, a = s.recvfrom(4096)
                    if d: s.sendto(d, a)
                except socket.timeout:
                    continue
                except OSError:
                    break
        threading.Thread(target=echo, daemon=True).start()
        return port

    async def _run_dtls_client(self, port):
        """Connect to stunnel's DTLS server via openssl s_client,
        send test data, verify echo, then kill the process.
        Uses non-blocking I/O to avoid hanging on proc.communicate()."""
        test_data = b"HELLO_DTLS_SERVER_TEST\n"
        proc = await asyncio.create_subprocess_exec(
            "openssl", "s_client", "-dtls1_2",
            "-connect", f"127.0.0.1:{port}", "-quiet",
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        try:
            # Send test data and close write side
            proc.stdin.write(test_data)
            await proc.stdin.drain()
            proc.stdin.close()
            await proc.stdin.wait_closed()

            # Read echoed response; openssl s_client -quiet prints
            # received data to stdout.  The DTLS handshake (with
            # cookie exchange) may take several seconds, so allow
            # a generous timeout.
            response = await asyncio.wait_for(
                proc.stdout.readline(), timeout=20)

            if test_data.strip() not in response:
                raise RuntimeError(
                    f"Expected {test_data.strip()!r},"
                    f" got {response[:200]!r}")
        except asyncio.TimeoutError:
            raise RuntimeError(
                "openssl s_client timed out waiting for echo response")
        finally:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass


class StunnelDTLSServerTestPlugin(Plugin):
    def __init__(self):
        super().__init__()
        self.description = 'DTLS server mode'

    async def perform_operation(self, cfg, logger):
        await DTLSStunnelServerTest(cfg, logger).test_stunnel(cfg)
