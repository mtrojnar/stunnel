"""stunnel DTLS client mode test
   UDP client --> stunnel DTLS client --> openssl DTLS server"""

import asyncio
import logging
import os
import pathlib
import socket
import subprocess
from plugin_collection import Plugin, ERR_CONN_RESET
from maketest import Config, StunnelAcceptConnect, LogEvent, ResultEvent


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
            dtls_port = await self._start_dtls_echo(cfg)
            cfgfile, _ = await self.prepare_client_cfgfile(
                cfg, [dtls_port], 'dtls-client')
            stunnel_port = await self.start_stunnel(cfgfile, 'dtls-client')
            await self._run_udp_client(stunnel_port)
        except Exception as err:
            await cfg.mainq.put(LogEvent(etype="fatal_event", level=50,
                log=f"[{tag}] {type(err).__name__}: {err}"))
        finally:
            if self._dtls_proc is not None:
                try:
                    self._dtls_proc.kill()
                    await self._dtls_proc.wait()
                except ProcessLookupError:
                    pass
            # Clean up the echo relay task if still running
            if hasattr(self, '_echo_tasks'):
                for t in self._echo_tasks:
                    t.cancel()
                    try:
                        await t
                    except (asyncio.CancelledError, ProcessLookupError):
                        pass
                self._echo_tasks.clear()
            await self.cleanup_stunnels()
            await self.cleanup_tasks()
            await self.expect_event(self.cfg.logsq, "result_event")
            result = task.result()
            await self.cfg.mainq.put(
                ResultEvent(etype="set_result_event", level=20,
                            log=f"[{tag}] Test {result}", result=result))
            await self.expect_event(self.cfg.logsq, "set_result_event")

    async def _start_dtls_echo(self, cfg):
        """Start an openssl DTLS server as an echo backend.
        Returns the listening port."""
        # Bind a UDP socket to find a free port, then close it
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        s.close()

        proc = await asyncio.create_subprocess_exec(
            "openssl", "s_server", "-dtls1_2",
            "-accept", f"127.0.0.1:{port}",
            "-cert", str(cfg.certdir / "server_cert.pem"),
            "-key", str(cfg.certdir / "server_cert.pem"),
            "-quiet",
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        self._dtls_proc = proc

        # Relay stdout back to stdin (echo).  Keep running until cancelled.
        async def echo_relay():
            try:
                while True:
                    try:
                        data = await asyncio.wait_for(
                            proc.stdout.read(4096), timeout=1.0)
                    except asyncio.TimeoutError:
                        continue
                    if not data:
                        break
                    proc.stdin.write(data)
                    await proc.stdin.drain()
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
        self._echo_tasks = [asyncio.ensure_future(echo_relay())]
        return port

    async def _run_udp_client(self, stunnel_port):
        """Send test data through stunnel's UDP accept port,
        receive the echo, and verify it.
        Uses non-blocking asyncio socket methods to avoid
        stalling the event loop."""
        loop = asyncio.get_running_loop()
        test_data = b"HELLO_DTLS_CLIENT_TEST"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            sock.connect(('127.0.0.1', stunnel_port))
            await asyncio.wait_for(
                loop.sock_sendall(sock, test_data), timeout=10)
            response = await asyncio.wait_for(
                loop.sock_recv(sock, 4096), timeout=10)
        except asyncio.TimeoutError:
            raise RuntimeError(
                "UDP echo timed out waiting for response")
        finally:
            sock.close()
        if test_data not in response:
            raise RuntimeError(
                f"Expected {test_data!r}, got {response[:200]!r}")


class StunnelDTLSClientTestPlugin(Plugin):
    def __init__(self):
        super().__init__()
        self.description = 'DTLS client mode'

    async def perform_operation(self, cfg, logger):
        await DTLSStunnelClientTest(cfg, logger).test_stunnel(cfg)
