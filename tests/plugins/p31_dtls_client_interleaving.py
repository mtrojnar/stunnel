"""stunnel DTLS client mode interleaving test
   Two UDP clients --> one stunnel DTLS client listener -->
   stunnel DTLS server --> UDP echo server
   UDP packets from two clients are queued before responses are read:
   A1, B1, A2, B2.  Each client verifies its own echoed data,
   confirming stunnel DTLS client mode handles multiple clients on
   the same UDP accept socket."""

import asyncio
import logging
import socket
import threading
from plugin_collection import Plugin, ERR_CONN_RESET
from maketest import Config, StunnelAcceptConnect, LogEvent, ResultEvent


class DTLSStunnelClientInterleavingTest(StunnelAcceptConnect):
    """Test one stunnel DTLS client listener with two UDP clients."""

    def __init__(self, cfg: Config, logger: logging.Logger):
        super().__init__(cfg, logger)
        self.params.ssl_server = False
        self.params.description = '311. Test DTLS client mode with interleaved clients'
        self.params.services = ['dtls-backend', 'dtls-client']
        self.events.failure = [
            "peer did not return a certificate",
            "bad certificate", "certificate verify failed",
            "unsupported protocol", ERR_CONN_RESET,
            "Connection lost", "Something went wrong",
            "timed out", "INTERNAL ERROR"
        ]
        self._udp_echo_socket = None
        self._udp_echo_stop = threading.Event()

    async def prepare_backend_cfgfile(self, cfg, port, service):
        """Create a DTLS server backend config file."""
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
        cfgfile = cfg.tempd / "stunnel_dtls_client_backend.conf"
        cfgfile.write_text(contents, encoding="UTF-8")
        return cfgfile

    async def prepare_client_cfgfile(self, cfg, port, service):
        """Create a DTLS client config file."""
        contents = f"""
    foreground = yes
    debug = debug
    syslog = no
    [{service}]
    client = yes
    accept = 127.0.0.1:0
    connect = 127.0.0.1:{port}
    transport = udp
    """
        cfgfile = cfg.tempd / "stunnel_dtls_client_interleaving.conf"
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
        tag = "test_stunnel_dtls_client_interleaving"
        task = asyncio.create_task(self.set_result())
        try:
            self.logger.info(self.params.description)
            # Step 1: UDP echo backend for the stunnel DTLS server
            udp_port = self._start_udp_echo()

            # Step 2: stunnel DTLS server backend; OpenSSL s_server handles
            # only one DTLS client reliably, while stunnel can handle several.
            backend_cfg = await self.prepare_backend_cfgfile(
                cfg, udp_port, 'dtls-backend')
            backend_port = await self.start_stunnel(
                backend_cfg, 'dtls-backend')

            # Step 3: one stunnel DTLS client listener under test
            client_cfg = await self.prepare_client_cfgfile(
                cfg, backend_port, 'dtls-client')
            stunnel_port = await self.start_stunnel(
                client_cfg, 'dtls-client')

            # Step 4: two UDP clients share the same stunnel accept socket
            await self._run_interleaved_udp_clients(stunnel_port)
        except Exception as err:
            await cfg.mainq.put(LogEvent(etype="fatal_event", level=50,
                log=f"[{tag}] {type(err).__name__}: {err}"))
        finally:
            if self._udp_echo_socket is not None:
                self._udp_echo_stop.set()
                self._udp_echo_socket.close()
                self._udp_echo_socket = None
            await self.cleanup_stunnels()
            await self.cleanup_tasks()
            await self.expect_event(self.cfg.logsq, "result_event")
            result = task.result()
            await self.cfg.mainq.put(
                ResultEvent(etype="set_result_event", level=20,
                            log=f"[{tag}] Test {result}", result=result))
            await self.expect_event(self.cfg.logsq, "set_result_event")

    def _start_udp_echo(self):
        """Start a UDP echo server on a random port."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
        self._udp_echo_socket = s
        self._udp_echo_stop.clear()

        def echo():
            while not self._udp_echo_stop.is_set():
                try:
                    s.settimeout(1.0)
                    data, addr = s.recvfrom(4096)
                    if data:
                        s.sendto(data, addr)
                except socket.timeout:
                    continue
                except OSError:
                    break
        threading.Thread(target=echo, daemon=True).start()
        return port

    async def _run_interleaved_udp_clients(self, port):
        """Queue interleaved UDP packets on one stunnel listener."""
        loop = asyncio.get_running_loop()
        data_a = [b"UDP_A_PACKET_1", b"UDP_A_PACKET_2"]
        data_b = [b"UDP_B_PACKET_1", b"UDP_B_PACKET_2"]

        async def send(sock, data, timeout=10):
            await asyncio.wait_for(
                loop.sock_sendall(sock, data), timeout=timeout)

        async def recv_all(sock, name, expected, timeout=20):
            remaining = list(expected)
            while remaining:
                response = await asyncio.wait_for(
                    loop.sock_recv(sock, 4096), timeout=timeout)
                for data in list(remaining):
                    if data in response:
                        remaining.remove(data)
                        break
                else:
                    raise RuntimeError(
                        f"[{name}] Unexpected response {response[:200]!r};"
                        f" expected one of {remaining!r}")

        sock_a = None
        sock_b = None
        try:
            sock_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_a.setblocking(False)
            sock_a.connect(('127.0.0.1', port))
            sock_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_b.setblocking(False)
            sock_b.connect(('127.0.0.1', port))

            # Queue all packets before reading responses to exercise
            # listener demultiplexing and per-client UDP sockets.
            await send(sock_a, data_a[0])
            await send(sock_b, data_b[0])
            await send(sock_a, data_a[1])
            await send(sock_b, data_b[1])

            await asyncio.gather(
                recv_all(sock_a, "A", data_a),
                recv_all(sock_b, "B", data_b))
        finally:
            for s in (sock_a, sock_b):
                if s is not None:
                    s.close()


class StunnelDTLSClientInterleavingTestPlugin(Plugin):
    """DTLS client mode with interleaved clients."""

    def __init__(self):
        super().__init__()
        self.description = 'DTLS client mode with interleaved clients'

    async def perform_operation(self, cfg, logger):
        await DTLSStunnelClientInterleavingTest(cfg, logger).test_stunnel(cfg)
