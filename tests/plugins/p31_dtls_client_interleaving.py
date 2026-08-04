"""stunnel DTLS client mode interleaving test
   Two UDP clients --> one stunnel DTLS client listener -->
   stunnel DTLS server --> UDP echo server
   The clients alternate request/response exchanges: A1, B1, A2, B2.
   Each client verifies its own echoed data, confirming stunnel DTLS
   client mode handles multiple clients on the same UDP accept socket."""

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
        self.events.skip = [
            r"requires OpenSSL 1\.1\.0 or later"
        ]
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
            await cfg.mainq.put(LogEvent(etype="log", level=30, log=""))
            await self._log(
                tag, f"***** Start '{self.params.description}' *****", level=30)
            await self._log(
                tag,
                "Topology: UDP clients A/B -> stunnel DTLS client ->"
                " stunnel DTLS backend -> UDP echo backend;"
                " request/response order A1, B1, A2, B2")

            # Do not remove this guard merely because the alternating test no
            # longer needs BIO_s_dgram_mem().  With OpenSSL 1.0.2 the
            # auxiliary stunnel-to-stunnel DTLS topology stalls during the
            # backend cookie exchange.  Test 291 covers DTLS client mode on
            # 1.0.2 without using this incompatible topology.
            openssl_version = cfg.versions.get("stunnel-openssl")
            if openssl_version is None:
                raise RuntimeError("stunnel OpenSSL version is unavailable")
            if openssl_version < (1, 1, 0):
                await cfg.mainq.put(LogEvent(
                    etype="output_event",
                    level=30,
                    log=f"[{tag}] The stunnel-to-stunnel DTLS topology"
                        f" requires OpenSSL 1.1.0 or later;"
                        f" got {openssl_version}"))
                return

            udp_port = self._start_udp_echo()
            await self._log(
                "udp-echo", f"Listening on 127.0.0.1:{udp_port}")

            backend_cfg = await self.prepare_backend_cfgfile(
                cfg, udp_port, 'dtls-backend')
            backend_port = await self.start_stunnel(
                backend_cfg, 'dtls-backend')
            await self._log(
                tag,
                f"DTLS backend forwards 127.0.0.1:{backend_port}"
                f" to UDP 127.0.0.1:{udp_port}")

            client_cfg = await self.prepare_client_cfgfile(
                cfg, backend_port, 'dtls-client')
            stunnel_port = int(
                await self.start_stunnel(client_cfg, 'dtls-client'))
            await self._log(
                tag,
                f"DTLS client under test forwards UDP 127.0.0.1:{stunnel_port}"
                f" to DTLS 127.0.0.1:{backend_port}")

            await self._run_interleaved_udp_clients(stunnel_port)
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

    async def _run_interleaved_udp_clients(self, port):
        """Alternate request/response exchanges: A1, B1, A2, B2."""
        tag = "udp-interleaving"
        loop = asyncio.get_running_loop()
        endpoint = f"127.0.0.1:{port}"
        data = {
            "A": [b"UDP_A_PACKET_1", b"UDP_A_PACKET_2"],
            "B": [b"UDP_B_PACKET_1", b"UDP_B_PACKET_2"]
        }

        async def exchange(sock, name, sequence, payload, timeout=20):
            local_addr, local_port = sock.getsockname()[:2]
            local_endpoint = f"{local_addr}:{local_port}"
            await self._log(
                tag,
                f"Client {name} sending payload {name}{sequence}"
                f" ({len(payload)} bytes) from {local_endpoint}"
                f" to {endpoint}: {payload!r}")
            try:
                await asyncio.wait_for(
                    loop.sock_sendall(sock, payload), timeout=timeout)
                response = await asyncio.wait_for(
                    loop.sock_recv(sock, 4096), timeout=timeout)
            except asyncio.TimeoutError as err:
                raise RuntimeError(
                    f"client {name} timed out after {timeout} seconds"
                    f" exchanging payload {name}{sequence}"
                    f" from {local_endpoint} with {endpoint}") from err
            await self._log(
                tag,
                f"Client {name} received {len(response)} bytes"
                f" from {endpoint}: {response!r}")
            if response != payload:
                raise RuntimeError(
                    f"client {name} received unexpected response"
                    f" for payload {name}{sequence}: {response[:200]!r};"
                    f" expected {payload!r}")
            await self._log(
                tag, f"Client {name} verified payload {name}{sequence}")

        sockets = {}
        try:
            for name in ("A", "B"):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                sock.connect(('127.0.0.1', port))
                sockets[name] = sock
                local_addr, local_port = sock.getsockname()[:2]
                await self._log(
                    tag,
                    f"Client {name} connected UDP"
                    f" {local_addr}:{local_port} to {endpoint}")

            for name, sequence in (("A", 1), ("B", 1),
                                   ("A", 2), ("B", 2)):
                await exchange(
                    sockets[name], name, sequence, data[name][sequence-1])
            await self._log(
                tag,
                "Verified alternating exchanges A1, B1, A2, B2")
        finally:
            for name, sock in sockets.items():
                sock.close()
                await self._log(
                    tag, f"Closed UDP socket for client {name}", level=10)


class StunnelDTLSClientInterleavingTestPlugin(Plugin):
    """DTLS client mode with interleaved clients."""

    def __init__(self):
        super().__init__()
        self.description = 'DTLS client mode with interleaved clients'

    async def perform_operation(self, cfg, logger):
        await DTLSStunnelClientInterleavingTest(cfg, logger).test_stunnel(cfg)
