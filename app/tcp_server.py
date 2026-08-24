import asyncio
import ssl
from pathlib import Path
import socket
import logging
from typing import List, Optional, Dict
from collections import defaultdict

from app import crud
from app.connection_manager import manager, ClientConnection
from app.protocols.v2.main import handle_incoming_message
from app.config import settings
from app.database import SessionLocal
from app.security_manager import security_manager

logger = logging.getLogger(__name__)

_running_servers: List[asyncio.Server] = []

# Connection rate limiting
_MAX_TOTAL_CONNECTIONS = 500
_MAX_CONNECTIONS_PER_IP = 10
_TLS_HANDSHAKE_TIMEOUT = 15  # seconds
# A real client sends its MP-A/MP-B/MP-C line immediately; blank lines before
# authentication only ever serve to keep a connection slot occupied.
_MAX_BLANK_LINES_BEFORE_AUTH = 3

_connection_semaphore: Optional[asyncio.Semaphore] = None
_per_ip_count: Dict[str, int] = defaultdict(int)
_per_ip_lock: Optional[asyncio.Lock] = None


def _init_connection_limiters():
    global _connection_semaphore, _per_ip_lock
    _connection_semaphore = asyncio.Semaphore(_MAX_TOTAL_CONNECTIONS)
    _per_ip_lock = asyncio.Lock()


async def client_connection_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, is_ssl: bool = False):
    peer_socket = writer.get_extra_info('socket')
    addr = writer.get_extra_info('peername') if peer_socket and peer_socket.fileno() != -1 else ('unknown', 0)
    addr_str = f"{addr[0]}:{addr[1]}"
    ssl_info = " (SSL)" if is_ssl else ""
    logger.info(f"TCP Connection attempt from {addr_str}{ssl_info}")

    client_ip = addr[0]
    if security_manager.is_blocked(client_ip):
        logger.critical(f"TCP Connection REJECTED from blocked IP: {client_ip}")
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return

    # Global connection cap
    if _connection_semaphore is None or not await _try_acquire_semaphore():
        logger.warning(f"TCP Connection REJECTED from {addr_str}: global connection limit ({_MAX_TOTAL_CONNECTIONS}) reached.")
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return

    # Per-IP connection cap
    async with _per_ip_lock:
        if _per_ip_count[client_ip] >= _MAX_CONNECTIONS_PER_IP:
            logger.warning(f"TCP Connection REJECTED from {addr_str}: per-IP limit ({_MAX_CONNECTIONS_PER_IP}) reached.")
            _connection_semaphore.release()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return
        _per_ip_count[client_ip] += 1

    if peer_socket and peer_socket.fileno() != -1:
        _setup_socket_keepalive(peer_socket)
    else:
        logger.warning(f"TCP Could not get valid socket for {addr_str}, keepalive not configured.")

    conn = ClientConnection(reader, writer, addr=addr, is_ssl=is_ssl)

    try:
        logger.info(f"TCP Connection established from {addr_str}{ssl_info}. Client: {conn.addr_str}")
        auth_timeout_active = True
        connection_started_at = asyncio.get_event_loop().time()
        blank_lines_before_auth = 0

        while not reader.at_eof():
            # Absolute deadline for unauthenticated sockets.
            #
            # The read timeout below is per-read and restarts on every byte, and the
            # blank-line branch further down skips straight back to the top of the loop
            # without ever reaching the authentication handler. A peer that sends a
            # single "\n" every minute therefore held a connection slot forever and
            # never produced a timeout, so it never counted as a v2tcp failure either.
            # The idle checker in connection_manager cannot see it: connections are only
            # registered there *after* successful authentication.
            if not conn.authenticated:
                age = asyncio.get_event_loop().time() - connection_started_at
                if age > settings.TIMEOUT_TCP_INITIAL_AUTH:
                    logger.warning(
                        f"TCP Unauthenticated client {conn.addr_str} exceeded the "
                        f"{settings.TIMEOUT_TCP_INITIAL_AUTH}s authentication window "
                        f"({age:.0f}s). Counting as failure and closing."
                    )
                    security_manager.record_failure(client_ip, 'v2tcp')
                    await conn.close()
                    break

            try:
                if auth_timeout_active:
                    current_timeout = settings.TIMEOUT_TCP_INITIAL_AUTH
                elif conn.client_type == 'C':
                    current_timeout = settings.TIMEOUT_CAR_IDLE
                else:
                    current_timeout = settings.TIMEOUT_APP_IDLE

                if settings.DEBUG_TCP_PACKETS:
                    logger.debug(f"TCP [{conn.addr_str}] Waiting for data (timeout: {current_timeout}s, auth: {conn.authenticated}, auth_timeout_active: {auth_timeout_active})")

                raw_line_bytes = await asyncio.wait_for(reader.readuntil(b'\n'), timeout=current_timeout + 5)
                message_line_str = raw_line_bytes.decode('utf-8').strip()

                if settings.DEBUG_TCP_PACKETS:
                    source_id = conn.vehicle_id or ('Unauth' if not conn.authenticated else 'Unknown')
                    logger.debug(f"TCP IN  (RAW) [{conn.addr_str} <- {source_id}]: {message_line_str}")

                conn.last_seen = asyncio.get_event_loop().time()

                if not message_line_str:
                    if settings.DEBUG_TCP_PACKETS:
                        logger.debug(f"TCP [{conn.addr_str}] Keep-alive or empty line received.")
                    if not conn.authenticated:
                        # Blank lines are a legitimate keep-alive *after* authentication.
                        # Before it they are pure slot-holding, so cap them instead of
                        # relying on the absolute deadline alone.
                        blank_lines_before_auth += 1
                        if blank_lines_before_auth > _MAX_BLANK_LINES_BEFORE_AUTH:
                            logger.warning(
                                f"TCP Client {conn.addr_str} sent "
                                f"{blank_lines_before_auth} blank lines without "
                                f"authenticating. Counting as failure and closing."
                            )
                            security_manager.record_failure(client_ip, 'v2tcp')
                            await conn.close()
                            break
                    continue

                await handle_incoming_message(conn, message_line_str)

                if conn.authenticated and auth_timeout_active:
                    logger.info(f"TCP Client {conn.vehicle_id} ({conn.addr_str}) authenticated as type {conn.client_type}. Auth timeout disabled.")
                    auth_timeout_active = False

            except asyncio.TimeoutError:
                if conn.authenticated:
                    logger.warning(f"TCP Timeout reading from authenticated client {conn.vehicle_id} ({conn.addr_str}). Closing.")
                elif auth_timeout_active:
                    # Count silent/idle unauthenticated timeouts as failures to prevent slow-loris
                    logger.warning(f"TCP Timeout during initial authentication for client {conn.addr_str}. Counting as failure.")
                    security_manager.record_failure(client_ip, 'v2tcp')
                else:
                    logger.warning(f"TCP Timeout reading from unauthenticated (but past initial auth phase?) client {conn.addr_str}. Closing.")
                await conn.close()
                break
            except asyncio.IncompleteReadError:
                logger.info(f"TCP Connection closed by peer (incomplete read): {conn.vehicle_id or conn.addr_str}")
                break
            except ConnectionResetError:
                logger.info(f"TCP Connection reset by peer: {conn.vehicle_id or conn.addr_str}")
                break
            except UnicodeDecodeError as e:
                logger.error(f"TCP Unicode decode error from {conn.vehicle_id or conn.addr_str}: {e}. Data: {raw_line_bytes[:50] if 'raw_line_bytes' in locals() else 'N/A'}. Closing.")
                await conn.close()
                break
            except Exception as e:
                logger.error(f"TCP General error handling client {conn.vehicle_id or conn.addr_str}: {e}", exc_info=True)
                await conn.close()
                break
    finally:
        logger.info(f"TCP Closing connection for {conn.vehicle_id or 'Unknown'} ({conn.addr_str}). Authenticated: {conn.authenticated}")
        # Freeze the V2 "last seen" timestamp at the moment the car disconnects.
        if conn.authenticated and conn.client_type == 'C' and conn.vehicle_id:
            db = SessionLocal()
            try:
                crud.vehicle.update_vehicle_last_seen_tcp(db, conn.vehicle_id)
            except Exception as e:
                logger.error(f"TCP Failed to persist last_seen_tcp on disconnect for {conn.vehicle_id}: {e}")
            finally:
                db.close()
        manager.remove_connection(conn)
        if not conn.writer.is_closing():
            await conn.close()
        # Release connection limits
        async with _per_ip_lock:
            _per_ip_count[client_ip] = max(0, _per_ip_count[client_ip] - 1)
            if _per_ip_count[client_ip] == 0:
                del _per_ip_count[client_ip]
        if _connection_semaphore is not None:
            _connection_semaphore.release()
        logger.info(f"TCP Connection for {conn.vehicle_id or 'Unknown'} ({conn.addr_str}) fully closed and removed.")


async def _try_acquire_semaphore() -> bool:
    """Non-blocking semaphore acquire; returns False immediately if at capacity."""
    if _connection_semaphore._value <= 0:
        return False
    await _connection_semaphore.acquire()
    return True


async def _ssl_client_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    await client_connection_handler(reader, writer, is_ssl=True)


def _setup_socket_keepalive(actual_socket: socket.socket):
    """
    Attempts to set TCP keepalive options on the given socket.
    It's platform-dependent and might not work on all OSes.
    """
    if not actual_socket or actual_socket.fileno() == -1:
        logger.warning("TCP Keepalive: Invalid socket provided.")
        return

    try:
        peer_info = actual_socket.getpeername() 
        actual_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        
        if hasattr(socket, "TCP_KEEPIDLE"): 
            actual_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, settings.TCP_KEEPIDLE)
        if hasattr(socket, "TCP_KEEPINTVL"):
            actual_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, settings.TCP_KEEPINTVL)
        if hasattr(socket, "TCP_KEEPCNT"): 
            actual_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, settings.TCP_KEEPCNT)
        
        logger.debug(f"TCP SO_KEEPALIVE configured for {peer_info}. Idle: {settings.TCP_KEEPIDLE}, Intvl: {settings.TCP_KEEPINTVL}, Cnt: {settings.TCP_KEEPCNT}")

    except OSError as e: 
        logger.warning(f"TCP Keepalive Warning: Could not set some SO_KEEPALIVE options for {peer_info if 'peer_info' in locals() else 'unknown socket'}: {e}")
    except Exception as e:
        logger.error(f"TCP Keepalive Error: Unexpected error setting SO_KEEPALIVE for {peer_info if 'peer_info' in locals() else 'unknown socket'}: {e}", exc_info=False) # exc_info=False for brevity


async def start_tcp_server_main() -> List[asyncio.Task]:
    global _running_servers
    _init_connection_limiters()

    if settings.DEBUG_TCP_PACKETS:
        logger.info("DEBUG_TCP_PACKETS is enabled. All TCP traffic will be logged to the console at DEBUG level.")
    else:
        logger.info("DEBUG_TCP_PACKETS is disabled. Set to True in config for verbose packet logging.")

    logger.info(
        f"TCP connection limits: global={_MAX_TOTAL_CONNECTIONS}, per-IP={_MAX_CONNECTIONS_PER_IP}, "
        f"TLS handshake timeout={_TLS_HANDSHAKE_TIMEOUT}s"
    )

    server_tasks = []

    try:
        plain_server = await asyncio.start_server(
            lambda r, w: client_connection_handler(r, w, is_ssl=False),
            settings.SERVER_HOST, settings.TCP_PORT
        )
        _running_servers.append(plain_server)
        addr_plain = plain_server.sockets[0].getsockname()
        logger.info(f'PyOVMS Plain TCP Server listening on {addr_plain}')
        server_tasks.append(asyncio.create_task(plain_server.serve_forever()))
    except Exception as e:
        logger.error(f"Failed to start Plain TCP Server on {settings.SERVER_HOST}:{settings.TCP_PORT}: {e}", exc_info=True)

    if settings.SSL_CERT_FILE and settings.SSL_KEY_FILE:
        cert_path = Path(settings.SSL_CERT_FILE)
        key_path = Path(settings.SSL_KEY_FILE)
        if cert_path.exists() and key_path.exists():
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            # PROTOCOL_TLS_SERVER on its own still negotiates TLS 1.0 and 1.1 on
            # older OpenSSL builds. Both are deprecated and broken; this listener
            # carries the vehicle's RC4 session key exchange, so it is not the place
            # to accept whatever the peer offers.
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            try:
                # Forward secrecy and AEAD only. Left at the default, the cipher list
                # includes CBC suites that are still tolerated for compatibility.
                ssl_context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM")
            except ssl.SSLError as e:
                logger.warning(f"Could not restrict TLS cipher suites, using defaults: {e}")
            try:
                # The private key is readable by this process; if it is readable by
                # everyone else too, that is worth saying out loud rather than
                # discovering later.
                key_mode = key_path.stat().st_mode & 0o777
                if key_mode & 0o077:
                    logger.warning(
                        f"TLS private key {key_path} is mode {key_mode:04o} — it should "
                        f"be readable only by the service user (0600)."
                    )
            except OSError:
                pass
            try:
                ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
                # Use _ssl_client_handler to apply TLS handshake timeout
                ssl_server = await asyncio.start_server(
                    _ssl_client_handler,
                    settings.SERVER_HOST, settings.TCP_SSL_PORT,
                    ssl=ssl_context,
                    ssl_handshake_timeout=_TLS_HANDSHAKE_TIMEOUT,
                )
                _running_servers.append(ssl_server)
                addr_ssl = ssl_server.sockets[0].getsockname()
                logger.info(f'PyOVMS SSL TCP Server listening on {addr_ssl}')
                server_tasks.append(asyncio.create_task(ssl_server.serve_forever()))
            except ssl.SSLError as e:
                logger.error(f"SSL Error starting TCP SSL server: {e}. Check cert/key files, permissions, and password (if key is encrypted).")
            except Exception as e:
                logger.error(f"Error starting TCP SSL server: {e}", exc_info=True)
        else:
            logger.warning(f"SSL_CERT_FILE ({cert_path}) or SSL_KEY_FILE ({key_path}) not found. SSL TCP server NOT started.")
    else:
        logger.info("SSL_CERT_FILE or SSL_KEY_FILE not configured. SSL TCP server NOT started.")

    if not _running_servers:
        logger.error("No TCP servers were successfully started. Exiting TCP server task.")
        return []

    manager.start_idle_checker()
    logger.info("TCP Idle connection checker task started.")

    return server_tasks

async def shutdown_tcp_servers():
    """Gracefully shuts down all running TCP server instances."""
    if not _running_servers:
        logger.info("No running TCP servers to shut down.")
        return

    for srv in _running_servers:
        try:
            sockname = srv.sockets[0].getsockname() if srv.sockets else "unknown socket"
        except (IndexError, OSError):
            sockname = "already closed socket"

        if srv.is_serving():
            srv.close()
            try:
                await asyncio.wait_for(srv.wait_closed(), timeout=2.0)
                logger.info(f"TCP server on {sockname} shut down gracefully.")
            except asyncio.TimeoutError:
                logger.warning(f"TCP server on {sockname} did not close in time.")
    _running_servers.clear()