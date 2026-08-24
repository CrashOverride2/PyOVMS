import asyncio
from typing import Dict, List, Tuple, Optional
import datetime
from sqlalchemy.orm import Session, joinedload

from app.protocols.v2.crypto import ARC4
from app.models import api as models_api
from app.models import db as models_db
from app.config import settings
from app.utils.vehicle_data_presenter import parse_stored_msgs_for_vehicle_info
import logging

logger = logging.getLogger(__name__)

class ClientConnection:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, addr: Tuple[str, int], is_ssl: bool = False):
        self.reader = reader
        self.writer = writer
        self.addr = addr
        self.addr_str = f"{addr[0]}:{addr[1]}"
        self.is_ssl = is_ssl

        self.vehicle_id: Optional[str] = None
        self.client_type: Optional[str] = None 

        self.tx_cipher: Optional[ARC4.ARC4Cipher] = None
        self.rx_cipher: Optional[ARC4.ARC4Cipher] = None
        self.authenticated: bool = False

        self.client_token: Optional[str] = None
        self.server_token: Optional[str] = None

        self.created_at: float = asyncio.get_event_loop().time()
        self.last_seen: float = self.created_at
        self.last_ping: float = 0.0
        # Last time last_seen_tcp was persisted to DB (throttles writes while connected).
        self.last_tcp_seen_persisted: float = 0.0

        self.command_futures: Dict[str, asyncio.Future] = {}

        # Last time this connection issued a history command (MP-0 C 30/31/32). Those
        # are the only app commands whose reply size is driven by stored data rather
        # than by the request, so they are spaced out per connection.
        self.last_history_command_at: float = 0.0

    async def send_raw_message(self, message: str):
        if self.writer.is_closing():
            logger.debug(f"TCP OUT [{self.addr_str}] Attempted to send raw message but writer is closing: {message.strip()[:50]}...")
            return

        if settings.DEBUG_TCP_PACKETS:
            target_id = self.vehicle_id or ('Unauth' if not self.authenticated else 'Unknown')
            logger.debug(f"TCP OUT (RAW) [{self.addr_str} -> {target_id}]: {message.strip()}")

        try:
            self.writer.write(message.encode('utf-8'))
            await self.writer.drain()
            self.last_seen = asyncio.get_event_loop().time()
        except ConnectionResetError:
            logger.warning(f"TCP OUT [{self.addr_str}] Connection reset while sending raw message.")
            await self.close()
        except Exception as e:
            logger.error(f"TCP OUT [{self.addr_str}] Error sending raw message: {e}", exc_info=True)
            await self.close()

    async def send_encrypted_message(self, code: str, data: str):
        if not self.tx_cipher:
            logger.warning(f"TCP OUT [{self.addr_str}] Attempted to send encrypted message to {self.vehicle_id or self.addr_str} but no cipher. Code: {code}")
            return
        from app.protocols.v2.crypto import rc4_encrypt_b64

        payload_to_encrypt = f"MP-0 {code}{data}"
        if settings.DEBUG_TCP_PACKETS:
            target_id = self.vehicle_id or ('Unauth' if not self.authenticated else 'Unknown')
            logger.debug(f"TCP OUT (CLEAR) [{self.addr_str} -> {target_id}]: {payload_to_encrypt}")

        encrypted_payload_b64 = rc4_encrypt_b64(self.tx_cipher, payload_to_encrypt)
        await self.send_raw_message(f"{encrypted_payload_b64}\r\n")

    async def close(self):
        if not self.writer.is_closing():
            logger.info(f"TCP Closing client connection for {self.vehicle_id or 'Unknown'} ({self.addr_str})")
            self.writer.close()
            try:
                await asyncio.wait_for(self.writer.wait_closed(), timeout=5.0)
                logger.debug(f"TCP Writer closed gracefully for {self.vehicle_id or 'Unknown'} ({self.addr_str})")
            except asyncio.TimeoutError:
                logger.warning(f"TCP Writer wait_closed() timed out for {self.vehicle_id or 'Unknown'} ({self.addr_str}). Connection likely already dropped by peer.")
            except Exception as e:
                logger.warning(f"TCP Exception during writer.wait_closed() for {self.vehicle_id or 'Unknown'} ({self.addr_str}): {e}")
        else:
            logger.debug(f"TCP Client connection writer already closing for {self.vehicle_id or 'Unknown'} ({self.addr_str})")

        for future_key, future in list(self.command_futures.items()):
            if not future.done():
                logger.debug(f"TCP Cancelling pending command future '{future_key}' for {self.vehicle_id or 'Unknown'} ({self.addr_str}) due to connection close.")
                future.cancel("Client connection closed")
        self.command_futures.clear()


class ConnectionManager:
    def __init__(self):
        self.car_connections: Dict[str, ClientConnection] = {}
        self.app_connections: Dict[str, List[ClientConnection]] = {} 
        self._idle_check_task: Optional[asyncio.Task] = None

    def start_idle_checker(self):
        if self._idle_check_task is None or self._idle_check_task.done():
            self._idle_check_task = asyncio.create_task(self._periodic_idle_check())
            logger.info("TCP Idle connection checker started.")

    def stop_idle_checker(self):
        if self._idle_check_task and not self._idle_check_task.done():
            self._idle_check_task.cancel()
            logger.info("TCP Idle connection checker stopped.")

    async def _periodic_idle_check(self):
        while True:
            try:
                for _ in range(settings.TCP_IDLE_CHECK_INTERVAL):
                    await asyncio.sleep(1)

                now = asyncio.get_event_loop().time()

                for vehicle_id, conn in list(self.car_connections.items()):
                    if conn.authenticated and (now - conn.last_seen > settings.TIMEOUT_CAR_IDLE):
                        logger.warning(f"TCP Car {vehicle_id} ({conn.addr_str}) timed out due to inactivity ({now - conn.last_seen:.0f}s > {settings.TIMEOUT_CAR_IDLE}s). Closing.")
                        await conn.close()
                        continue

                    time_since_last_activity = now - conn.last_seen
                    
                    if conn.authenticated and time_since_last_activity > settings.TCP_SERVER_PING_INTERVAL:
                        logger.info(f"TCP Pinging idle car {vehicle_id} to prevent timeout (idle for {time_since_last_activity:.0f}s).")
                        asyncio.create_task(conn.send_encrypted_message('A', ''))

                    if not conn.authenticated and (now - conn.created_at > settings.TIMEOUT_TCP_INITIAL_AUTH):
                         logger.warning(f"TCP Car {conn.addr_str} (unauth {vehicle_id or ''}) timed out on initial auth ({now - conn.created_at:.0f}s > {settings.TIMEOUT_TCP_INITIAL_AUTH}s). Closing.")
                         await conn.close() 

                for vehicle_id, conns in list(self.app_connections.items()):
                    for conn in list(conns): 
                        timeout = settings.TIMEOUT_APP_IDLE
                        if not conn.authenticated and (now - conn.created_at > settings.TIMEOUT_TCP_INITIAL_AUTH):
                            logger.warning(f"TCP App {conn.addr_str} (unauth {vehicle_id or ''}) timed out on initial auth ({now - conn.created_at:.0f}s > {settings.TIMEOUT_TCP_INITIAL_AUTH}s). Closing.")
                            await conn.close()
                            continue
                        if conn.authenticated and (now - conn.last_seen > timeout):
                            logger.warning(f"TCP App for {vehicle_id} ({conn.addr_str}) timed out due to inactivity ({now - conn.last_seen:.0f}s > {timeout}s). Closing.")
                            await conn.close()
            except asyncio.CancelledError:
                logger.info("Periodic idle check task was cancelled.")
                break
            except Exception:
                # Anything other than cancellation used to end the task for good, and
                # nothing restarted it: from that moment on no connection was ever
                # closed again — not the unauthenticated ones sitting on the initial
                # auth timeout, and not the authenticated ones that had gone away.
                # One bad connection object was enough to disable every timeout in
                # the server. Log and keep looping instead; the next pass rebuilds
                # its view from the current dictionaries anyway.
                logger.exception("TCP idle check pass failed; the checker keeps running.")

    def _remove_conn_from_list(self, conn_list: List[ClientConnection], conn_to_remove: ClientConnection):
        try:
            conn_list.remove(conn_to_remove)
            logger.debug(f"TCP Removed connection {conn_to_remove.addr_str} from list for vehicle {conn_to_remove.vehicle_id}")
        except ValueError:
            logger.debug(f"TCP Connection {conn_to_remove.addr_str} not found in list for vehicle {conn_to_remove.vehicle_id} during removal.")

    def add_connection(self, conn: ClientConnection):
        from app.database import SessionLocal
        from app.crud.vehicle import update_vehicle_last_seen_tcp 

        if not conn.vehicle_id or not conn.client_type:
            logger.error(f"TCP Attempt to add connection without vehicle_id or client_type: {conn.addr_str}")
            return

        logger.info(f"TCP Adding connection for {conn.vehicle_id} ({conn.addr_str}), type: {conn.client_type}")
        
        db = SessionLocal()
        try:
            update_vehicle_last_seen_tcp(db, conn.vehicle_id)
            logger.debug(f"TCP Updated last_seen_tcp for {conn.vehicle_id} in DB.")
        finally:
            db.close()

        if conn.client_type == 'C':
            old_conn = self.car_connections.get(conn.vehicle_id)
            if old_conn and old_conn != conn: 
                logger.warning(f"TCP Duplicate car connection for {conn.vehicle_id}. Closing old one from {old_conn.addr_str}.")
                asyncio.create_task(old_conn.close()) 
            self.car_connections[conn.vehicle_id] = conn
            logger.info(f"TCP Car connection for {conn.vehicle_id} from {conn.addr_str} registered.")
            asyncio.create_task(self.notify_apps_car_status(conn.vehicle_id, True, 0))
            asyncio.create_task(self.notify_car_app_count(conn.vehicle_id))

        elif conn.client_type in ('A', 'B'): 
            if conn.vehicle_id not in self.app_connections:
                self.app_connections[conn.vehicle_id] = []
            
            if conn not in self.app_connections[conn.vehicle_id]:
                 self.app_connections[conn.vehicle_id].append(conn)
                 logger.info(f"TCP App connection for {conn.vehicle_id} from {conn.addr_str} registered.")
            else:
                 logger.debug(f"TCP App connection for {conn.vehicle_id} from {conn.addr_str} was already in list.")

            asyncio.create_task(self.notify_car_app_count(conn.vehicle_id))


    def remove_connection(self, conn: ClientConnection):
        logger.info(f"TCP Removing connection for {conn.vehicle_id or 'Unknown'} ({conn.addr_str}), type: {conn.client_type}")
        if conn.vehicle_id:
            if conn.client_type == 'C':
                if self.car_connections.get(conn.vehicle_id) == conn:
                    del self.car_connections[conn.vehicle_id]
                    logger.info(f"TCP Car connection for {conn.vehicle_id} from {conn.addr_str} deregistered.")
                    
                    from app.database import SessionLocal 
                    db_session_for_staleness = SessionLocal()
                    try:
                        staleness = self._get_db_staleness(conn.vehicle_id, db_session_for_staleness)
                    finally:
                        db_session_for_staleness.close()
                    asyncio.create_task(self.notify_apps_car_status(conn.vehicle_id, False, staleness))
                else:
                    logger.debug(f"TCP Stale car connection for {conn.vehicle_id} from {conn.addr_str} is being cleaned up. A newer connection is active, so dictionary is not modified.")
            elif conn.client_type in ('A', 'B'):
                if conn.vehicle_id in self.app_connections:
                    self._remove_conn_from_list(self.app_connections[conn.vehicle_id], conn)
                    if not self.app_connections[conn.vehicle_id]: 
                        del self.app_connections[conn.vehicle_id]
                        logger.info(f"TCP Last app connection for {conn.vehicle_id} removed. Deleting vehicle entry from app_connections.")
                    else:
                        logger.info(f"TCP App connection for {conn.vehicle_id} from {conn.addr_str} deregistered. {len(self.app_connections[conn.vehicle_id])} remaining.")
                    asyncio.create_task(self.notify_car_app_count(conn.vehicle_id))
                else:
                    logger.debug(f"TCP App connection for {conn.vehicle_id} from {conn.addr_str} not found in app_connections dict during removal.")
        else: 
            logger.info(f"TCP Connection from {conn.addr_str} (unidentified) removed.")


    def _get_db_staleness(self, vehicle_id: str, db: Session) -> int:
        from app.crud.vehicle import get_vehicle_by_vehicle_id 
        try:
            vehicle_db = get_vehicle_by_vehicle_id(db, vehicle_id)
            if vehicle_db and vehicle_db.last_message_at:
                now_utc = datetime.datetime.now(datetime.timezone.utc)
                last_message_at_aware = vehicle_db.last_message_at
                
                if last_message_at_aware.tzinfo is None:
                    last_message_at_aware = last_message_at_aware.replace(tzinfo=datetime.timezone.utc)

                delta_seconds = (now_utc - last_message_at_aware).total_seconds()
                logger.debug(f"TCP Calculated DB staleness for {vehicle_id}: {int(delta_seconds)}s")
                return int(delta_seconds)
            logger.debug(f"TCP No DB record or last_message_at for {vehicle_id}, returning default staleness 300s.")
            return 300 
        except Exception as e:
            logger.error(f"Error getting DB staleness for {vehicle_id}: {e}", exc_info=True)
            return 300


    def get_car_connection(self, vehicle_id: str) -> Optional[ClientConnection]:
        return self.car_connections.get(vehicle_id.upper())

    def get_app_connections_for_vehicle(self, vehicle_id: str) -> List[ClientConnection]:
        return self.app_connections.get(vehicle_id.upper(), [])

    def get_all_vehicle_infos(self, db: Session, current_user: Optional[models_db.User] = None) -> List[models_api.VehicleInfo]:
        infos = []
        
        db_vehicles_query = db.query(models_db.Vehicle).options(joinedload(models_db.Vehicle.owner))
        if current_user and not current_user.is_admin:
            db_vehicles_query = db_vehicles_query.filter(models_db.Vehicle.owner_id == current_user.id)
        
        all_db_vehicles = db_vehicles_query.order_by(models_db.Vehicle.vehicle_id).all()
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        V3_TIMEOUT_SECONDS = 15 * 60 

        for db_vehicle_data in all_db_vehicles:
            is_v2_online = db_vehicle_data.vehicle_id in self.car_connections
            
            is_v3_online = False
            if db_vehicle_data.last_seen_v3:
                last_seen_v3_for_comparison = db_vehicle_data.last_seen_v3
                if last_seen_v3_for_comparison.tzinfo is None:
                    last_seen_v3_for_comparison = last_seen_v3_for_comparison.replace(tzinfo=datetime.timezone.utc)
                if (now_utc - last_seen_v3_for_comparison).total_seconds() < V3_TIMEOUT_SECONDS:
                    is_v3_online = True

            connection_type = "Offline"
            if is_v2_online and is_v3_online: connection_type = "V2+V3"
            elif is_v2_online: connection_type = "V2"
            elif is_v3_online: connection_type = "V3"
            
            status_parsed, loc_parsed, tpms_parsed, diag_parsed = parse_stored_msgs_for_vehicle_info(db_vehicle_data)

            info = models_api.VehicleInfo.from_orm(db_vehicle_data)
            info.owner_username = db_vehicle_data.owner.username if db_vehicle_data.owner else "N/A"
            info.connection_type = connection_type
            info.address = self.car_connections[db_vehicle_data.vehicle_id].addr_str if is_v2_online else None
            info.authenticated = is_v2_online or is_v3_online
            info.latest_status_parsed = status_parsed
            info.latest_location_parsed = loc_parsed
            info.latest_tpms_parsed = tpms_parsed
            info.latest_diag_parsed = diag_parsed
            infos.append(info)

        return infos

    def get_vehicle_info(self, db: Session, db_vehicle: "models_db.Vehicle") -> Optional["models_api.VehicleInfo"]:
        """Build a VehicleInfo for a single already-fetched vehicle DB object."""
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        V3_TIMEOUT_SECONDS = 15 * 60

        is_v2_online = db_vehicle.vehicle_id in self.car_connections

        is_v3_online = False
        if db_vehicle.last_seen_v3:
            last_seen_v3 = db_vehicle.last_seen_v3
            if last_seen_v3.tzinfo is None:
                last_seen_v3 = last_seen_v3.replace(tzinfo=datetime.timezone.utc)
            if (now_utc - last_seen_v3).total_seconds() < V3_TIMEOUT_SECONDS:
                is_v3_online = True

        connection_type = "Offline"
        if is_v2_online and is_v3_online:
            connection_type = "V2+V3"
        elif is_v2_online:
            connection_type = "V2"
        elif is_v3_online:
            connection_type = "V3"

        status_parsed, loc_parsed, tpms_parsed, diag_parsed = parse_stored_msgs_for_vehicle_info(db_vehicle)

        info = models_api.VehicleInfo.from_orm(db_vehicle)
        info.owner_username = db_vehicle.owner.username if db_vehicle.owner else "N/A"
        info.connection_type = connection_type
        info.address = self.car_connections[db_vehicle.vehicle_id].addr_str if is_v2_online else None
        info.authenticated = is_v2_online or is_v3_online
        info.latest_status_parsed = status_parsed
        info.latest_location_parsed = loc_parsed
        info.latest_tpms_parsed = tpms_parsed
        info.latest_diag_parsed = diag_parsed
        return info

    async def forward_to_car(self, vehicle_id: str, command_code_with_args: str, source_app_conn: Optional[ClientConnection]) -> Optional[str]:
        car_conn = self.get_car_connection(vehicle_id)
        source_display = source_app_conn.addr_str if source_app_conn else "API/UI"

        if not (car_conn and car_conn.authenticated):
            logger.warning(f"TCP Car {vehicle_id} not connected/authenticated. Cannot forward command '{command_code_with_args}' from {source_display}")
            return None

        loop = asyncio.get_event_loop()
        future = loop.create_future()

        cmd_num_str = command_code_with_args.split(',')[0]
        command_key = f"c{cmd_num_str}"

        if command_key in car_conn.command_futures and not car_conn.command_futures[command_key].done():
            logger.warning(f"TCP Previous command '{command_key}' to {vehicle_id} from {source_display} still pending. New command C{command_code_with_args} not sent.")
            return "BUSY_PENDING_COMMAND"

        car_conn.command_futures[command_key] = future

        logger.info(f"TCP Forwarding command C{command_code_with_args} from {source_display} to car {vehicle_id} ({car_conn.addr_str})")
        await car_conn.send_encrypted_message("C", command_code_with_args)

        try:
            response_data = await asyncio.wait_for(future, timeout=20.0) 
            logger.info(f"TCP Received response for command C{command_code_with_args} from car {vehicle_id}: {response_data[:100] if response_data else 'None'}")
            return response_data
        except asyncio.TimeoutError:
            logger.warning(f"TCP Timeout waiting for response to C{command_code_with_args} from car {vehicle_id}")
            if car_conn.command_futures.get(command_key) == future: 
                 if not future.done(): future.set_exception(asyncio.TimeoutError("Command timed out"))
                 del car_conn.command_futures[command_key]
            return "TIMEOUT"
        except asyncio.CancelledError:
            logger.info(f"TCP Command C{command_code_with_args} to car {vehicle_id} was cancelled (e.g., connection closed).")
            if car_conn.command_futures.get(command_key) == future:
                 if not future.done(): future.cancel() 
                 del car_conn.command_futures[command_key]
            return "CANCELLED"
        finally:
            if car_conn.command_futures.get(command_key) == future and (future.done() or future.cancelled()):
                logger.debug(f"TCP Future for {command_key} for {vehicle_id} is done/cancelled, removing from command_futures.")
                del car_conn.command_futures[command_key]


    async def forward_to_apps(self, vehicle_id: str, code: str, data: str, source_car_conn: ClientConnection):
        app_conns = self.get_app_connections_for_vehicle(vehicle_id)
        if app_conns:
            logger.debug(f"TCP Forwarding message code '{code}' from car {vehicle_id} to {len(app_conns)} app(s). Data: {data[:60]}...")
            tasks = [app_conn.send_encrypted_message(code, data) for app_conn in app_conns if app_conn.authenticated]
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True) 
                for i, res in enumerate(results):
                    if isinstance(res, Exception):
                        logger.error(f"Error forwarding to app {app_conns[i].addr_str} for {vehicle_id}: {res}")


    async def notify_apps_car_status(self, vehicle_id: str, car_is_online: bool, staleness_seconds: int):
        app_conns = self.get_app_connections_for_vehicle(vehicle_id)

        message_data_T = str(staleness_seconds)
        message_data_Z = "1" if car_is_online else "0"

        if app_conns:
            logger.debug(f"TCP Notifying {len(app_conns)} app(s) for {vehicle_id}: car_online={car_is_online}, staleness={staleness_seconds}s. Sending Z({message_data_Z}), T({message_data_T})")
            tasks = []
            for app_conn in app_conns:
                if app_conn.authenticated:
                    tasks.append(app_conn.send_encrypted_message("Z", message_data_Z))
                    tasks.append(app_conn.send_encrypted_message("T", message_data_T))
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for i, res in enumerate(results):
                    if isinstance(res, Exception):
                         conn_index = i // 2 
                         logger.error(f"Error notifying app {app_conns[conn_index].addr_str} for {vehicle_id}: {res}")


    async def notify_car_app_count(self, vehicle_id: str):
        car_conn = self.get_car_connection(vehicle_id)
        if car_conn and car_conn.authenticated:
            app_count = sum(1 for app_conn in self.get_app_connections_for_vehicle(vehicle_id) if app_conn.authenticated)
            logger.debug(f"TCP Notifying car {vehicle_id} of app count: {app_count}")
            await car_conn.send_encrypted_message("Z", str(app_count))
            
    async def close_all_connections(self):
        """Iterate through all active connections and close them."""
        all_conns = list(self.car_connections.values())
        for app_conn_list in self.app_connections.values():
            all_conns.extend(app_conn_list)
        
        if all_conns:
            logger.info(f"Closing {len(all_conns)} active TCP connections for server shutdown.")
            await asyncio.gather(*(conn.close() for conn in all_conns), return_exceptions=True)
        else:
            logger.info("No active TCP connections to close.")

manager = ConnectionManager()