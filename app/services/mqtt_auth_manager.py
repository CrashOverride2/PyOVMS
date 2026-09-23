import os
import base64
import hashlib
import logging
import stat
import threading
from pathlib import Path
from typing import Optional, List, Dict 
from sqlalchemy.orm import Session, joinedload
from datetime import datetime, timezone

from app.config import settings 
from app.models import db as models_db
from app.utils.crypto import decrypt_data

logger = logging.getLogger(__name__)

class MosquittoAuthManager:
    """Manages Mosquitto password and ACL files for ALL PyOVMS-related users."""

    def __init__(self, passwd_path: Optional[str], acl_path: Optional[str]):
        self.passwd_path = Path(passwd_path) if passwd_path else None
        self.acl_path = Path(acl_path) if acl_path else None
        # PBKDF2 iterations: OWASP recommends 100,000+ for PBKDF2-SHA512
        # Changed from 101 (legacy Mosquitto default) for security
        self.pbkdf2_iterations = 100000
        # Every mutation below is a read-modify-write of a shared file. Without this
        # lock two concurrent writers can each read the old content and the second
        # write silently drops the first one's entry. Re-entrant because
        # sync_all_from_db() calls regenerate_acl_file() while holding it.
        self._file_lock = threading.RLock()

    def is_enabled(self) -> bool:
        return self.passwd_path is not None and self.acl_path is not None

    def _hash_mosquitto_password(self, password: str) -> str:
        salt = os.urandom(16)
        derived_key = hashlib.pbkdf2_hmac(
            'sha512', password.encode('utf-8'), salt, self.pbkdf2_iterations, dklen=64
        )
        salt_b64 = base64.b64encode(salt).decode('ascii')
        derived_key_b64 = base64.b64encode(derived_key).decode('ascii')
        return f"$7${self.pbkdf2_iterations}${salt_b64}${derived_key_b64}"

    def _atomic_write(self, file_path: Path, lines: List[str]) -> bool:
        file_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        temp_path = file_path.with_suffix(file_path.suffix + '.tmp')
        try:
            try:
                mode = stat.S_IMODE(os.stat(file_path).st_mode)
            except FileNotFoundError:
                mode = 0o640
            with open(temp_path, 'w', encoding='utf-8') as f:
                os.fchmod(f.fileno(), mode)
                for line in lines: f.write(line + '\n')
            os.rename(temp_path, file_path)
            logger.debug(f"Successfully wrote to {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to write to {file_path}: {e}", exc_info=True)
            if temp_path.exists(): os.remove(temp_path)
            return False

    def _upsert_passwd_entry(self, username: str, hashed_password: str) -> bool:
        """Replaces (or appends) a single line of the password file under the file lock."""
        new_entry = f"{username}:{hashed_password}"
        with self._file_lock:
            lines = []
            if self.passwd_path.exists():
                with open(self.passwd_path, 'r', encoding='utf-8') as f:
                    lines = f.read().splitlines()

            updated_lines = [new_entry if line.startswith(f"{username}:") else line for line in lines]
            if not any(line.startswith(f"{username}:") for line in updated_lines):
                updated_lines.append(new_entry)

            return self._atomic_write(self.passwd_path, sorted(set(updated_lines)))

    def _remove_passwd_entry(self, username: str) -> bool:
        with self._file_lock:
            if not self.passwd_path.exists():
                return True
            with open(self.passwd_path, 'r', encoding='utf-8') as f:
                lines = [line for line in f.read().splitlines() if not line.startswith(f"{username}:")]
            return self._atomic_write(self.passwd_path, lines)

    def add_api_key_user(self, key_prefix: str, full_key: str) -> bool:
        if not self.is_enabled() or not self.passwd_path: return False
        logger.info(f"MQTT: Updating password for API key user '{key_prefix}'")
        # Hashing is expensive (100k PBKDF2 iterations) — do it before taking the lock.
        hashed_password = self._hash_mosquitto_password(full_key)
        return self._upsert_passwd_entry(key_prefix, hashed_password)

    def remove_api_key_user(self, key_prefix: str) -> bool:
        if not self.is_enabled() or not self.passwd_path: return False
        logger.info(f"MQTT: Removing API key user '{key_prefix}' from password file.")
        return self._remove_passwd_entry(key_prefix)

    def update_vehicle_password(self, vehicle_id: str, server_password: str) -> bool:
        if not self.is_enabled() or not self.passwd_path: return False
        vehicle_id_upper = vehicle_id.upper()
        logger.info(f"MQTT: Updating password for vehicle '{vehicle_id_upper}'")
        hashed_password = self._hash_mosquitto_password(server_password)
        return self._upsert_passwd_entry(vehicle_id_upper, hashed_password)

    def remove_vehicle(self, vehicle_id: str) -> bool:
        if not self.is_enabled() or not self.passwd_path: return False
        vehicle_id_upper = vehicle_id.upper()
        logger.info(f"MQTT: Removing vehicle '{vehicle_id_upper}' from password file.")
        return self._remove_passwd_entry(vehicle_id_upper)

    def regenerate_acl_file(self, db: Session) -> bool:
        if not self.is_enabled() or not self.acl_path: return False
        logger.info("MQTT: Regenerating ACL file.")
        acl_lines = [
            "# PyOVMS Auto-Generated ACL File",
            f"# Last generated: {datetime.now(timezone.utc)} UTC", "",
            "# Default access is denied. Rules below grant specific access.", ""
        ]

        # Backend service users
        if settings.MQTT_BACKEND_METRICS_SUB_USER:
            acl_lines.extend([f"user {settings.MQTT_BACKEND_METRICS_SUB_USER}", "topic read ovms/+/+/metric/#", "topic read $SYS/broker/state", ""])
        if settings.MQTT_BACKEND_NOTIFY_SUB_USER:
            acl_lines.extend([f"user {settings.MQTT_BACKEND_NOTIFY_SUB_USER}", "topic read ovms/+/+/notify/#", "topic read $SYS/broker/state", ""])
        
        # Backend interactive user (with standard wildcards)
        if settings.MQTT_BACKEND_INTERACTIVE_USER:
            acl_lines.extend([
                f"user {settings.MQTT_BACKEND_INTERACTIVE_USER}",
                "topic write ovms/+/+/client/+/command/#",
                "topic read ovms/+/+/client/+/response/#",
                "topic read $SYS/broker/state", ""
            ])
        
        # Karto service user
        if settings.ENABLE_KARTO_TRIP_TRACKING and settings.KARTO_MQTT_USER:
            acl_lines.extend([
                f"user {settings.KARTO_MQTT_USER}",
                "topic read ovms/+/+/metric/v/e/on",
                "topic read ovms/+/+/metric/v/b/soc",
                "topic read ovms/+/+/metric/v/b/energy/used",
                "topic read ovms/+/+/metric/v/b/capacity",
                "topic read ovms/+/+/metric/v/p/latitude",
                "topic read ovms/+/+/metric/v/p/longitude",
                "topic read ovms/+/+/metric/v/p/altitude",
                "topic read ovms/+/+/metric/v/p/speed",
                "topic read ovms/+/+/metric/v/p/gpslock",
                "topic read ovms/+/+/metric/m/time/utc",
                "topic read ovms/+/+/notify/data/#",
                ""
            ])

        vehicles_by_owner: dict[str, list[str]] = {}
        for vehicle in db.query(models_db.Vehicle).options(joinedload(models_db.Vehicle.owner)).all():
            if (
                vehicle.protocol in ('v3', 'both')
                and vehicle.owner
                and vehicle.owner.username
                and vehicle.owner.is_active
            ):
                vid = vehicle.vehicle_id.upper()
                topic = f"ovms/{vehicle.owner.username}/{vid}/#"
                acl_lines.extend([f"user {vid}", f"topic readwrite {topic}", ""])
                vehicles_by_owner.setdefault(vehicle.owner.username, []).append(vid)

        now_utc = datetime.now(timezone.utc)
        for key in db.query(models_db.ApiKey).options(joinedload(models_db.ApiKey.user)).filter(
            models_db.ApiKey.is_active == True,
            (models_db.ApiKey.expires_at == None) | (models_db.ApiKey.expires_at > now_utc)
        ).all():
            if not (key.user and key.user.username and key.user.is_active):
                continue
            owned = vehicles_by_owner.get(key.user.username, [])
            if not owned:
                # No MQTT-capable vehicle: no topic rules at all, so the broker denies
                # everything for this account.
                continue
            acl_lines.append(f"user {key.key_prefix}")
            for vid in owned:
                base = f"ovms/{key.user.username}/{vid}"
                acl_lines.append(f"topic read {base}/#")
                acl_lines.append(f"topic write {base}/client/#")

            discovery_base = f"ovms/{key.user.username}"
            acl_lines.append(f"topic read {discovery_base}/+/metric/m/version")
            acl_lines.append(f"topic write {discovery_base}/discovery/client/#")
            acl_lines.append("")

        with self._file_lock:
            return self._atomic_write(self.acl_path, acl_lines)

    def sync_all_from_db(self, db: Session) -> bool:
        if not self.is_enabled() or not self.passwd_path:
            logger.info("MQTT Manager is disabled, skipping sync.")
            return False

        logger.info("MQTT: Performing full sync from database to password file and regenerating ACLs.")
        all_mqtt_users: Dict[str, str] = {} 

        # Add backend service users
        backend_creds = {
            settings.MQTT_BACKEND_METRICS_SUB_USER: settings.MQTT_BACKEND_METRICS_SUB_PASS,
            settings.MQTT_BACKEND_NOTIFY_SUB_USER: settings.MQTT_BACKEND_NOTIFY_SUB_PASS,
            settings.MQTT_BACKEND_INTERACTIVE_USER: settings.MQTT_BACKEND_INTERACTIVE_PASS,
            settings.KARTO_MQTT_USER: settings.KARTO_MQTT_PASSWORD,
        }
        for user, password in backend_creds.items():
            if user and password:
                all_mqtt_users[user] = self._hash_mosquitto_password(password)
        
        for vehicle in db.query(models_db.Vehicle).options(joinedload(models_db.Vehicle.owner)).all():
            if vehicle.protocol in ('v3', 'both') and vehicle.owner and vehicle.owner.is_active:
                decrypted_password = decrypt_data(vehicle.encrypted_server_password)
                all_mqtt_users[vehicle.vehicle_id.upper()] = self._hash_mosquitto_password(decrypted_password)

        now_utc = datetime.now(timezone.utc)
        active_api_keys_db = db.query(models_db.ApiKey).filter(
            models_db.ApiKey.is_active == True,
            (models_db.ApiKey.expires_at == None) | (models_db.ApiKey.expires_at > now_utc)
        ).all()
        
        with self._file_lock:
            current_passwd_entries: Dict[str, str] = {}
            if self.passwd_path.exists():
                with open(self.passwd_path, 'r', encoding='utf-8') as f:
                    current_passwd_entries = dict(line.strip().split(':', 1) for line in f if ':' in line)

            for key in active_api_keys_db:
                if key.key_prefix in current_passwd_entries:
                    all_mqtt_users[key.key_prefix] = current_passwd_entries[key.key_prefix]
                else:
                    logger.warning(f"MQTT Sync: Active API key '{key.key_prefix}' found in DB but not in password file. It will be ignored until recreated.")

            final_lines = [f"{user}:{hpass}" for user, hpass in all_mqtt_users.items()]
            ok = self._atomic_write(self.passwd_path, sorted(final_lines))

            ok = self.regenerate_acl_file(db) and ok

        logger.info("MQTT: Full password file and ACL sync completed.")
        return ok

mqtt_manager = MosquittoAuthManager(
    passwd_path=settings.MQTT_PASSWD_FILE,
    acl_path=settings.MQTT_ACL_FILE
)