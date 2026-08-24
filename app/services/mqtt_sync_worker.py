"""Decouples broker credential updates from the request that triggered them.

CRUD code only marks *what* changed; this worker figures out the resulting state
from the database and performs the file I/O — including the 100k-iteration PBKDF2
hashing — in a worker thread. Neither the HTTP request nor the event loop waits
for it, and repeated changes to the same vehicle collapse into a single write
(and therefore a single broker reload).
"""

import asyncio
import logging
import threading
import time
from typing import Dict, Set, Tuple

from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import db as models_db
from app.security_events import SecurityEventLogger, SecurityEventSeverity, SecurityEventType
from app.services.mqtt_auth_manager import mqtt_manager
from app.utils.crypto import decrypt_data

logger = logging.getLogger(__name__)

# How often pending work is picked up. Short enough that a user who saves a
# vehicle and then walks over to the module never notices the delay.
TICK_SECONDS = 0.3
# Pause before retrying after a failed cycle. Failures here are systemic
# (permissions, full disk), so hammering the filesystem helps nobody.
RETRY_DELAY_SECONDS = 5.0
# Attempts per job before raising a security event. Jobs are NOT dropped at this
# point — see _requeue() for why a revocation must keep retrying forever.
MAX_ATTEMPTS = 3
# Ceiling for the per-job exponential backoff.
MAX_RETRY_DELAY_SECONDS = 300.0

# Job key: ("vehicle", "MYCAR") or ("acl", "")
Job = Tuple[str, str]


class MqttSyncWorker:
    """Coalescing background writer for the broker password and ACL files."""

    def __init__(self):
        self._lock = threading.Lock()
        self._pending: Set[Job] = set()
        self._attempts: Dict[Job, int] = {}
        self._retry_at: Dict[Job, float] = {}

    def mark_vehicle_dirty(self, vehicle_id: str, acl: bool = True) -> None:
        """Queues a vehicle's broker credentials for (re)synchronisation.

        The worker derives the target state from the database, so this covers
        creation, password change, protocol switch and deletion alike. Call it
        only after the transaction has been committed.
        """
        if not mqtt_manager.is_enabled() or not vehicle_id:
            return
        with self._lock:
            self._pending.add(("vehicle", vehicle_id.upper()))
            if acl:
                self._pending.add(("acl", ""))

    def mark_acl_dirty(self) -> None:
        """Queues a rebuild of the ACL file (e.g. after a username change)."""
        if not mqtt_manager.is_enabled():
            return
        with self._lock:
            self._pending.add(("acl", ""))

    def has_pending_work(self) -> bool:
        with self._lock:
            return bool(self._pending)

    def _claim(self) -> Set[Job]:
        """Takes the pending jobs whose per-job backoff has elapsed."""
        now = time.monotonic()
        with self._lock:
            if not self._pending:
                return set()
            claimed = {job for job in self._pending if self._retry_at.get(job, 0.0) <= now}
            self._pending -= claimed
            for job in claimed:
                self._retry_at.pop(job, None)
            return claimed

    def _requeue(self, failed: Set[Job]) -> None:
        """
        Puts failed jobs back with exponential backoff. Nothing is ever dropped.

        Jobs used to be discarded after MAX_ATTEMPTS. For a revocation that meant the
        deleted vehicle's entry stayed in the Mosquitto password file permanently —
        after roughly fifteen seconds the revocation was simply lost, and the removed
        module went on authenticating against the broker until someone restarted the
        process. Giving up is the one thing a revocation must not do.

        MAX_ATTEMPTS now only decides when to raise a security event, so an operator
        hears about a persistently failing sync instead of it disappearing quietly.

        Backoff is per job. It used to be a single global timestamp, so one job that
        kept failing also held back every unrelated one.
        """
        now = time.monotonic()
        with self._lock:
            for job in failed:
                attempts = self._attempts.get(job, 0) + 1
                self._attempts[job] = attempts
                self._pending.add(job)
                # 5s, 10s, 20s, … capped, so a broken filesystem is retried at a
                # sane rate rather than hammered.
                delay = min(
                    RETRY_DELAY_SECONDS * (2 ** (attempts - 1)),
                    MAX_RETRY_DELAY_SECONDS,
                )
                self._retry_at[job] = now + delay

    def _sync_vehicle(self, db: Session, vehicle_id: str) -> bool:
        """Brings one vehicle's password entry in line with the database."""
        vehicle = db.query(models_db.Vehicle).filter(
            models_db.Vehicle.vehicle_id == vehicle_id.upper()
        ).first()
        if (
            not vehicle
            or vehicle.protocol not in ('v3', 'both')
            or (vehicle.owner and not vehicle.owner.is_active)
        ):
            # Deleted, no longer speaking MQTT, or owned by a deactivated account:
            # revoke its broker login. The password is recoverable from the DB, so
            # reactivating the owner restores it on the next sync.
            return mqtt_manager.remove_vehicle(vehicle_id)
        return mqtt_manager.update_vehicle_password(
            vehicle_id, decrypt_data(vehicle.encrypted_server_password)
        )

    def _apply(self, jobs: Set[Job]) -> Set[Job]:
        """Runs the queued jobs in a worker thread. Returns the failed ones."""
        failed: Set[Job] = set()
        db = SessionLocal()
        try:
            for job in sorted(jobs):
                kind, target = job
                try:
                    ok = mqtt_manager.regenerate_acl_file(db) if kind == "acl" else self._sync_vehicle(db, target)
                except Exception as e:
                    logger.error(f"MQTT sync job {kind}:{target} raised: {e}", exc_info=True)
                    ok = False
                if not ok:
                    failed.add(job)

            if failed:
                self._report_failures(db, failed)
        finally:
            db.close()
        return failed

    def _report_failures(self, db: Session, failed: Set[Job]) -> None:
        """
        Raise a security event the first time a job crosses MAX_ATTEMPTS.

        Exactly once, not on every cycle: jobs are no longer dropped at that point,
        so a permanently failing sync would otherwise emit an event every few seconds
        and bury the log it is meant to draw attention to.
        """
        with self._lock:
            crossing = sorted(
                f"{kind}:{target}" for kind, target in failed
                if self._attempts.get((kind, target), 0) + 1 == MAX_ATTEMPTS
            )
        if not crossing:
            return
        logger.error(
            f"MQTT sync still failing after {MAX_ATTEMPTS} attempts (will keep "
            f"retrying): {', '.join(crossing)}"
        )
        try:
            SecurityEventLogger.log_event(
                db=db,
                event_type=SecurityEventType.MQTT_SYNC_FAILED,
                details={
                    "failed_jobs": crossing,
                    "attempts": MAX_ATTEMPTS,
                    "passwd_file": str(mqtt_manager.passwd_path),
                    "acl_file": str(mqtt_manager.acl_path),
                    "impact": "Broker credentials/ACLs are out of sync with the database until the next restart.",
                },
                severity=SecurityEventSeverity.ERROR,
            )
        except Exception as e:
            logger.error(f"Failed to record MQTT sync failure as security event: {e}", exc_info=True)

    async def _run_once(self) -> None:
        jobs = self._claim()
        if not jobs:
            return
        failed = await run_in_threadpool(self._apply, jobs)
        if failed:
            self._requeue(failed)

    async def flush(self) -> None:
        """Processes everything still queued — used on shutdown."""
        with self._lock:
            self._retry_at.clear()
        if self.has_pending_work():
            logger.info("MQTT sync worker: flushing pending jobs before shutdown.")
            await self._run_once()

    async def run(self, shutdown_event: asyncio.Event) -> None:
        if not mqtt_manager.is_enabled():
            logger.info("MQTT sync worker not started (MQTT auth files not configured).")
            return
        logger.info("MQTT sync worker started.")
        try:
            while not shutdown_event.is_set():
                await asyncio.sleep(TICK_SECONDS)
                try:
                    await self._run_once()
                except Exception as e:
                    logger.error(f"MQTT sync worker cycle failed: {e}", exc_info=True)
        except asyncio.CancelledError:
            pass
        finally:
            logger.info("MQTT sync worker stopped.")


mqtt_sync_worker = MqttSyncWorker()
