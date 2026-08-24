"""Fan a single vehicle notification out to every channel the vehicle is subscribed to.

"""

import datetime
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from app import crud
from app.config import settings
from app.database import SessionLocal
from app.notifications.channels.apns import send_apns_notification
from app.notifications.channels.fcm import send_fcm_notification
from app.notifications.channels.ntfy import send_ntfy_notification
from app.notifications.channels.unified_push import send_unified_push_notification
from app.notifications.email_queue import queue_email_notification
from app.notifications.errors import InvalidPushTargetError
from app.notifications.outbound import close_all_sessions
from app.notifications.ratelimit import rate_limiter
from app.notifications.retry import MAX_SEND_ATTEMPTS, backoff_delay, is_transient
from app.notifications.scheduler import DelayedRetryScheduler
from app.utils.crypto import decrypt_data

logger = logging.getLogger(__name__)

# Ceiling on how many recipients a single notification may reach. A person's devices
# number in the handful; anything beyond this is accumulation or abuse, and each
# extra recipient is another outbound request behind one rate-limit slot.
MAX_RECIPIENTS_PER_NOTIFICATION = 20

# Caps on what a vehicle can push through this path. The title becomes a mail subject
# and an NTFY header; the body becomes a mail body and a push payload. A module that
# publishes a megabyte of text would otherwise have it copied into every channel, for
# every recipient, on every retry — and APNs and FCM reject oversized payloads anyway.
MAX_TITLE_CHARS = 200
MAX_BODY_CHARS = 4_000
MAX_HTML_BODY_CHARS = 32_000

# Workers for the per-notification fan-out. Bounded deliberately: this exists so one
# unreachable recipient does not delay the others, not to allow unlimited concurrent
# outbound requests.
#
# It was 8, sized for a pool whose workers each slept through their own retry backoff —
# which meant eight recipients could occupy the entire subsystem for fifteen seconds at
# a time. Retries are deferred now (see `_retry_scheduler`), so a worker is held only
# for the duration of one real request, and the pool can be sized for the number of
# vehicles on the server instead of for the retry budget of the slowest of them.
FANOUT_WORKERS = settings.NOTIFY_FANOUT_WORKERS

ALERT_ICONS = {
    'I': 'ℹ️', 'A': '⚠️', 'W': '🔔', 'E': '❌', 'F': '⚙️', 'S': '✅',
}

_pool: Optional[ThreadPoolExecutor] = None
_pool_lock = threading.Lock()
_pool_shutdown = False


@dataclass(frozen=True)
class DispatchTarget:
    """One recipient on one channel, with everything needed to send already resolved.

    Everything here is a plain value: no ORM instance survives into the send phase, so
    nothing can trigger a lazy load against a session that has been closed.
    """
    channel: str
    sender: Callable[..., Any]
    kwargs: Dict[str, Any] = field(repr=False)
    subscription_id: Optional[int] = None
    device_id: Optional[str] = None


@dataclass(frozen=True)
class SendOutcome:
    """What one target did. `dead` is set only when the target is permanently gone.

    `retrying` distinguishes "failed, and that is the end of it" from "failed, and a
    later attempt is already booked". Both are `ok=False` — the notification has not
    been delivered yet either way — but only the first is worth alarming about.
    """
    channel: str
    ok: bool
    dead: Optional[Tuple[int, str, str]] = None
    retrying: bool = False


def _clamp(value: Optional[str], limit: int) -> Optional[str]:
    if value is None:
        return None
    if len(value) <= limit:
        return value
    return value[:limit] + "…"


def _one_line(value: str, limit: int = 120) -> str:
    """Flatten a user-controlled string for logging.

    Vehicle-supplied titles reach the log verbatim; a newline in one is enough to forge
    an additional log record.
    """
    return value.replace("\r", " ").replace("\n", " ")[:limit]


def _memoized(func: Callable[[], Any]) -> Callable[[], Any]:
    """Call `func` at most once, on first use. Not thread-shared: one plan, one thread."""
    cache: List[Any] = []

    def get() -> Any:
        if not cache:
            cache.append(func())
        return cache[0]

    return get


def _decrypt_optional(value: Optional[bytes]) -> Optional[str]:
    """Decrypt a Fernet-encrypted field, returning None if the value is empty."""
    if not value:
        return None
    try:
        return decrypt_data(value)
    except Exception:
        return None


def _get_pool() -> Optional[ThreadPoolExecutor]:
    """The fan-out pool, or None once the application is shutting down.

    None is a supported answer: `_execute()` then runs the targets inline. Handing back
    a *fresh* pool after shutdown would be the harmful option — ThreadPoolExecutor
    threads are non-daemon and joined by an atexit hook, so a notification that arrived
    late (a producer this shutdown has not stopped yet) would hold the process open for
    the full retry budget of whatever host it was talking to.
    """
    global _pool
    if _pool_shutdown:
        return None
    if _pool is None:
        with _pool_lock:
            if _pool_shutdown:
                return None
            if _pool is None:
                _pool = ThreadPoolExecutor(
                    max_workers=FANOUT_WORKERS, thread_name_prefix="ovms-fanout"
                )
    return _pool


def _run_on_pool(fn: Callable[[], None]) -> None:
    """Hand a due retry to the fan-out pool. The scheduler's timer thread calls this.

    It must not block — the timer thread is the only one watching the due times, so
    anything slow here delays every other pending retry.
    """
    pool = _get_pool()
    if pool is None:
        logger.debug("Dispatch pool is shut down; dropping a scheduled retry.")
        return
    try:
        pool.submit(fn)
    except RuntimeError:
        logger.debug("Dispatch pool is stopping; dropping a scheduled retry.")


# Where a failed send waits for its next attempt. Deliberately module-level and shared:
# what it holds is timers, not threads, so one is enough for the whole server.
_retry_scheduler = DelayedRetryScheduler("ovms-push-retry", _run_on_pool)


def shutdown_dispatch_pool(wait: bool = True) -> None:
    """Stop the retry scheduler and the fan-out pool. Called on application shutdown.

    One-way: neither is recreated afterwards. Blocking, so call it off the event loop —
    `wait=True` sits out whatever the in-flight sends still owe.

    The scheduler goes first. It is a *producer* for the pool, so stopping the pool
    while timers are still firing would mean retries submitted into a pool that is
    already closing.
    """
    global _pool, _pool_shutdown
    _retry_scheduler.shutdown()
    with _pool_lock:
        _pool_shutdown = True
        pool, _pool = _pool, None
    if pool is not None:
        pool.shutdown(wait=wait)
    # Only now that no worker can be mid-request is it safe to close the sockets they
    # were pooling.
    close_all_sessions()


def build_dispatch_plan(
    db,
    vehicle_db,
    *,
    icon_title: str,
    message_plain: str,
    message_html: Optional[str],
    ntfy_priority: int,
    ntfy_tags: Optional[List[str]],
    push_data_payload: Dict[str, str],
    badge_count,
) -> List[DispatchTarget]:
    """Resolve a vehicle's subscriptions into a flat list of ready-to-run sends.

    Runs entirely inside the caller's session and must not perform any network I/O:
    that separation is what lets the session be closed before anything blocks.

    `badge_count` may be an int or a zero-argument callable. The callable form exists
    because incrementing the badge is a side effect and only the channels that carry a
    badge should be able to trigger it — a vehicle with no push targets at all must not
    have its badge counted up by a notification nobody receives.
    """
    vehicle_id = vehicle_db.vehicle_id

    # One more than the cap, so "there were more than we will deliver to" is still
    # visible without a second COUNT query.
    all_subs = crud.push_subscription.get_subscriptions_for_vehicle(
        db, vehicle_db.id, limit=MAX_RECIPIENTS_PER_NOTIFICATION + 1
    )

    # Cap the fan-out per notification.
    #
    # The rate limit above is keyed on vehicle_id alone: one permitted
    # notification then fans out to however many subscriptions exist, each an
    # outbound SMTP/HTTP request. Accumulating device registrations therefore
    # multiplied what a single allowed notification costs, with no ceiling.
    #
    # The ordering and the cut are the database's job: sorting the full set in Python
    # meant loading every row a vehicle had ever accumulated on every notification.
    if len(all_subs) > MAX_RECIPIENTS_PER_NOTIFICATION:
        logger.warning(
            f"Vehicle {vehicle_id} has more than {MAX_RECIPIENTS_PER_NOTIFICATION} push "
            f"subscriptions; delivering to the {MAX_RECIPIENTS_PER_NOTIFICATION} most "
            f"recently registered and skipping the rest."
        )
        all_subs = all_subs[:MAX_RECIPIENTS_PER_NOTIFICATION]

    badge = badge_count if callable(badge_count) else (lambda: badge_count)

    ntfy_subs = [s for s in all_subs if s.push_type == 'ntfy']
    email_subs = [s for s in all_subs if s.push_type == 'email']
    fcm_subs = [s for s in all_subs if s.push_type == 'fcm']
    apns_subs = [s for s in all_subs if s.push_type == 'apns']
    up_subs = [s for s in all_subs if s.push_type == 'up']

    targets: List[DispatchTarget] = []

    def add(channel, sender, sub=None, **kwargs):
        targets.append(DispatchTarget(
            channel=channel,
            sender=sender,
            kwargs=kwargs,
            subscription_id=getattr(sub, "id", None),
            device_id=getattr(sub, "device_id", None),
        ))

    # --- NTFY ---------------------------------------------------------------
    if ntfy_subs:
        for sub in ntfy_subs:
            add(
                "NTFY", send_ntfy_notification, sub,
                topic=sub.endpoint,
                title=icon_title,
                message=message_plain,
                priority=ntfy_priority,
                tags=ntfy_tags,
                server_url=sub.ntfy_server_url,
                auth_method=sub.ntfy_auth_method,
                auth_token=_decrypt_optional(sub.ntfy_auth_token),
                auth_user=sub.ntfy_auth_user,
                auth_password=_decrypt_optional(sub.ntfy_auth_password),
                auth_query_param_name=sub.ntfy_auth_query_param_name,
            )
    elif vehicle_db.enable_ntfy_notifications:
        topic_to_use = vehicle_db.ntfy_topic or settings.NTFY_DEFAULT_TOPIC
        if topic_to_use:
            add(
                "NTFY", send_ntfy_notification,
                topic=topic_to_use,
                title=icon_title,
                message=message_plain,
                priority=ntfy_priority,
                tags=ntfy_tags,
                server_url=vehicle_db.ntfy_server_url,
                auth_method=vehicle_db.ntfy_auth_method,
                auth_token=_decrypt_optional(vehicle_db.ntfy_auth_token),
                auth_user=vehicle_db.ntfy_auth_user,
                auth_password=_decrypt_optional(vehicle_db.ntfy_auth_password),
                auth_query_param_name=vehicle_db.ntfy_auth_query_param_name,
            )
        else:
            logger.warning(f"NTFY enabled for {vehicle_id} but no topic resolved (vehicle or default).")

    # --- Email --------------------------------------------------------------
    #
    # The only channel that does not talk to the far end from the fan-out: mail goes on
    # the queue and a mail worker delivers it. The target still exists so that the cap,
    # the legacy fallback and the logging stay identical across channels — it just
    # returns as soon as the message is accepted.
    if email_subs:
        for sub in email_subs:
            add(
                "Email", queue_email_notification, sub,
                recipient_email=sub.endpoint,
                subject=icon_title,
                body_text=message_plain,
                body_html=message_html,
            )
    elif vehicle_db.enable_email_notifications and vehicle_db.notification_email:
        add(
            "Email", queue_email_notification,
            recipient_email=vehicle_db.notification_email,
            subject=icon_title,
            body_text=message_plain,
            body_html=message_html,
        )
    elif vehicle_db.enable_email_notifications:
        logger.warning(f"Email notifications enabled for {vehicle_id} but no recipient email configured.")

    # --- FCM ----------------------------------------------------------------
    if fcm_subs:
        for sub in fcm_subs:
            add(
                "FCM", send_fcm_notification, sub,
                device_token=sub.endpoint,
                title=icon_title,
                body=message_plain,
                data=push_data_payload,
                is_apns_token=False,
            )
    elif vehicle_db.enable_fcm_notifications and vehicle_db.fcm_token:
        add(
            "FCM", send_fcm_notification,
            device_token=vehicle_db.fcm_token,
            title=icon_title,
            body=message_plain,
            data=push_data_payload,
            is_apns_token=False,
        )
    elif vehicle_db.enable_fcm_notifications:
        logger.warning(f"FCM notifications enabled for {vehicle_id} but no FCM token configured.")

    # --- APNs (directly, or tunnelled through FCM) --------------------------
    apns_via_fcm = (settings.APNS_DELIVERY_METHOD or "apns").lower() == 'fcm'
    if apns_subs:
        for sub in apns_subs:
            if apns_via_fcm:
                add(
                    "APNs/FCM", send_fcm_notification, sub,
                    device_token=sub.endpoint,
                    title=icon_title,
                    body=message_plain,
                    data=push_data_payload,
                    is_apns_token=True,
                )
            else:
                add(
                    "APNs", send_apns_notification, sub,
                    device_token=sub.endpoint,
                    title=icon_title,
                    body=message_plain,
                    data=push_data_payload,
                    badge=badge(),
                )
    elif vehicle_db.enable_apns_notifications and vehicle_db.apns_token:
        if apns_via_fcm:
            add(
                "APNs/FCM", send_fcm_notification,
                device_token=vehicle_db.apns_token,
                title=icon_title,
                body=message_plain,
                data=push_data_payload,
                is_apns_token=True,
            )
        else:
            add(
                "APNs", send_apns_notification,
                device_token=vehicle_db.apns_token,
                title=icon_title,
                body=message_plain,
                data=push_data_payload,
                badge=badge(),
            )
    elif vehicle_db.enable_apns_notifications:
        logger.warning(f"APNs notifications enabled for {vehicle_id} but no APNs token configured.")

    # --- UnifiedPush --------------------------------------------------------
    if up_subs:
        for sub in up_subs:
            add(
                "UnifiedPush", send_unified_push_notification, sub,
                endpoint_url=sub.endpoint,
                title=icon_title,
                body=message_plain,
                data=push_data_payload,
                badge=badge(),
            )
    elif vehicle_db.enable_unified_push_notifications and vehicle_db.unified_push_endpoint:
        add(
            "UnifiedPush", send_unified_push_notification,
            endpoint_url=vehicle_db.unified_push_endpoint,
            title=icon_title,
            body=message_plain,
            data=push_data_payload,
            badge=badge(),
        )

    return targets


def _schedule_retry(target: DispatchTarget, vehicle_id: str, vehicle_id_fk: Optional[int],
                    attempt: int, delay: float) -> bool:
    """Book another attempt for `target`. False when the scheduler refused it.

    The follow-up runs detached from the notification that produced it: the caller has
    long since returned its summary, so this closure has to finish the job on its own —
    including reaping a subscription that turns out to be dead on the later attempt.
    """
    def run_later() -> None:
        outcome = _send_one(target, vehicle_id, vehicle_id_fk, attempt)
        if outcome.dead and vehicle_id_fk is not None:
            _reap_dead_subscriptions(vehicle_id_fk, vehicle_id, [outcome.dead])
        elif outcome.ok:
            logger.info(
                f"{target.channel}: notification for {vehicle_id} accepted on "
                f"attempt {attempt}/{MAX_SEND_ATTEMPTS}."
            )

    return _retry_scheduler.schedule(delay, run_later)


def _send_one(target: DispatchTarget, vehicle_id: str,
              vehicle_id_fk: Optional[int] = None, attempt: int = 1) -> SendOutcome:
    """Execute one target. Never raises.

    The channels signal four different things and all four are kept: a transient
    failure (rescheduled, not slept through), an exception that will fail identically
    next time (logged), a permanently dead target (reaped by the caller), and a plain
    False — "did not go out, do not retry", which every channel returns for a
    misconfiguration and which used to be discarded here.
    """
    try:
        accepted = target.sender(**target.kwargs)
    except InvalidPushTargetError as e:
        if target.subscription_id is not None:
            return SendOutcome(
                target.channel, False,
                (target.subscription_id, target.device_id or "?", str(e)),
            )
        logger.warning(f"{target.channel}: push target for {vehicle_id} is invalid: {e}")
        return SendOutcome(target.channel, False)
    except Exception as e:
        if is_transient(e) and attempt < MAX_SEND_ATTEMPTS:
            delay = backoff_delay(attempt)
            if _schedule_retry(target, vehicle_id, vehicle_id_fk, attempt + 1, delay):
                logger.warning(
                    f"{target.channel}: attempt {attempt}/{MAX_SEND_ATTEMPTS} for "
                    f"{vehicle_id} hit a transient error ({e}); retrying in {delay:.0f}s."
                )
                return SendOutcome(target.channel, False, retrying=True)
        logger.error(
            f"{target.channel}: notification dispatch failed for {vehicle_id} on "
            f"attempt {attempt}/{MAX_SEND_ATTEMPTS}: {e}",
            exc_info=not is_transient(e),
        )
        return SendOutcome(target.channel, False)
    return SendOutcome(target.channel, bool(accepted))


def _execute(targets: List[DispatchTarget], vehicle_id: str,
             vehicle_id_fk: Optional[int] = None) -> List[SendOutcome]:
    """Run every target, in parallel where there is more than one.

    Sequentially, one unreachable recipient delayed every recipient behind it by its
    full retry budget; with twenty subscriptions that is minutes of a blocked caller
    thread for a notification the user expects within seconds.
    """
    if len(targets) == 1:
        return [_send_one(targets[0], vehicle_id, vehicle_id_fk)]

    pool = _get_pool()
    if pool is None:
        return [_send_one(t, vehicle_id, vehicle_id_fk) for t in targets]

    try:
        futures = [pool.submit(_send_one, target, vehicle_id, vehicle_id_fk) for target in targets]
    except RuntimeError:
        # Pool already shut down (application is stopping): finish inline rather than
        # dropping notifications that were accepted.
        return [_send_one(t, vehicle_id, vehicle_id_fk) for t in targets]

    return [future.result() for future in as_completed(futures)]  # _send_one never raises


def _reap_dead_subscriptions(vehicle_id_fk: int, vehicle_id: str,
                             dead: List[Tuple[int, str, str]]) -> None:
    """Drop subscriptions whose target is permanently gone, in one short session."""
    db = SessionLocal()
    try:
        for subscription_id, device_id, reason in dead:
            try:
                crud.push_subscription.delete_subscription(db, subscription_id, vehicle_id_fk)
                logger.warning(
                    f"Removed dead push subscription (device '{device_id}') "
                    f"for {vehicle_id}: {reason}"
                )
            except Exception:
                logger.error(
                    f"Failed to remove dead push subscription {subscription_id} for {vehicle_id}",
                    exc_info=True,
                )
    finally:
        db.close()


def dispatch_notification_to_vehicle(
    vehicle_id: str,
    title: str,
    message_plain: str,
    source_protocol: str,
    message_html: Optional[str] = None,
    ntfy_priority: int = 3,
    ntfy_tags: Optional[List[str]] = None,
    fcm_data_payload: Optional[Dict[str, str]] = None,
    alert_type_char: str = 'I'
) -> bool:
    """Fan one notification out. False means the rate limiter suppressed it.

    The return value exists for callers that keep their own de-duplication state: a
    message the limiter threw away was never considered, so it must not go on occupying
    a de-duplication slot and hiding the next copy of itself. Every other outcome —
    unknown vehicle, wrong source protocol, no targets, a channel that refused — returns
    True, because in all of those cases re-offering the identical message would change
    nothing.
    """
    # Rate limiting: prevent notification spam from misbehaving vehicle modules.
    # Checked first, before any database work, because that is what it is shielding.
    suppressed_after = rate_limiter.acquire(vehicle_id)
    if suppressed_after is not None:
        logger.info(
            f"Rate limiting: Skipping notification for vehicle {vehicle_id} "
            f"(last notification {suppressed_after:.1f}s ago, sustained interval: "
            f"{rate_limiter.interval_seconds}s, burst: {rate_limiter.burst}). "
            f"Suppressed notification: '{_one_line(title)}'"
        )
        return False

    title = _clamp(title, MAX_TITLE_CHARS) or ""
    message_plain = _clamp(message_plain, MAX_BODY_CHARS) or ""
    message_html = _clamp(message_html, MAX_HTML_BODY_CHARS)

    icon = ALERT_ICONS.get((alert_type_char or 'I').upper(), 'ℹ️')
    icon_title = f"{icon} {title}"

    db = SessionLocal()
    try:
        vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_id)
        if not vehicle_db:
            logger.warning(f"Cannot dispatch notifications for unknown vehicle ID: {vehicle_id}")
            return True

        if vehicle_db.protocol == 'both' and vehicle_db.notification_preference:
            if source_protocol != vehicle_db.notification_preference:
                logger.info(
                    f"Skipping notification for {vehicle_id} from {source_protocol} "
                    f"due to preference '{vehicle_db.notification_preference}'."
                )
                return True

        logger.info(f"Dispatching notifications for vehicle {vehicle_id}")

        # The badge count is a stored counter, so reading it is a write. Deferred behind
        # a callable and resolved at most once, by the first badge-carrying target: a
        # vehicle with no APNs/UnifiedPush recipient must not accumulate a badge for
        # notifications that were never delivered to a device that could clear it.
        def _next_badge_count() -> int:
            from app.widget_push_service import widget_push_service
            return widget_push_service.increment_badge_count(vehicle_id) or 1

        badge_count = _memoized(_next_badge_count)

        # Enrich push data payload with a server-side timestamp so the app never falls back to epoch
        notification_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        push_data_payload = {**(fcm_data_payload or {}), "timestamp": notification_timestamp}

        vehicle_id_fk = vehicle_db.id
        targets = build_dispatch_plan(
            db, vehicle_db,
            icon_title=icon_title,
            message_plain=message_plain,
            message_html=message_html,
            ntfy_priority=ntfy_priority,
            ntfy_tags=ntfy_tags,
            push_data_payload=push_data_payload,
            badge_count=badge_count,
        )
    except Exception as e:
        logger.error(f"Notification dispatch for {vehicle_id} failed: {e}", exc_info=True)
        return True
    finally:
        # Closed before a single byte goes out: nothing below needs the session, and
        # holding one across the network I/O is what starved the connection pool.
        db.close()

    if not targets:
        logger.debug(f"No notification targets configured for {vehicle_id}.")
        return True

    outcomes = _execute(targets, vehicle_id, vehicle_id_fk)

    # Each channel logs its own detail; this is the one line that says whether the
    # notification as a whole got out. A channel that returns False has already
    # explained itself, but silently discarding that answer meant a vehicle whose every
    # recipient was misconfigured looked exactly like one that was delivered to.
    failed = [o.channel for o in outcomes if not o.ok and not o.retrying]
    retrying = [o.channel for o in outcomes if o.retrying]
    if failed or retrying:
        accepted = len(outcomes) - len(failed) - len(retrying)
        detail = []
        if failed:
            detail.append(f"failed on {', '.join(sorted(set(failed)))}")
        if retrying:
            detail.append(f"retrying {', '.join(sorted(set(retrying)))}")
        logger.warning(
            f"Notification for {vehicle_id}: {accepted}/{len(outcomes)} "
            f"target(s) accepted; {'; '.join(detail)}."
        )
    else:
        logger.info(
            f"Notification for {vehicle_id} accepted by all {len(outcomes)} target(s)."
        )

    dead = [outcome.dead for outcome in outcomes if outcome.dead]
    if dead:
        _reap_dead_subscriptions(vehicle_id_fk, vehicle_id, dead)
    return True
