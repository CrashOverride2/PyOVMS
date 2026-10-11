"""
Deleting a vehicle must remove its data everywhere, or not happen at all.

The main server cascade was already complete — historical_data, charge_logs,
push_subscriptions and auto-provisioning profiles all hang off Vehicle with
`cascade="all, delete-orphan"`. The Karto side was not:

* the call was fire-and-forget. A failed request was logged and the vehicle was
  deleted anyway, so a briefly unreachable Karto left the whole GPS history behind —
  and a vehicle id is free again afterwards, so the next registration inherited it.
* Karto's own deletion removed the `trips` rows and relied on the database cascade
  for `gps_points` (correct), but left `map_regeneration_queue` rows (no foreign key
  to cascade through) and the rendered map previews on disk. Those PNGs *are* the
  route — deleting the trip while keeping a picture of it is not a deletion.
"""

import datetime
import inspect

import pytest

from app.models import db as models_db
from app.routers.api import main as api_main
from app.routers.ui import vehicles as ui_vehicles
from app.services import vehicle_service


def _code_only(obj):
    """
    Source with comments *and* docstrings removed.

    Docstrings matter here: the first version of this module searched for
    "KartoDeletionFailed" and matched the sentence in the docstring describing the
    behaviour, so removing the actual `raise` left the test green.
    """
    import ast
    import textwrap

    source = textwrap.dedent(inspect.getsource(obj))
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                body.pop(0)
    return ast.unparse(tree)


# ---------------------------------------------------------------------------
# Main server cascade
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "relationship_name",
    ["historical_data", "charge_logs", "push_subscriptions", "auto_provision_profile_assoc"],
)
def test_vehicle_deletion_cascades_locally(relationship_name):
    relationship = models_db.Vehicle.__mapper__.relationships[relationship_name]

    assert "delete-orphan" in relationship.cascade, (
        f"{relationship_name} survives vehicle deletion"
    )


# ---------------------------------------------------------------------------
# The Karto call is verified, not fire-and-forget
# ---------------------------------------------------------------------------


def test_failed_karto_deletion_raises():
    source = _code_only(vehicle_service.trigger_karto_vehicle_deletion)

    assert "raise KartoDeletionFailed" in source, (
        "a failed Karto deletion is still swallowed"
    )


def test_karto_deletion_retries_before_giving_up():
    """The common failure is a restarting Karto, not a permanent one."""
    assert vehicle_service.KARTO_DELETE_ATTEMPTS >= 2

    source = _code_only(vehicle_service.trigger_karto_vehicle_deletion)
    assert "KARTO_DELETE_ATTEMPTS" in source


def test_karto_deletion_includes_the_running_trip():
    """
    Karto's bulk delete keeps an in-progress trip by default; a vehicle deletion
    must ask for it too, or one trip outlives the vehicle.
    """
    source = _code_only(vehicle_service.trigger_karto_vehicle_deletion)
    assert "'include_in_progress': 'true'" in source
    assert "params=params" in source


@pytest.mark.parametrize(
    "route_module,route",
    [
        (ui_vehicles, "ui_delete_vehicle_route"),
        (api_main, "api_delete_vehicle"),
    ],
)
def test_deletion_routes_abort_when_karto_fails(route_module, route):
    """
    The vehicle must survive a failed trip-data deletion. Removing it anyway is what
    orphaned the history in the first place.
    """
    source = _code_only(getattr(route_module, route))

    assert "KartoDeletionFailed" in source, f"{route} ignores a failed Karto deletion"

    guard = source.index("KartoDeletionFailed")
    local_delete = source.index("crud.vehicle.delete_vehicle(")
    assert guard < local_delete, (
        f"{route} deletes the vehicle before handling a Karto failure"
    )


def test_karto_is_called_before_the_local_row_disappears():
    """
    Karto authorizes the deletion against the OVMS database, so the vehicle has to
    still be there when the call is made.
    """
    for module, route in ((ui_vehicles, "ui_delete_vehicle_route"),
                          (api_main, "api_delete_vehicle")):
        source = _code_only(getattr(module, route))
        karto = source.index("trigger_karto_vehicle_deletion(")
        local = source.index("crud.vehicle.delete_vehicle(")
        assert karto < local, f"{route} deletes locally before telling Karto"


def test_housekeeping_deletes_inside_the_guarded_block():
    """
    The lifecycle auto-deletion must inherit the same property: a Karto failure
    aborts that vehicle and the next daily run retries it.
    """
    from app import lifespan

    source = _code_only(lifespan.periodic_lifecycle_housekeeping)

    karto = source.index("trigger_karto_vehicle_deletion(")
    local = source.index("crud.vehicle.delete_vehicle(")
    assert karto < local


# ---------------------------------------------------------------------------
# Who the Karto deletion acts as
# ---------------------------------------------------------------------------
#
# Karto admits the owner on ownership alone and anyone else only as an *active*
# admin. The housekeeping acted as an admin only and skipped Karto when there was
# none, deleting the vehicle anyway — the GPS history stayed behind.


from types import SimpleNamespace


def _person(is_active=True):
    return SimpleNamespace(is_active=is_active)


def test_karto_deletion_acts_as_the_active_owner():
    owner, admin = _person(), _person()
    assert vehicle_service.karto_deletion_actor(owner, admin) is owner


@pytest.mark.parametrize("owner", [None, _person(is_active=False)])
def test_karto_deletion_falls_back_to_the_admin(owner):
    admin = _person()
    assert vehicle_service.karto_deletion_actor(owner, admin) is admin


def test_karto_deletion_has_no_actor_without_owner_or_admin():
    assert vehicle_service.karto_deletion_actor(_person(is_active=False), None) is None


def test_karto_deletion_without_an_actor_fails_instead_of_skipping(monkeypatch):
    """No one to act as must keep the vehicle, not delete it past Karto."""
    import asyncio

    monkeypatch.setattr(vehicle_service.settings, "ENABLE_KARTO_TRIP_TRACKING", True)
    with pytest.raises(vehicle_service.KartoDeletionFailed):
        asyncio.run(vehicle_service.trigger_karto_vehicle_deletion(None, "CAR1", None))


def test_karto_deletion_without_an_actor_is_fine_when_karto_is_off(monkeypatch):
    import asyncio

    monkeypatch.setattr(vehicle_service.settings, "ENABLE_KARTO_TRIP_TRACKING", False)
    asyncio.run(vehicle_service.trigger_karto_vehicle_deletion(None, "CAR1", None))


def test_housekeeping_never_skips_karto():
    """`if admin_user:` around the call is what left the trips behind."""
    from app import lifespan

    source = _code_only(lifespan.periodic_lifecycle_housekeeping)
    assert "if admin_user" not in source
    assert source.count("karto_deletion_actor(") == 2


def test_karto_deletion_key_keeps_the_shape_karto_checks():
    """
    Karto admits an admin who does not own the vehicle only with this key, and
    recognises it by name and lifetime (crud.is_internal_deletion_key there):
    `temp-karto-delete-{vehicle_id}-{timestamp}`, valid for at most 5 minutes.
    """
    source = _code_only(vehicle_service.trigger_karto_vehicle_deletion)
    assert "f'temp-karto-delete-{vehicle_id}-{" in source
    assert "expires_delta=KARTO_DELETE_KEY_LIFETIME" in source
    assert vehicle_service.KARTO_DELETE_KEY_LIFETIME == datetime.timedelta(minutes=1)


# ---------------------------------------------------------------------------
# Every attempt inside the lifetime of its key
# ---------------------------------------------------------------------------
#
# One key served all attempts, but three 30 s timeouts and the pauses add up to 94 s:
# after two timeouts the third attempt was made with an expired key — a certain 401,
# which Karto also counts as a failed login from this server's address.


def test_one_attempt_fits_into_the_lifetime_of_its_key():
    lifetime = vehicle_service.KARTO_DELETE_KEY_LIFETIME.total_seconds()
    assert vehicle_service.KARTO_DELETE_TIMEOUT_SECONDS < lifetime


def _run_deletion(monkeypatch, outcomes):
    """Drives trigger_karto_vehicle_deletion with one fake response per attempt."""
    import asyncio
    import requests

    created, deleted, sent_keys = [], [], []

    def create_api_key(db, user_id, name, expires_delta, purpose):
        key_id = len(created) + 1
        created.append((key_id, name, expires_delta))
        return SimpleNamespace(id=key_id), f"plain-{key_id}"

    def delete_api_key(db, api_key_id, user_id):
        deleted.append(api_key_id)

    def fake_delete(url, headers, params, timeout):
        sent_keys.append(headers["X-API-Key"])
        outcome = outcomes[len(sent_keys) - 1]
        if isinstance(outcome, Exception):
            raise outcome
        return SimpleNamespace(raise_for_status=lambda: None, status_code=outcome)

    monkeypatch.setattr(vehicle_service.settings, "ENABLE_KARTO_TRIP_TRACKING", True)
    monkeypatch.setattr(vehicle_service, "KARTO_DELETE_RETRY_SECONDS", 0)
    monkeypatch.setattr(vehicle_service.crud.apikey, "create_api_key", create_api_key)
    monkeypatch.setattr(vehicle_service.crud.apikey, "delete_api_key_by_id_and_user", delete_api_key)
    monkeypatch.setattr(vehicle_service.requests, "delete", fake_delete)

    error = None
    try:
        asyncio.run(vehicle_service.trigger_karto_vehicle_deletion(None, "CAR1", SimpleNamespace(id=7)))
    except vehicle_service.KartoDeletionFailed as e:
        error = e
    return created, deleted, sent_keys, error, requests


def test_every_attempt_carries_a_fresh_key_and_removes_it(monkeypatch):
    import requests

    timeout = requests.Timeout("read timed out")
    created, deleted, sent_keys, error, _ = _run_deletion(monkeypatch, [timeout, timeout, timeout])

    assert error is not None
    assert len(created) == vehicle_service.KARTO_DELETE_ATTEMPTS
    assert len(set(sent_keys)) == vehicle_service.KARTO_DELETE_ATTEMPTS, "a key was reused across attempts"
    assert sorted(deleted) == [key_id for key_id, _, _ in created], "a temporary key outlived its attempt"
    assert all(name.startswith("temp-karto-delete-CAR1-") for _, name, _ in created)


def test_a_retry_that_succeeds_stops_there(monkeypatch):
    import requests

    created, deleted, sent_keys, error, _ = _run_deletion(
        monkeypatch, [requests.ConnectionError("502"), 204, 204])

    assert error is None
    assert len(sent_keys) == 2
    assert sorted(deleted) == [1, 2]
