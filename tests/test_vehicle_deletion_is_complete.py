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
