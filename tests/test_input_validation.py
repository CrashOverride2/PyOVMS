"""
Regression tests for H-7: `$` in a Python regex also matches before a trailing newline.

Every identifier validator used `re.match(r"^[A-Z0-9-]+$", v)`, which accepts "ABC\\n".
Those identifiers are written verbatim into the Mosquitto password and ACL files, where
a stray newline splits one rule into two malformed lines. Mosquitto then rejects the
whole file — and a broker that fails to load its ACL grants every authenticated client
access to every topic.

The fix is `re.fullmatch`. These tests pin the behaviour at the model boundary, so they
keep holding regardless of which anchor style someone reintroduces later.
"""

import pytest
from pydantic import ValidationError

from app.models import api as models_api

NEWLINE_PAYLOADS = ["ABC\n", "ABC\r\n", "ABC\r", "AB\nCD", "ABC\n\n"]


@pytest.mark.parametrize("vehicle_id", NEWLINE_PAYLOADS)
def test_vehicle_create_rejects_newlines_in_vehicle_id(vehicle_id):
    with pytest.raises(ValidationError):
        models_api.VehicleCreate(vehicle_id=vehicle_id, server_password="a-strong-password")


@pytest.mark.parametrize("vehicle_id", NEWLINE_PAYLOADS)
def test_vehicle_update_rejects_newlines_in_vehicle_id(vehicle_id):
    with pytest.raises(ValidationError):
        models_api.VehicleUpdate(vehicle_id=vehicle_id)


@pytest.mark.parametrize("username", ["bob\n", "bob\r\n", "bo\nb"])
def test_user_create_rejects_newlines_in_username(username):
    with pytest.raises(ValidationError):
        models_api.UserCreate(
            username=username, email="bob@example.com", password="Str0ng-Passw0rd!x"
        )


@pytest.mark.parametrize("vehicle_id", ["ABC123", "EV-1", "A"])
def test_legitimate_vehicle_ids_still_accepted(vehicle_id):
    """The fix must not tighten the rules beyond removing the newline hole."""
    model = models_api.VehicleCreate(vehicle_id=vehicle_id, server_password="a-strong-password")
    assert model.vehicle_id == vehicle_id.upper()


@pytest.mark.parametrize("bad", ["ABC DEF", "ABC:DEF", "abc#", "ABC/DEF", "ABC+DEF"])
def test_broker_metacharacters_still_rejected(bad):
    """':' splits a passwd line, '/' '+' '#' are MQTT topic separators/wildcards."""
    with pytest.raises(ValidationError):
        models_api.VehicleCreate(vehicle_id=bad, server_password="a-strong-password")
