"""
Saved terminal commands — one-click buttons in the vehicle terminal.

Per user, not per vehicle (see CommandFavorite in app/models/db.py). Three rules
shape this module:

* **The cap refuses, it never evicts.** A favorite is something the user set up on
  purpose; silently dropping the oldest to make room for a new one would delete
  exactly what the feature promises to keep. Past MAX_COMMAND_FAVORITES_PER_USER
  the create raises and the router answers 409.

* **One writer per user.** The cap is a read followed by a write, and two uploads
  in flight together both pass the read. The owner's `users` row is locked for the
  rest of the transaction — the same fence as crud.config_backup._lock_owner, and
  dialect neutral: SQLite drops the FOR UPDATE and has one writer anyway.

* **Ownership is the only filter.** delete_favorite() scopes by owner_id and
  reports False for anything else, so a foreign id and a missing id look the same
  to the caller. There is no administrative path around it — nobody but the owner
  has a use for these rows.
"""

import logging

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.db import CommandFavorite, User

logger = logging.getLogger(__name__)

MAX_COMMAND_FAVORITES_PER_USER = 50
LABEL_MAX_LENGTH = 40
COMMAND_MAX_LENGTH = 200


class FavoriteLimitReached(Exception):
    """The owner already holds MAX_COMMAND_FAVORITES_PER_USER rows."""


def _lock_owner(db: Session, owner_id: int) -> None:
    db.query(User.id).filter(User.id == owner_id).with_for_update().first()


def favorites_query(db: Session, owner_id: int):
    """A user's favorites in button order. Exposed so tests/test_cross_dialect_sql.py
    can compile it for every backend."""
    return (
        db.query(CommandFavorite)
        .filter(CommandFavorite.owner_id == owner_id)
        .order_by(CommandFavorite.position, CommandFavorite.id)
    )


def list_favorites(db: Session, owner_id: int) -> list[CommandFavorite]:
    return favorites_query(db, owner_id).all()


def count_favorites(db: Session, owner_id: int) -> int:
    return db.query(func.count(CommandFavorite.id)).filter(CommandFavorite.owner_id == owner_id).scalar() or 0


def create_favorite(db: Session, owner_id: int, label: str, command: str) -> CommandFavorite:
    """Append a favorite for the owner. The router validates the texts before it
    gets here; the length checks below are the last line, not the first."""
    label = label.strip()
    command = command.strip()
    if not label or len(label) > LABEL_MAX_LENGTH:
        raise ValueError("label must be 1..%d characters" % LABEL_MAX_LENGTH)
    if not command or len(command) > COMMAND_MAX_LENGTH:
        raise ValueError("command must be 1..%d characters" % COMMAND_MAX_LENGTH)

    _lock_owner(db, owner_id)
    if count_favorites(db, owner_id) >= MAX_COMMAND_FAVORITES_PER_USER:
        raise FavoriteLimitReached()

    # coalesce, not `max or -1`: a single row at position 0 is falsy and would
    # put the next one at 0 as well.
    next_position = db.query(func.coalesce(func.max(CommandFavorite.position), -1)).filter(
        CommandFavorite.owner_id == owner_id
    ).scalar() + 1

    row = CommandFavorite(owner_id=owner_id, label=label, command=command, position=next_position)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def delete_favorite(db: Session, owner_id: int, favorite_id: int) -> bool:
    """Remove one of the owner's favorites. False when there is no such row of theirs."""
    deleted = db.query(CommandFavorite).filter(
        CommandFavorite.owner_id == owner_id,
        CommandFavorite.id == favorite_id,
    ).delete(synchronize_session=False)
    db.commit()
    return deleted > 0
