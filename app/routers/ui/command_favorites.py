"""
Command favorites of the vehicle terminal — the AJAX half.

The list itself is rendered into the vehicle page (see `command_favorites` in
ui_vehicle_detail_page_route); these two routes are what the star and the × on
the terminal tab call. Both answer JSON and, like the command-ajax route, carry
the rotated CSRF token in every answer so the page can keep going without a
reload. Ownership is the only access rule: a favorite belongs to the user who
saved it, an admin has no use for anyone else's, and a foreign id is 404.
"""

import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Path, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app import crud
from app.csrf_protection import get_csrf_token, verify_csrf_token
from app.database import get_db
from app.dependencies import require_current_user_from_cookie_fully_authenticated
from app.models import api as models_api
from app.models import db as models_db
from . import get_translator

logger = logging.getLogger(__name__)
router = APIRouter()

# `id` is an Integer column: 32 bits on PostgreSQL and MySQL, and sqlite3 refuses
# anything past 64 bits with an OverflowError while binding the parameter — a 500
# with a traceback in the log, from an authenticated session, for a URL. The bound
# turns it into a 422 before the query is built.
MAX_FAVORITE_ID = 2**31 - 1


def _json(request: Request, status_code: int, **payload) -> JSONResponse:
    payload["csrf_token"] = get_csrf_token(request)
    return JSONResponse(status_code=status_code, content=payload)


@router.post("/favorites", name="ui_create_command_favorite")
def ui_create_command_favorite_route(
    request: Request,
    # "" rather than ...: an empty field is refused by the validator below with the
    # translated message, not by FastAPI as a 422 "Field required".
    label: str = Form(""),
    command: str = Form(""),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated),
):
    _ = get_translator(request)
    # Called here, not in a helper: tests/test_blocked_ip_csrf.py reads the handler
    # body for this call and does not accept the router-level dependency alone.
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token validation failed")

    try:
        data = models_api.CommandFavoriteCreate(label=label, command=command)
    except ValidationError as exc:
        field = (exc.errors()[0].get("loc") or ("",))[0]
        if field == "label":
            message = _("Label must be 1–%(n)d characters on a single line.") % {
                "n": crud.command_favorite.LABEL_MAX_LENGTH}
        else:
            message = _("Command must be 1–%(n)d characters on a single line.") % {
                "n": crud.command_favorite.COMMAND_MAX_LENGTH}
        return _json(request, status.HTTP_400_BAD_REQUEST, ok=False, error=message)

    try:
        favorite = crud.command_favorite.create_favorite(db, current_user.id, data.label, data.command)
    except crud.command_favorite.FavoriteLimitReached:
        return _json(
            request, status.HTTP_409_CONFLICT, ok=False,
            error=_("You can keep at most %(n)d favorites.") % {
                "n": crud.command_favorite.MAX_COMMAND_FAVORITES_PER_USER},
        )

    logger.info(f"Command favorite '{favorite.label}' saved for user '{current_user.username}'")
    return _json(
        request, status.HTTP_201_CREATED, ok=True,
        favorite=models_api.CommandFavoriteInfo.model_validate(favorite).model_dump(),
    )


@router.post("/favorites/{favorite_id}/delete", name="ui_delete_command_favorite")
def ui_delete_command_favorite_route(
    request: Request,
    favorite_id: int = Path(..., ge=1, le=MAX_FAVORITE_ID),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated),
):
    _ = get_translator(request)
    # Called here, not in a helper: tests/test_blocked_ip_csrf.py reads the handler
    # body for this call and does not accept the router-level dependency alone.
    try:
        verify_csrf_token(request, csrf_token)
    except HTTPException:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF token validation failed")

    if not crud.command_favorite.delete_favorite(db, current_user.id, favorite_id):
        return _json(request, status.HTTP_404_NOT_FOUND, ok=False, error=_("Favorite not found."))
    return _json(request, status.HTTP_200_OK, ok=True)
