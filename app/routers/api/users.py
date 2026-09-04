import logging

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List

from app import crud
from app.models import api as models_api, db as models_db
from app.database import get_db
from app.dependencies import require_admin_api_user, require_active_api_user
from app.security import verify_password
from app.services.disposable_email_service import (
    disposable_email_service,
    DisposableEmailBlocked,
    DisposableEmailListUnavailable,
)
from app.security_events import log_admin_role_change, security_event_logger, SecurityEventType
from app.security_manager import security_manager
from app.services.vehicle_service import (
    KartoDeletionFailed,
    trigger_karto_deletion_for_user_vehicles,
)

router = APIRouter(
    prefix="/users",
    tags=["User Management API"],
    dependencies=[Depends(require_admin_api_user)]
)

# Separate router for self-service endpoints that only require an active user,
# not admin privileges.  Mounted at the same prefix via api/main.py.
#
# The dependency is declared here as well as on the one route below, and that is not
# redundancy for its own sake: this router shares the /users prefix with the
# admin-only one above, so anything added here inherits the *path* of an
# administrative surface without inheriting its guard. A route written without an
# explicit Depends would be reachable unauthenticated, and would read as protected to
# anyone who saw the prefix. The floor belongs on the router.
me_router = APIRouter(
    prefix="/users",
    tags=["User Management API"],
    dependencies=[Depends(require_active_api_user)],
)

logger = logging.getLogger(__name__)


@router.post("", response_model=models_api.UserInfo, status_code=status.HTTP_201_CREATED)
def create_user_api(
    user_in: models_api.UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_admin: models_db.User = Depends(require_admin_api_user),
):
    # The admin check is the router-level dependency above; current_admin re-declares
    # it so the guard is visible in the signature (FastAPI caches it, so this is the
    # same call) and so the audit records below can name who acted.
    ip_addr = request.client.host if request.client else "unknown"
    if crud.user.get_user_by_username(db, username=user_in.username):
        security_manager.record_failure(ip_addr, 'api_general')
        raise HTTPException(status_code=400, detail="Username already registered")
    if user_in.email and crud.user.get_user_by_email(db, email=user_in.email):
        security_manager.record_failure(ip_addr, 'api_general')
        raise HTTPException(status_code=400, detail="Email already registered")
    try:
        disposable_email_service.check_email(db, user_in.email)
    except DisposableEmailBlocked:
        ip_addr = request.client.host if request.client else None
        security_event_logger.log_event(
            db=db,
            event_type=SecurityEventType.DISPOSABLE_EMAIL_BLOCKED,
            username=user_in.username,
            ip_address=ip_addr,
            details={"email": user_in.email, "domain": user_in.email.split("@")[-1].lower()},
        )
        raise HTTPException(status_code=400, detail="Disposable email addresses are not allowed")
    except DisposableEmailListUnavailable as exc:
        logger.error("Disposable email validation unavailable via API: %s", exc)
        raise HTTPException(status_code=503, detail="Unable to validate email domain at this time")
    new_user = crud.user.create_user(db=db, user_in=user_in)
    try:
        ip_addr = request.client.host if request.client else None
        security_event_logger.log_event(
            db=db, event_type=SecurityEventType.USER_CREATED,
            user_id=new_user.id, username=new_user.username,
            ip_address=ip_addr,
            details={
                "created_via": "api",
                "created_by": current_admin.username,
                "is_admin": new_user.is_admin,
            },
        )
    except Exception:
        pass
    if new_user.is_admin:
        log_admin_role_change(
            db, target_id=new_user.id, target_username=new_user.username, granted=True,
            actor=current_admin, ip_address=ip_addr, via="api_create",
        )
    return new_user

@router.get("", response_model=List[models_api.UserInfo])
def read_users_api(
    skip: int = 0, limit: int = 100, db: Session = Depends(get_db)
):
    return crud.user.get_users(db, skip=skip, limit=limit)

@router.get("/{user_id}", response_model=models_api.UserInfo)
def read_user_api(user_id: int, db: Session = Depends(get_db)):
    db_user = crud.user.get_user_by_id(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

@router.put("/{user_id}", response_model=models_api.UserInfo)
def update_user_api(
    user_id: int, user_in: models_api.UserUpdate, request: Request, db: Session = Depends(get_db),
    current_admin: models_db.User = Depends(require_admin_api_user)
):
    db_user = crud.user.get_user_by_id(db, user_id=user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    # The invariant first, deliberately ahead of the self-checks below. Ordered after
    # them it would be unreachable — the actor is an active admin and cannot demote or
    # deactivate their own account, so a sole admin never gets this far — which makes
    # it a guard that never runs and therefore never fails visibly if it breaks. Ahead
    # of them it carries the sole-admin case itself, and says the accurate thing: the
    # problem is not that you are editing yourself, it is that nobody else can get in.
    if (user_in.is_admin is False or user_in.is_active is False) and crud.user.is_last_active_admin(db, db_user):
        raise HTTPException(status_code=400, detail="Cannot remove the last remaining admin account.")

    if db_user.id == current_admin.id:
        if user_in.is_active is False: raise HTTPException(status_code=400, detail="Admin cannot deactivate themselves.")
        if user_in.is_admin is False: raise HTTPException(status_code=400, detail="Admin cannot remove their own admin status.")

    if user_in.username and user_in.username != db_user.username and crud.user.get_user_by_username(db, user_in.username):
        raise HTTPException(status_code=400, detail="Username already registered by another user.")
    if user_in.email and user_in.email != db_user.email and crud.user.get_user_by_email(db, user_in.email):
        raise HTTPException(status_code=400, detail="Email already registered by another user.")
    if user_in.email and user_in.email != db_user.email:
        try:
            disposable_email_service.check_email(db, user_in.email)
        except DisposableEmailBlocked:
            ip_addr = request.client.host if request.client else None
            security_event_logger.log_event(
                db=db,
                event_type=SecurityEventType.DISPOSABLE_EMAIL_BLOCKED,
                username=user_in.username or db_user.username,
                ip_address=ip_addr,
                details={"email": user_in.email, "domain": user_in.email.split("@")[-1].lower()},
            )
            raise HTTPException(status_code=400, detail="Disposable email addresses are not allowed")
        except DisposableEmailListUnavailable as exc:
            logger.error("Disposable email validation unavailable via API update: %s", exc)
            raise HTTPException(status_code=503, detail="Unable to validate email domain at this time")
            
    old_is_active = db_user.is_active
    old_is_admin = db_user.is_admin
    updated_user = crud.user.update_user(db=db, user_db=db_user, user_in=user_in)
    if user_in.is_admin is not None and user_in.is_admin != old_is_admin:
        log_admin_role_change(
            db, target_id=user_id, target_username=updated_user.username,
            granted=user_in.is_admin, actor=current_admin,
            ip_address=request.client.host if request.client else None, via="api_update",
        )
    if user_in.is_active is not None and user_in.is_active != old_is_active:
        try:
            ip_addr = request.client.host if request.client else None
            event_type = SecurityEventType.USER_ENABLED if user_in.is_active else SecurityEventType.USER_DISABLED
            security_event_logger.log_event(
                db=db, event_type=event_type,
                user_id=user_id, username=db_user.username,
                ip_address=ip_addr,
                details={"changed_by_admin": current_admin.username}
            )
        except Exception:
            pass
    return updated_user

@router.delete("/{user_id}", response_model=models_api.UserInfo)
async def delete_user_api(
    user_id: int, request: Request, db: Session = Depends(get_db),
    current_admin: models_db.User = Depends(require_admin_api_user)
):
    db_user = crud.user.get_user_by_id(db, user_id=user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    if crud.user.is_last_active_admin(db, db_user):
        raise HTTPException(status_code=400, detail="Cannot delete the last remaining admin account.")
    if db_user.id == current_admin.id:
        raise HTTPException(status_code=400, detail="Admin cannot delete themselves.")

    # Karto first, and only proceed if it confirmed — see the UI route for why the ORM
    # cascade makes this necessary. async for the same reason DELETE /vehicles is.
    try:
        await trigger_karto_deletion_for_user_vehicles(db, db_user, current_admin)
    except KartoDeletionFailed as e:
        logger.error(f"Aborting deletion of user '{db_user.username}': {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Trip data could not be deleted right now, so the account was kept. Please retry.",
        )

    deleted_user_id = db_user.id
    deleted_username = db_user.username
    deleted_user_obj = crud.user.delete_user(db, user_id=user_id)
    if not deleted_user_obj:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Cannot delete user {db_user.username}. They may own associated data.")
    try:
        ip_addr = request.client.host if request.client else None
        security_event_logger.log_event(
            db=db, event_type=SecurityEventType.USER_DELETED,
            user_id=deleted_user_id, username=deleted_username,
            ip_address=ip_addr,
            details={"deleted_by_admin": current_admin.username}
        )
    except Exception:
        pass
    return deleted_user_obj

@me_router.put("/me/password", status_code=status.HTTP_204_NO_CONTENT)
def update_current_user_password_api(
    password_update: models_api.UserPasswordUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user),
):
    if not verify_password(password_update.current_password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect current password")

    user_in_update = models_api.UserUpdate(password=password_update.new_password)
    crud.user.update_user(db=db, user_db=current_user, user_in=user_in_update)
    try:
        ip_addr = request.client.host if request.client else None
        security_event_logger.log_event(
            db=db, event_type=SecurityEventType.PASSWORD_CHANGED,
            user_id=current_user.id, username=current_user.username,
            ip_address=ip_addr, details={"method": "api"}
        )
    except Exception:
        pass
