from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
import datetime

from app import crud
from app.models import api as models_api, db as models_db
from app.database import get_db
from app.dependencies import require_current_user_from_cookie_fully_authenticated

router = APIRouter(
    tags=["WebSocket Support API"],
)

@router.get("/ws-ticket", response_model=models_api.WsTicketResponse, name="api_get_ws_ticket")
def get_websocket_ticket(
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_current_user_from_cookie_fully_authenticated)
):
    """
    Issues a short-lived (60-second) API key (ticket) for authenticating WebSocket connections.
    Requires a fully authenticated session (including 2FA if enabled).
    """
    key_name = f"ws-ticket-{current_user.username}-{datetime.datetime.now(datetime.timezone.utc).timestamp()}"
    expires_delta = datetime.timedelta(minutes=1)
    
    db_api_key, plain_key = crud.apikey.create_api_key(
        db=db,
        user_id=current_user.id,
        name=key_name,
        expires_delta=expires_delta,
        # Server plumbing: exempt from the quota and hidden from the profile page.
        purpose=crud.apikey.KeyPurpose.INTERNAL,
    )
    
    return models_api.WsTicketResponse(
        app_ws_ticket=plain_key,
        mqtt_username=db_api_key.key_prefix,
        mqtt_password=plain_key
    )