from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List
import datetime

from app import crud
from app.models import api as models_api
from app.models import db as models_db
from app.database import get_db
from app.dependencies import require_active_api_user
from app.security_manager import security_manager

router = APIRouter(
    prefix="/apikeys", 
    tags=["API Key Management"],
    dependencies=[Depends(require_active_api_user)] 
)

@router.post("", response_model=models_api.ApiKeyCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key_for_current_user(
    request: Request,
    api_key_in: models_api.ApiKeyCreate,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user) 
):
    """
    Create a new API key for the currently authenticated user.
    The full API key is returned only once. Store it securely.
    """
    expires_delta = None
    if api_key_in.expires_in_days:
        expires_delta = datetime.timedelta(days=api_key_in.expires_in_days)
    
    try:
        db_api_key, plain_key = crud.apikey.create_api_key(
            db=db, 
            user_id=current_user.id, 
            name=api_key_in.name, 
            expires_delta=expires_delta
        )
    except ValueError as e:
        # Use client IP from request for rate limiting
        from app.dependencies import get_client_ip
        ip_addr = await get_client_ip(request)
        security_manager.record_failure(ip_addr, 'api_general')
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    
    return models_api.ApiKeyCreateResponse(
        id=db_api_key.id,
        name=db_api_key.name,
        key_prefix=db_api_key.key_prefix,
        created_at=db_api_key.created_at,
        expires_at=db_api_key.expires_at,
        last_used_at=db_api_key.last_used_at,
        is_active=db_api_key.is_active,
        full_key=plain_key
    )

@router.get("", response_model=List[models_api.ApiKeyInfo])
def list_api_keys_for_current_user(
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user)
):
    """
    List all API keys for the currently authenticated user.
    """
    api_keys_db = crud.apikey.get_api_keys_for_user(db, user_id=current_user.id)
    return api_keys_db

@router.delete("/{api_key_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_api_key_for_current_user(
    api_key_id: int,
    db: Session = Depends(get_db),
    current_user: models_db.User = Depends(require_active_api_user)
):
    """
    Delete an API key owned by the currently authenticated user.
    This effectively revokes the key.
    """
    api_key_to_delete = crud.apikey.get_api_key_by_id_and_user(db, api_key_id=api_key_id, user_id=current_user.id)
    if not api_key_to_delete:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API Key not found or not owned by user.")
    
    crud.apikey.delete_api_key_by_id_and_user(db, api_key_id=api_key_id, user_id=current_user.id)
    return None # HTTP 204 No Content
