from sqlalchemy.orm import Session, joinedload
from typing import Optional, List

from app.models import db as models_db
from app.models import api as models_api
from app.utils.crypto import encrypt_data
import datetime

def get_auto_provision_profile(db: Session, ap_key: str) -> Optional[models_db.AutoProvisionProfile]:
    return db.query(models_db.AutoProvisionProfile).options(joinedload(models_db.AutoProvisionProfile.owner)).filter(
        models_db.AutoProvisionProfile.ap_key == ap_key,
        models_db.AutoProvisionProfile.is_active == True 
    ).first()

def get_auto_provision_profile_by_id(db: Session, profile_id: int) -> Optional[models_db.AutoProvisionProfile]:
    return db.query(models_db.AutoProvisionProfile).options(joinedload(models_db.AutoProvisionProfile.owner)).filter(models_db.AutoProvisionProfile.id == profile_id).first()

def get_all_auto_provision_profiles(db: Session, owner_id: Optional[int] = None, skip: int = 0, limit: int = 100) -> List[models_db.AutoProvisionProfile]:
    query = db.query(models_db.AutoProvisionProfile).options(joinedload(models_db.AutoProvisionProfile.owner))
    if owner_id:
        query = query.filter(models_db.AutoProvisionProfile.owner_id == owner_id)
    return query.order_by(models_db.AutoProvisionProfile.ap_key).offset(skip).limit(limit).all()

_AP_ENCRYPTED_FIELDS = {'target_server_password', 'target_module_password'}

def create_auto_provision_profile(db: Session, profile_in: models_api.AutoProvisionProfileCreate, owner_id: int) -> models_db.AutoProvisionProfile:
    db_profile_data = profile_in.model_dump(exclude={'owner_id'} | _AP_ENCRYPTED_FIELDS)
    db_profile_data['target_vehicle_id_str'] = db_profile_data.pop('target_vehicle_id', None)
    db_profile_data['owner_id'] = owner_id
    db_profile_data['created_at'] = datetime.datetime.now(datetime.timezone.utc)

    db_profile = models_db.AutoProvisionProfile(**db_profile_data)
    db_profile.target_server_password = encrypt_data(profile_in.target_server_password)
    db_profile.target_module_password = encrypt_data(profile_in.target_module_password) if profile_in.target_module_password else None
    db.add(db_profile)
    db.commit()
    db.refresh(db_profile)
    return db_profile

def update_auto_provision_profile(db: Session, profile_db: models_db.AutoProvisionProfile, profile_in: models_api.AutoProvisionProfileCreate) -> models_db.AutoProvisionProfile:
    update_data = profile_in.model_dump(exclude_unset=True, exclude={'owner_id'} | _AP_ENCRYPTED_FIELDS)
    if 'target_vehicle_id' in update_data:
        update_data['target_vehicle_id_str'] = update_data.pop('target_vehicle_id')
    for field, value in update_data.items():
        setattr(profile_db, field, value)
    if profile_in.target_server_password:
        profile_db.target_server_password = encrypt_data(profile_in.target_server_password)
    if 'target_module_password' in profile_in.model_fields_set:
        profile_db.target_module_password = encrypt_data(profile_in.target_module_password) if profile_in.target_module_password else None
    db.commit()
    db.refresh(profile_db)
    return profile_db

def delete_auto_provision_profile(db: Session, profile_id: int) -> Optional[models_db.AutoProvisionProfile]:
    db_profile = get_auto_provision_profile_by_id(db, profile_id)
    if db_profile:
        db.delete(db_profile)
        db.commit()
    return db_profile