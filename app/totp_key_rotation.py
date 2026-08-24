"""
TOTP Encryption Key Rotation

This module handles rotating the encryption key used for TOTP secrets
without requiring users to re-setup their 2FA.

The TOTP secret itself never changes - only the encryption key protecting it.
"""

import logging
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from cryptography.fernet import Fernet

from app.config import settings
from app.models import db as models_db

logger = logging.getLogger(__name__)


class TOTPKeyManager:
    """Manages TOTP encryption key rotation."""

    def __init__(self):
        # Support multiple encryption key versions
        self.encryption_keys: Dict[int, Fernet] = {}
        self._load_keys()

    def _load_keys(self):
        """Load all encryption keys from settings."""
        # Primary key (current)
        try:
            primary_key = settings.TOTP_ENCRYPTION_KEY.encode('utf-8')
            self.encryption_keys[1] = Fernet(primary_key)
        except Exception as e:
            logger.error(f"Failed to load primary TOTP encryption key: {e}")
            raise

        # Load additional keys for rotation (if configured)
        # V2 key for rotation
        if hasattr(settings, 'TOTP_ENCRYPTION_KEY_V2') and settings.TOTP_ENCRYPTION_KEY_V2:
            try:
                v2_key = settings.TOTP_ENCRYPTION_KEY_V2.encode('utf-8')
                self.encryption_keys[2] = Fernet(v2_key)
                logger.info("TOTP encryption key v2 loaded for rotation")
            except Exception as e:
                logger.warning(f"Failed to load TOTP encryption key v2: {e}")

    def encrypt_totp_secret(self, secret: str, key_version: int = 1) -> tuple[bytes, int]:
        """
        Encrypt TOTP secret with specified key version.

        Args:
            secret: The TOTP secret to encrypt
            key_version: Which key version to use (default: latest)

        Returns:
            Tuple of (encrypted_data, key_version_used)
        """
        if key_version not in self.encryption_keys:
            # Fall back to primary key
            key_version = 1

        fernet = self.encryption_keys[key_version]
        encrypted = fernet.encrypt(secret.encode('utf-8'))
        return encrypted, key_version

    def decrypt_totp_secret(self, encrypted_data: bytes, key_version: int = 1) -> str:
        """
        Decrypt TOTP secret using specified key version.

        Args:
            encrypted_data: The encrypted TOTP secret
            key_version: Which key version was used for encryption

        Returns:
            Decrypted TOTP secret

        Raises:
            ValueError: If decryption fails or key version not found
        """
        if key_version not in self.encryption_keys:
            raise ValueError(f"Encryption key version {key_version} not found")

        fernet = self.encryption_keys[key_version]
        try:
            decrypted = fernet.decrypt(encrypted_data)
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to decrypt TOTP secret with key v{key_version}: {e}")
            raise ValueError(f"Decryption failed: {e}")

    def rotate_user_key(
        self,
        db: Session,
        user: models_db.User,
        target_version: int = 2
    ) -> bool:
        """
        Rotate a single user's TOTP encryption to new key version.

        Args:
            db: Database session
            user: User to rotate
            target_version: Target key version (default: 2)

        Returns:
            True if successful, False otherwise
        """
        if not user.is_totp_enabled or not user.encrypted_totp_secret:
            logger.debug(f"User {user.username} has no TOTP to rotate")
            return False

        if target_version not in self.encryption_keys:
            logger.error(f"Target key version {target_version} not available")
            return False

        try:
            # Get current key version (default to 1 if not set)
            current_version = getattr(user, 'totp_key_version', 1) or 1

            if current_version == target_version:
                logger.debug(f"User {user.username} already on key version {target_version}")
                return True

            # Decrypt with old key
            totp_secret = self.decrypt_totp_secret(
                user.encrypted_totp_secret,
                current_version
            )

            # Re-encrypt with new key
            new_encrypted, new_version = self.encrypt_totp_secret(
                totp_secret,
                target_version
            )

            # Update user record
            user.encrypted_totp_secret = new_encrypted
            user.totp_key_version = new_version
            db.commit()

            logger.info(
                f"Rotated TOTP key for user {user.username} "
                f"from v{current_version} to v{new_version}"
            )
            return True

        except Exception as e:
            db.rollback()
            logger.error(f"Failed to rotate TOTP key for user {user.username}: {e}")
            return False

    def rotate_all_users(
        self,
        db: Session,
        target_version: int = 2
    ) -> Dict[str, int]:
        """
        Rotate TOTP encryption keys for all users.

        Args:
            db: Database session
            target_version: Target key version

        Returns:
            Dictionary with rotation statistics
        """
        stats = {
            "total": 0,
            "rotated": 0,
            "skipped": 0,
            "failed": 0,
            "errors": []
        }

        users_with_totp = db.query(models_db.User).filter(
            models_db.User.is_totp_enabled == True
        ).all()

        stats["total"] = len(users_with_totp)

        for user in users_with_totp:
            try:
                if self.rotate_user_key(db, user, target_version):
                    stats["rotated"] += 1
                else:
                    stats["skipped"] += 1
            except Exception as e:
                stats["failed"] += 1
                stats["errors"].append(f"{user.username}: {str(e)}")
                logger.error(f"Error rotating user {user.username}: {e}")

        logger.info(
            f"TOTP key rotation complete: {stats['rotated']} rotated, "
            f"{stats['skipped']} skipped, {stats['failed']} failed"
        )

        return stats

    def generate_new_key(self) -> str:
        """
        Generate a new Fernet encryption key for rotation.

        Returns:
            Base64-encoded Fernet key suitable for .env file
        """
        new_key = Fernet.generate_key()
        return new_key.decode('utf-8')


# Global instance
totp_key_manager = TOTPKeyManager()


def get_decrypted_totp_secret_with_rotation(user: models_db.User) -> Optional[str]:
    """
    Deprecated alias for crud.user.get_decrypted_totp_secret_for_user().

    This function used to be the only key-version-aware reader, but nothing called
    it — the login path went through crud.user, which was not version aware. That
    split is exactly what made the rotation button a 2FA lockout. Rather than keep
    two implementations that can drift apart again, the version handling now lives
    in crud.user and this delegates to it.
    """
    from app.crud import user as user_crud

    return user_crud.get_decrypted_totp_secret_for_user(user)


def find_users_with_unavailable_keys(db: Session) -> List[str]:
    """
    Usernames whose TOTP secret is encrypted with a key this process cannot load.

    A rotation to v2 followed by a deployment that forgot TOTP_ENCRYPTION_KEY_V2
    leaves those users unable to log in, and nothing in the normal flow reports it
    until they try. Called at startup so the condition is visible in the log rather
    than discovered by a locked-out user.
    """
    affected = []
    users = db.query(models_db.User).filter(
        models_db.User.is_totp_enabled == True,  # noqa: E712 - SQLAlchemy column comparison
        models_db.User.encrypted_totp_secret != None,  # noqa: E711
    ).all()
    for user in users:
        key_version = getattr(user, "totp_key_version", None) or 1
        if key_version not in totp_key_manager.encryption_keys:
            affected.append(user.username)
    return affected
