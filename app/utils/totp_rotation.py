"""
TOTP key rotation utilities.

Handles transparent rotation of TOTP encryption keys without requiring
users to re-setup their 2FA.
"""
from sqlalchemy.orm import Session
from app.models.db import User
from app.utils.crypto import FernetCipher
from app.config import Settings
from typing import Dict, List, Any
import secrets
import base64


class TOTPKeyRotation:
    """Utilities for TOTP encryption key rotation."""

    def __init__(self, settings: Settings):
        """
        Initialize TOTP key rotation helper.

        Args:
            settings: Application settings with TOTP encryption keys
        """
        self.settings = settings
        self.available_keys = self._get_available_keys()

    def _get_available_keys(self) -> Dict[int, str]:
        """Get all available TOTP encryption keys from settings."""
        keys = {}

        # Primary key (version 1)
        if self.settings.TOTP_ENCRYPTION_KEY:
            keys[1] = self.settings.TOTP_ENCRYPTION_KEY

        # Additional versioned keys
        for version in range(2, 11):  # Support up to 10 versions
            key = getattr(self.settings, f"TOTP_ENCRYPTION_KEY_V{version}", None)
            if key:
                keys[version] = key

        return keys

    def get_available_versions(self) -> List[int]:
        """Get list of available key versions."""
        return sorted(self.available_keys.keys())

    def generate_new_key(self) -> str:
        """
        Generate a new Fernet-compatible encryption key.

        Returns:
            Base64-encoded 32-byte key
        """
        key_bytes = secrets.token_bytes(32)
        return base64.urlsafe_b64encode(key_bytes).decode('utf-8')

    def get_version_stats(self, db: Session) -> Dict[int, int]:
        """
        Get statistics on TOTP key version distribution.

        Args:
            db: Database session

        Returns:
            Dictionary mapping version -> user count
        """
        users = db.query(User).filter(
            User.is_totp_enabled == True,
            User.totp_key_version.isnot(None)
        ).all()

        stats = {}
        for user in users:
            version = user.totp_key_version or 1  # Default to v1 if not set
            stats[version] = stats.get(version, 0) + 1

        return stats

    def rotate_user_key(
        self,
        db: Session,
        user: User,
        target_version: int
    ) -> bool:
        """
        Rotate a single user's TOTP encryption key to a new version.

        The TOTP secret itself doesn't change, only the encryption key.

        Args:
            db: Database session
            user: User to rotate
            target_version: Target key version to rotate to

        Returns:
            True if successful, False otherwise
        """
        if not user.is_totp_enabled or not user.encrypted_totp_secret:
            return False  # Skip users without TOTP

        current_version = user.totp_key_version or 1
        if current_version == target_version:
            return False  # Already on target version

        # Get encryption keys
        current_key = self.available_keys.get(current_version)
        target_key = self.available_keys.get(target_version)

        if not current_key or not target_key:
            raise ValueError(f"Missing encryption key for version {current_version} or {target_version}")

        try:
            # Decrypt with current key
            current_cipher = FernetCipher(current_key)
            totp_secret = current_cipher.decrypt(user.encrypted_totp_secret)

            # Re-encrypt with target key
            target_cipher = FernetCipher(target_key)
            new_encrypted_secret = target_cipher.encrypt(totp_secret)

            # Update user record
            user.encrypted_totp_secret = new_encrypted_secret
            user.totp_key_version = target_version

            db.commit()
            return True

        except Exception as e:
            db.rollback()
            raise Exception(f"Failed to rotate key for user {user.username}: {str(e)}")

    def rotate_all_users(
        self,
        db: Session,
        target_version: int
    ) -> Dict[str, Any]:
        """
        Rotate all TOTP-enabled users to a specific key version.

        Args:
            db: Database session
            target_version: Target key version

        Returns:
            Dictionary with rotation statistics:
            - total: Total TOTP users
            - rotated: Successfully rotated
            - skipped: Already on target version
            - failed: Failed to rotate
            - errors: List of error messages
        """
        if target_version not in self.available_keys:
            raise ValueError(f"Target version {target_version} not available in settings")

        users = db.query(User).filter(
            User.is_totp_enabled == True,
            User.encrypted_totp_secret.isnot(None)
        ).all()

        stats = {
            "total": len(users),
            "rotated": 0,
            "skipped": 0,
            "failed": 0,
            "errors": []
        }

        for user in users:
            try:
                current_version = user.totp_key_version or 1

                if current_version == target_version:
                    stats["skipped"] += 1
                    continue

                if self.rotate_user_key(db, user, target_version):
                    stats["rotated"] += 1
                else:
                    stats["skipped"] += 1

            except Exception as e:
                stats["failed"] += 1
                stats["errors"].append(f"User {user.username}: {str(e)}")

        return stats

    def get_next_version_suggestion(self, db: Session) -> int:
        """
        Suggest the next version number for a new key.

        Args:
            db: Database session

        Returns:
            Suggested version number
        """
        current_versions = self.get_available_versions()
        if not current_versions:
            return 1

        # Find the next available version number
        max_version = max(current_versions)
        return max_version + 1

    def validate_rotation_safety(
        self,
        db: Session,
        target_version: int
    ) -> Dict[str, Any]:
        """
        Validate that rotation to target version is safe.

        Args:
            db: Database session
            target_version: Target version to validate

        Returns:
            Dictionary with validation results:
            - safe: bool
            - warnings: list of warning messages
            - errors: list of error messages
        """
        warnings = []
        errors = []

        # Check target key exists
        if target_version not in self.available_keys:
            errors.append(f"Target version {target_version} not configured in settings")

        # Check all current versions have keys available
        version_stats = self.get_version_stats(db)
        for version in version_stats.keys():
            if version not in self.available_keys:
                errors.append(f"Current version {version} is in use but key not available in settings")

        # Warn if rotating to older version
        current_versions = list(version_stats.keys())
        if current_versions and target_version < max(current_versions):
            warnings.append(f"Rotating to older version {target_version} (current max: {max(current_versions)})")

        return {
            "safe": len(errors) == 0,
            "warnings": warnings,
            "errors": errors
        }
