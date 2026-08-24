"""
Routes for serving .well-known files for WebAuthn/Passkey support.

These files are required for mobile apps to verify domain ownership
for WebAuthn/FIDO2 passkey authentication.
"""
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path
import logging

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Well-Known"])


@router.get("/.well-known/apple-app-site-association")
def apple_app_site_association():
    """
    Serve Apple App Site Association file for iOS passkeys.

    This file allows iOS apps to use WebAuthn/passkeys with this domain.
    Must be accessible at: https://yourdomain.com/.well-known/apple-app-site-association

    See: https://developer.apple.com/documentation/xcode/supporting-associated-domains
    """
    file_path = Path("app/static/.well-known/apple-app-site-association")

    if not file_path.exists():
        logger.warning(
            "apple-app-site-association file not found. "
            "Copy apple-app-site-association.example and configure it for iOS passkey support."
        )
        raise HTTPException(
            status_code=404,
            detail="Apple App Site Association file not configured. See documentation for setup."
        )

    return FileResponse(
        file_path,
        media_type="application/json",
        headers={
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
        }
    )


@router.get("/.well-known/assetlinks.json")
def assetlinks():
    """
    Serve Digital Asset Links file for Android passkeys.

    This file allows Android apps to use WebAuthn/passkeys with this domain.
    Must be accessible at: https://yourdomain.com/.well-known/assetlinks.json

    See: https://developer.android.com/training/app-links/verify-android-applinks
    """
    file_path = Path("app/static/.well-known/assetlinks.json")

    if not file_path.exists():
        logger.warning(
            "assetlinks.json file not found. "
            "Copy assetlinks.json.example and configure it for Android passkey support."
        )
        raise HTTPException(
            status_code=404,
            detail="Digital Asset Links file not configured. See documentation for setup."
        )

    return FileResponse(
        file_path,
        media_type="application/json",
        headers={
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
        }
    )
