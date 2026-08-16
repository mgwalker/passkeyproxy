import json
import os
from datetime import datetime
from pathlib import Path

from webauthn.helpers import bytes_to_base64url

from lib.config import CONFIG
from lib.logger import logger
from lib.util import format_credential_id


class _CredentialStore:
    """Manages credential storage in JSON file"""

    def __init__(self, filepath: str):
        self.filepath = Path(filepath)
        self.credentials: list[dict] = []
        self._load()

    def _load(self):
        """Load credentials from file"""
        if self.filepath.exists():
            try:
                with open(self.filepath) as f:
                    data = json.load(f)
                    self.credentials = data.get("credentials", [])
            except Exception as e:
                logger.error(f"Failed to load credentials: {e}")
                self.credentials = []
        else:
            self.credentials = []

    def _save(self):
        """Save credentials to file"""
        try:
            self.filepath.parent.mkdir(parents=True, exist_ok=True)
            with open(self.filepath, "w") as f:
                json.dump({"credentials": self.credentials}, f, indent=2)
            os.chmod(self.filepath, 0o600)
        except Exception as e:
            logger.error(f"Failed to save credentials: {e}")

    def is_empty(self) -> bool:
        """Check if there are no credentials"""
        return len(self.credentials) == 0

    def add_credential(
        self,
        credential_id: bytes,
        public_key: bytes,
        username: str,
        sign_count: int,
        credential_data: dict,
    ):
        """Add a new credential"""
        cred_id_b64 = bytes_to_base64url(credential_id)
        self.credentials.append(
            {
                "id": cred_id_b64,
                "public_key": bytes_to_base64url(public_key),
                "sign_count": sign_count,
                "username": username,
                "credential_data": credential_data,
                "created_at": datetime.utcnow().isoformat(),
            }
        )
        self._save()
        cred = format_credential_id(cred_id_b64)
        logger.info(f"Credential stored for user '{username}' (credential: {cred})")

    def get_all_credentials(self) -> list[dict]:
        """Get all credentials for authentication"""
        return self.credentials

    def get_credential_by_id(self, credential_id: bytes) -> dict | None:
        """Find credential by ID"""
        cred_id_b64 = bytes_to_base64url(credential_id)
        for cred in self.credentials:
            if cred["id"] == cred_id_b64:
                return cred
        return None

    def update_sign_count(self, credential_id: bytes, sign_count: int):
        """Update sign count for a credential"""
        cred = self.get_credential_by_id(credential_id)
        if cred:
            old_count = cred["sign_count"]
            cred["sign_count"] = sign_count
            self._save()
            logger.info(
                f"Sign count updated for user '{cred['username']}' (credential: {format_credential_id(cred['id'])}, count: {sign_count})"  # noqa: E501
            )

            # Check for sign count anomaly (possible credential cloning)
            # Only check if both old and new counts are non-zero (authenticator
            # supports sign count) Per WebAuthn spec, sign_count=0 means "not
            # supported"
            if old_count > 0 and sign_count > 0 and sign_count <= old_count:
                logger.warning(
                    f"Sign count anomaly for user '{cred['username']}' (expected > {old_count}, got {sign_count}) - possible credential cloning"  # noqa: E501
                )


cred_store = _CredentialStore(CONFIG["CREDENTIALS_FILE"])
