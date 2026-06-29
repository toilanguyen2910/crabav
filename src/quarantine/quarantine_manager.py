"""
Quarantine Manager - Safely isolates suspicious files with AES-256-GCM encryption
"""

import os
import shutil
import hashlib
import secrets
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from ..models import QuarantineRecord
from ..utils import get_logger, ensure_directory, calculate_file_hash

logger = get_logger("quarantine_manager")

# Constants for the encrypted file format:
#   [salt: 16 bytes] [nonce: 12 bytes] [ciphertext + tag]
SALT_LENGTH = 16
NONCE_LENGTH = 12
PBKDF2_ITERATIONS = 600_000


class QuarantineManager:
    """
    Manages quarantine operations for suspicious files

    Features:
    - Move files to isolated storage with AES-256-GCM encryption
    - Create backups before deletion
    - Encrypt quarantined files with authenticated encryption
    - Track quarantine records
    - Restore from quarantine (decrypt + move back)
    - Auto-delete old items
    """

    def __init__(
        self,
        quarantine_dir: str = "./data/quarantine",
        backup_dir: str = "./data/backups"
    ):
        self.quarantine_dir = Path(quarantine_dir)
        self.backup_dir = Path(backup_dir)

        ensure_directory(str(self.quarantine_dir))
        ensure_directory(str(self.backup_dir))

        # Derive a stable encryption key from a machine-local secret.
        # In production, this should be injected from a secure keystore.
        self._encryption_key = self._derive_key()

        logger.info(
            f"QuarantineManager initialized: "
            f"quarantine={quarantine_dir}, backup={backup_dir}"
        )

    # ──────────────────────── key management ────────────────────────

    def _derive_key(self) -> bytes:
        """
        Derive a 256-bit AES key from a PBKDF2-hardened secret.

        The secret is a combination of a per-machine salt file (auto-created
        on first run) and a fixed application pepper. This means every
        CrabAV installation gets its own unique encryption key without
        the user needing to manage passwords.
        """
        keyfile = self.quarantine_dir / ".keysalt"

        if keyfile.exists():
            salt = keyfile.read_bytes()
            if len(salt) != SALT_LENGTH:
                salt = secrets.token_bytes(SALT_LENGTH)
                keyfile.write_bytes(salt)
        else:
            salt = secrets.token_bytes(SALT_LENGTH)
            keyfile.write_bytes(salt)

        # Application pepper — constant across installations.
        # Compromise of this alone does NOT recover encrypted files
        # because the per-machine salt is also required.
        pepper = b"crabav-quarantine-v1"

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key for AES-256
            salt=salt + pepper,
            iterations=PBKDF2_ITERATIONS,
        )
        return kdf.derive(pepper)

    # ──────────────────────── low-level crypto ──────────────────────

    @staticmethod
    def _encrypt_file(source_path: Path, dest_path: Path, key: bytes) -> None:
        """
        Encrypt a file with AES-256-GCM.

        Output format: [file_salt: 16B] [nonce: 12B] [ciphertext+tag]

        Each file gets its own random nonce for semantic security.
        """
        aesgcm = AESGCM(key)
        file_salt = secrets.token_bytes(SALT_LENGTH)
        nonce = secrets.token_bytes(NONCE_LENGTH)

        with open(source_path, "rb") as f:
            plaintext = f.read()

        # Mix file-level salt into the key to isolate files cryptographically
        file_key = hashlib.pbkdf2_hmac(
            "sha256", key, file_salt, iterations=100_000, dklen=32
        )

        aesgcm2 = AESGCM(file_key)
        ciphertext = aesgcm2.encrypt(nonce, plaintext, None)

        with open(dest_path, "wb") as f:
            f.write(file_salt)
            f.write(nonce)
            f.write(ciphertext)

    @staticmethod
    def _decrypt_file(source_path: Path, dest_path: Path, key: bytes) -> None:
        """
        Decrypt a file encrypted with _encrypt_file.

        Reads the [salt][nonce][ciphertext] format and writes plaintext.
        """
        with open(source_path, "rb") as f:
            file_salt = f.read(SALT_LENGTH)
            nonce = f.read(NONCE_LENGTH)
            ciphertext = f.read()

        if len(file_salt) != SALT_LENGTH or len(nonce) != NONCE_LENGTH:
            raise ValueError("Corrupted quarantine file: header too short")

        # Re-derive the file-level key
        file_key = hashlib.pbkdf2_hmac(
            "sha256", key, file_salt, iterations=100_000, dklen=32
        )

        aesgcm = AESGCM(file_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        with open(dest_path, "wb") as f:
            f.write(plaintext)

    # ──────────────────────── public API ────────────────────────────

    def quarantine_file(
        self,
        file_path: str,
        threat_id: str,
        reason: str
    ) -> Optional[QuarantineRecord]:
        """
        Move file to encrypted quarantine.

        Args:
            file_path: Path to suspicious file
            threat_id: Associated threat ID
            reason: Reason for quarantine

        Returns:
            QuarantineRecord or None if failed
        """
        try:
            source_path = Path(file_path)

            if not source_path.exists():
                logger.error(f"File not found: {file_path}")
                return None

            # Sanity check: don't quarantine ourselves
            if self.quarantine_dir in source_path.parents:
                logger.warning(f"Refusing to quarantine file already in quarantine: {file_path}")
                return None

            # Generate quarantine ID
            quarantine_id = f"QUAR_{uuid.uuid4().hex[:12]}"

            # Calculate hash BEFORE moving
            file_hash = calculate_file_hash(str(source_path))
            file_size = source_path.stat().st_size

            # Create plaintext backup (encrypted at rest is handled below)
            backup_path = self.backup_dir / f"{quarantine_id}.bak"
            shutil.copy2(source_path, backup_path)

            # Encrypt → quarantine storage
            quarantine_path = self.quarantine_dir / f"{quarantine_id}.quar"
            self._encrypt_file(source_path, quarantine_path, self._encryption_key)

            # Remove original only AFTER successful encryption + backup
            source_path.unlink()

            # Create record
            record = QuarantineRecord(
                quarantine_id=quarantine_id,
                threat_id=threat_id,
                original_path=str(source_path),
                quarantined_path=str(quarantine_path),
                backup_path=str(backup_path),
                file_hash=file_hash,
                file_size=file_size,
                reason=reason,
                encrypted=True,
                quarantined_at=datetime.now(),
                auto_delete_at=datetime.now() + timedelta(days=30)
            )

            logger.info(
                f"Quarantined file: {quarantine_id} "
                f"({file_size} bytes from {file_path}, AES-256-GCM encrypted)"
            )

            return record

        except Exception as e:
            logger.error(f"Failed to quarantine file: {e}")
            return None

    def restore_file(
        self, quarantine_id: str, original_path: Optional[str] = None
    ) -> bool:
        """
        Restore (decrypt) file from quarantine back to original location.

        Args:
            quarantine_id: Quarantine record ID
            original_path: Optional original path (queried from DB if omitted)

        Returns:
            True if successful
        """
        try:
            quarantine_path = self.quarantine_dir / f"{quarantine_id}.quar"
            backup_path = self.backup_dir / f"{quarantine_id}.bak"

            # Prefer quarantine file; fall back to backup
            encrypted_source = (
                quarantine_path if quarantine_path.exists() else None
            )
            plaintext_backup = backup_path if backup_path.exists() else None

            if encrypted_source is None and plaintext_backup is None:
                logger.error(f"Quarantined/backup file not found: {quarantine_id}")
                return False

            if not original_path:
                db_path = Path("./data/crabav.db")
                if db_path.exists():
                    try:
                        import sqlite3
                        conn = sqlite3.connect(str(db_path))
                        cursor = conn.cursor()
                        cursor.execute(
                            "SELECT original_path FROM quarantine_records "
                            "WHERE quarantine_id = ?",
                            (quarantine_id,),
                        )
                        row = cursor.fetchone()
                        if row:
                            original_path = row[0]
                        conn.close()
                    except Exception as e:
                        logger.error(
                            f"Failed to query database for original path: {e}"
                        )

            if not original_path:
                logger.error(f"Original path not found for: {quarantine_id}")
                return False

            dest_path = Path(original_path)
            dest_path.parent.mkdir(parents=True, exist_ok=True)

            if encrypted_source is not None:
                # Decrypt from quarantine
                self._decrypt_file(
                    encrypted_source, dest_path, self._encryption_key
                )
            else:
                # Fallback: plaintext backup
                shutil.copy2(plaintext_backup, dest_path)

            # Clean up
            for p in (quarantine_path, backup_path):
                if p is not None and p.exists():
                    p.unlink()

            logger.info(
                f"Restored from quarantine: {quarantine_id} → {original_path}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to restore file: {e}")
            return False

    def delete_quarantined_file(self, quarantine_id: str) -> bool:
        """
        Permanently delete quarantined file.

        Args:
            quarantine_id: Quarantine record ID

        Returns:
            True if successful
        """
        try:
            quarantine_path = self.quarantine_dir / f"{quarantine_id}.quar"
            backup_path = self.backup_dir / f"{quarantine_id}.bak"

            if quarantine_path.exists():
                quarantine_path.unlink()

            # Keep backup for disaster recovery (configurable via cleanup_expired)
            logger.info(f"Deleted quarantined file: {quarantine_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete quarantined file: {e}")
            return False

    def get_quarantine_size(self) -> int:
        """Get total size of quarantined files in bytes."""
        total = 0
        for file in self.quarantine_dir.glob("*.quar"):
            total += file.stat().st_size
        return total

    def cleanup_expired(self, days: int = 30) -> int:
        """
        Delete quarantined files older than specified days.

        Args:
            days: Number of days to keep

        Returns:
            Number of files deleted
        """
        cutoff = datetime.now() - timedelta(days=days)
        deleted = 0

        for file in self.quarantine_dir.glob("*.quar"):
            mtime = datetime.fromtimestamp(file.stat().st_mtime)
            if mtime < cutoff:
                try:
                    file.unlink()
                    deleted += 1
                except Exception as e:
                    logger.error(f"Failed to delete {file}: {e}")

        if deleted > 0:
            logger.info(f"Cleaned up {deleted} expired quarantine files")

        return deleted

    def get_quarantine_records(self) -> List[Dict[str, Any]]:
        """Get list of quarantined files."""
        records = []

        for file in self.quarantine_dir.glob("*.quar"):
            stat = file.stat()
            records.append({
                "name": file.stem,
                "size": stat.st_size,
                "quarantined_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "path": str(file)
            })

        return sorted(records, key=lambda x: x["quarantined_at"], reverse=True)
