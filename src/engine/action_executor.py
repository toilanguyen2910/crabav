"""
Action Executor - Executes approved threat actions with HMAC integrity protection
"""

from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path
import hashlib
import hmac
import secrets
import json

from ..enums import ActionType, Status
from ..models import ThreatReport, QuarantineRecord
from ..quarantine import QuarantineManager
from ..utils import get_logger

logger = get_logger("action_executor")

# ── HMAC Integrity Protection ────────────────────────────────────────
# The whitelist is signed with an HMAC key so malware can't silently
# add its own hash to the whitelist. If the signature doesn't verify
# on load, CrabAV rejects the whitelist and starts fresh.

_HMAC_KEY_FILE = Path("./data/.whitelist_key")
_HMAC_HASH = "sha256"
_SIG_PREFIX = "CRABAV_SIG_V1:"


def _get_hmac_key() -> bytes:
    """Load or create a per-installation HMAC key stored outside the whitelist."""
    _HMAC_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if _HMAC_KEY_FILE.exists():
        return _HMAC_KEY_FILE.read_bytes()
    key = secrets.token_bytes(32)
    _HMAC_KEY_FILE.write_bytes(key)
    # Restrict access on Unix; on Windows we hide it
    try:
        _HMAC_KEY_FILE.chmod(0o600)
    except Exception:
        pass
    return key


def _sign_whitelist(lines: set, key: bytes) -> str:
    """Produce HMAC-signed whitelist content."""
    normalized = "\n".join(sorted(lines)) + "\n"
    sig = hmac.new(key, normalized.encode("utf-8"), _HMAC_HASH).hexdigest()
    lines_with_sig = [f"{_SIG_PREFIX}{sig}"] + sorted(lines)
    return "\n".join(lines_with_sig) + "\n"


def _load_and_verify(path: Path, key: bytes) -> Optional[set]:
    """Load whitelist file and verify HMAC signature. Returns None if tampered."""
    if not path.exists():
        return set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except Exception as e:
        logger.error(f"Failed to read whitelist: {e}")
        return None

    lines = [l.strip() for l in raw.splitlines() if l.strip()]
    if not lines:
        return set()

    # Check for signature header
    sig_line = lines[0]
    if not sig_line.startswith(_SIG_PREFIX):
        logger.error(
            "WHITELIST INTEGRITY FAILED: no HMAC signature found. "
            "Whitelist may have been tampered with — rejecting."
        )
        return None

    expected_sig = sig_line[len(_SIG_PREFIX):]
    content_lines = sorted(lines[1:])  # the whitelist entries (sorted for canonical form)
    normalized = "\n".join(content_lines) + "\n"
    actual_sig = hmac.new(key, normalized.encode("utf-8"), _HMAC_HASH).hexdigest()

    if not hmac.compare_digest(expected_sig, actual_sig):
        logger.error(
            "WHITELIST INTEGRITY FAILED: HMAC mismatch! "
            "Whitelist has been tampered with — rejecting."
        )
        return None

    logger.info(f"Whitelist integrity verified ({len(content_lines)} entries)")
    return set(content_lines)

# ──────────────────────────────────────────────────────────────────────


class ActionExecutor:
    """
    Executes user-approved actions on threats

    Supported Actions:
    - Quarantine: Move file to isolated storage
    - Delete: Permanently remove file (with backup)
    - Whitelist: Add to exception list
    - Restore: Restore from quarantine
    """

    def __init__(
        self,
        quarantine_manager: QuarantineManager,
        whitelist_path: str = "./data/whitelist.txt"
    ):
        self.quarantine = quarantine_manager
        self.whitelist_path = Path(whitelist_path)
        self._hmac_key = _get_hmac_key()
        self.whitelist: set = self._load_whitelist()

        logger.info("ActionExecutor initialized")

    def _load_whitelist(self) -> set:
        """Load whitelist from file with HMAC integrity verification."""
        whitelist = _load_and_verify(self.whitelist_path, self._hmac_key)
        if whitelist is None:
            logger.warning(
                "Whitelist integrity check FAILED — starting with empty whitelist"
            )
            return set()
        return whitelist

    def _save_whitelist(self) -> bool:
        """Save whitelist to file with HMAC signature."""
        try:
            self.whitelist_path.parent.mkdir(parents=True, exist_ok=True)
            signed_content = _sign_whitelist(self.whitelist, self._hmac_key)
            self.whitelist_path.write_text(signed_content, encoding="utf-8")
            return True
        except Exception as e:
            logger.error(f"Failed to save whitelist: {e}")
            return False

    def execute_action(
        self,
        action: ActionType,
        threat_report: ThreatReport
    ) -> Dict[str, Any]:
        """
        Execute an approved action

        Args:
            action: Action to execute
            threat_report: Threat report with file details

        Returns:
            Result dict with success status and details
        """
        logger.info(
            f"Executing {action.value} on {threat_report.threat_name} "
            f"(file: {threat_report.file_path})"
        )

        result = {
            'action': action.value,
            'threat_id': threat_report.threat_id,
            'success': False,
            'timestamp': datetime.now().isoformat(),
            'details': {}
        }

        try:
            if action == ActionType.QUARANTINE:
                result.update(self._execute_quarantine(threat_report))

            elif action == ActionType.DELETE:
                result.update(self._execute_delete(threat_report))

            elif action == ActionType.WHITELIST:
                result.update(self._execute_whitelist(threat_report))

            elif action == ActionType.RESTORE:
                result.update(self._execute_restore(threat_report))

            else:
                result['details']['error'] = f"Unknown action: {action}"

        except Exception as e:
            logger.error(f"Action execution failed: {e}")
            result['details']['error'] = str(e)

        return result

    def _execute_quarantine(self, threat_report: ThreatReport) -> Dict[str, Any]:
        """Quarantine a file"""
        file_path = threat_report.file_path

        if not Path(file_path).exists():
            return {
                'success': False,
                'details': {'error': 'File not found'}
            }

        # Move to quarantine
        record = self.quarantine.quarantine_file(
            file_path=file_path,
            threat_id=threat_report.threat_id,
            reason=f"Threat: {threat_report.threat_name}, Risk: {threat_report.risk_score}"
        )

        if record:
            logger.info(f"Successfully quarantined: {record.quarantine_id}")
            return {
                'success': True,
                'details': {
                    'quarantine_id': record.quarantine_id,
                    'original_path': record.original_path,
                    'quarantined_path': record.quarantined_path,
                    'backup_path': record.backup_path
                }
            }
        else:
            return {
                'success': False,
                'details': {'error': 'Quarantine operation failed'}
            }

    def _execute_delete(self, threat_report: ThreatReport) -> Dict[str, Any]:
        """Delete a file"""
        file_path = threat_report.file_path

        if not Path(file_path).exists():
            return {
                'success': False,
                'details': {'error': 'File not found'}
            }

        # First quarantine, then delete
        record = self.quarantine.quarantine_file(
            file_path=file_path,
            threat_id=threat_report.threat_id,
            reason=f"DELETE action: {threat_report.threat_name}"
        )

        if record:
            # Delete from quarantine
            deleted = self.quarantine.delete_quarantined_file(record.quarantine_id)

            if deleted:
                logger.info(f"Successfully deleted: {file_path}")
                return {
                    'success': True,
                    'details': {
                        'deleted_path': file_path,
                        'backup_kept': record.backup_path
                    }
                }

        return {
            'success': False,
            'details': {'error': 'Delete operation failed'}
        }

    def _execute_whitelist(self, threat_report: ThreatReport) -> Dict[str, Any]:
        """Add file to whitelist with HMAC signature protection"""
        file_path = threat_report.file_path
        file_hash = threat_report.file_hash

        # Add by hash for security
        if file_hash:
            self.whitelist.add(file_hash)
            self._save_whitelist()

            logger.info(f"Added to whitelist: {file_hash} ({file_path})")
            return {
                'success': True,
                'details': {
                    'whitelisted': file_hash,
                    'file_path': file_path
                }
            }
        else:
            return {
                'success': False,
                'details': {'error': 'File hash not available'}
            }

    def _execute_restore(self, threat_report: ThreatReport) -> Dict[str, Any]:
        """Restore file from quarantine"""
        # Would need quarantine_id from threat report metadata
        quarantine_id = threat_report.metadata.get('quarantine_id')

        if not quarantine_id:
            return {
                'success': False,
                'details': {'error': 'Quarantine ID not found'}
            }

        original_path = threat_report.metadata.get('original_path')
        success = self.quarantine.restore_file(quarantine_id, original_path)

        if success:
            logger.info(f"Restored from quarantine: {quarantine_id}")
            return {
                'success': True,
                'details': {'quarantine_id': quarantine_id}
            }
        else:
            return {
                'success': False,
                'details': {'error': 'Restore operation failed'}
            }

    def is_whitelisted(self, file_hash: str) -> bool:
        """Check if file is whitelisted"""
        return file_hash in self.whitelist

    def get_statistics(self) -> Dict[str, Any]:
        """Get executor statistics"""
        return {
            'whitelist_entries': len(self.whitelist),
            'quarantine_size_bytes': self.quarantine.get_quarantine_size(),
            'quarantine_records': len(self.quarantine.get_quarantine_records())
        }
