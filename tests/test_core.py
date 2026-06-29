"""
Unit tests for CrabAV components
"""

import pytest
import asyncio
from pathlib import Path
from datetime import datetime


# ── Decision Engine ────────────────────────────────────────────

def test_threat_scorer():
    from src.decision import ThreatScorer
    from src.enums import AgentType, ThreatLevel, FindingType
    from src.models import ThreatFinding

    scorer = ThreatScorer()

    finding = ThreatFinding(
        agent_id="test_agent",
        agent_type=AgentType.SCANNER,
        finding_type=FindingType.FILE_SIGNATURE,
        threat_name="Test.Threat",
        threat_level=ThreatLevel.HIGH,
        confidence=0.9,
        evidence={"test": "data"},
        recommended_actions=[],
        metadata={}
    )

    score = scorer.calculate_score([finding])
    assert 0 <= score <= 100
    assert score > 50  # High confidence should give high score


# ── Approval Handler ───────────────────────────────────────────

def test_approval_handler():
    from src.approval import ApprovalHandler
    from src.enums import ActionType

    handler = ApprovalHandler()

    request = handler.generate_request(
        threat_id="test_threat",
        threat_name="Test Threat",
        file_path="/test/path",
        risk_score=75.0,
        threat_level="HIGH",
        recommended_actions=[ActionType.QUARANTINE],
        source_agent="test"
    )

    assert request.request_id is not None
    assert request.is_pending()
    assert not request.is_expired()

    result = handler.approve(
        request.request_id,
        ActionType.QUARANTINE,
        "test_user"
    )

    assert result.approved is True
    assert result.approved_action == ActionType.QUARANTINE


# ── Quarantine Manager (basic) ─────────────────────────────────

def test_quarantine_manager(tmp_path):
    from src.quarantine import QuarantineManager

    quar_dir = tmp_path / "quarantine"
    backup_dir = tmp_path / "backup"

    manager = QuarantineManager(
        quarantine_dir=str(quar_dir)
    )

    test_file = tmp_path / "test.txt"
    test_file.write_text("test content")

    record = manager.quarantine_file(
        file_path=str(test_file),
        threat_id="test_threat",
        reason="Test quarantine"
    )

    assert record is not None
    assert not test_file.exists()  # Original removed
    assert Path(record.quarantined_path).exists()


# ── Quarantine: AES-256-GCM encryption ─────────────────────────

def test_quarantine_file_is_encrypted(tmp_path):
    """
    Verify quarantined files are ACTUALLY encrypted — the .quar file must
    NOT contain the original plaintext and must be different from the backup.
    """
    from src.quarantine import QuarantineManager

    quar_dir = tmp_path / "quarantine"
    backup_dir = tmp_path / "backup"

    manager = QuarantineManager(
        quarantine_dir=str(quar_dir)
    )

    original_content = b"TOP SECRET: password=12345"
    test_file = tmp_path / "secret.txt"
    test_file.write_bytes(original_content)

    record = manager.quarantine_file(
        file_path=str(test_file),
        threat_id="test_threat",
        reason="Test encryption"
    )

    assert record is not None

    # The .quar file should NOT contain the original plaintext
    quar_path = Path(record.quarantined_path)
    assert quar_path.exists()
    quar_data = quar_path.read_bytes()
    assert original_content not in quar_data, (
        "QUARANTINE FILE IS NOT ENCRYPTED — plaintext found in .quar!"
    )


def test_quarantine_encrypt_decrypt_roundtrip(tmp_path):
    """
    Full roundtrip: encrypt → decrypt → verify content matches exactly.
    """
    from src.quarantine import QuarantineManager

    quar_dir = tmp_path / "quarantine"
    backup_dir = tmp_path / "backup"

    manager = QuarantineManager(
        quarantine_dir=str(quar_dir)
    )

    # Use binary data to verify no corruption
    original_content = bytes(range(256)) * 4  # 1 KB of varied data
    original_path = tmp_path / "data.bin"
    original_path.write_bytes(original_content)

    # Quarantine it
    record = manager.quarantine_file(
        file_path=str(original_path),
        threat_id="test_threat",
        reason="Roundtrip test"
    )

    assert record is not None
    assert not original_path.exists()

    # Restore it to a new location
    restored_path = tmp_path / "restored.bin"
    success = manager.restore_file(
        record.quarantine_id,
        original_path=str(restored_path)
    )

    assert success, "restore_file returned False"
    assert restored_path.exists(), "Restored file does not exist"

    restored_content = restored_path.read_bytes()
    assert restored_content == original_content, (
        f"Roundtrip failed: restored content differs! "
        f"original={len(original_content)}B, restored={len(restored_content)}B"
    )

    # Quarantine files should be cleaned up after restore
    assert not Path(record.quarantined_path).exists(), (
        "Quarantine file not cleaned up after restore"
    )


def test_quarantine_deterministic_content(tmp_path):
    """
    Verify that encrypting the same content twice produces different
    ciphertexts (random nonce per encryption).
    """
    from src.quarantine import QuarantineManager

    quar_dir = tmp_path / "q"
    backup_dir = tmp_path / "b"

    original_content = b"same content"

    # Quarantine same content twice
    records = []
    for i in range(2):
        manager = QuarantineManager(
            quarantine_dir=str(quar_dir)
        )
        f = tmp_path / f"same_{i}.txt"
        f.write_bytes(original_content)
        rec = manager.quarantine_file(
            file_path=str(f), threat_id="t", reason="determinism test"
        )
        assert rec is not None
        records.append(rec)

    # Both should exist (different quarantine IDs)
    q1 = Path(records[0].quarantined_path).read_bytes()
    q2 = Path(records[1].quarantined_path).read_bytes()

    # Ciphertexts must differ (random nonces ensure this)
    assert q1 != q2, (
        "Identical plaintext produced identical ciphertext — nonce reuse risk!"
    )


# ── Path Validation: Security ──────────────────────────────────

def test_validate_scan_path_normal():
    """Normal paths should resolve without error."""
    from src.utils import validate_scan_path

    result = validate_scan_path("C:\\Users")
    assert result is not None
    assert result.exists()


def test_validate_scan_path_traversal_blocked():
    """Path traversal with ../ should raise ValueError."""
    from src.utils import validate_scan_path

    with pytest.raises(ValueError, match="Path traversal"):
        validate_scan_path("C:\\Users\\..\\..\\Windows\\System32")


def test_validate_scan_path_null_byte():
    """Null byte injection should raise ValueError."""
    from src.utils import validate_scan_path

    with pytest.raises(ValueError, match="null byte"):
        validate_scan_path("C:\\Users\x00\\secret")


def test_validate_scan_path_url_encoded_traversal():
    """URL-encoded path traversal should be caught."""
    from src.utils import validate_scan_path

    with pytest.raises(ValueError, match="Path traversal"):
        validate_scan_path("C:\\Users\\..%2f..%2fWindows")


def test_validate_subprocess_arg_rejects_shell_chars():
    """Dangerous shell characters in subprocess args should raise."""
    from src.utils import validate_subprocess_arg

    # Valid
    assert validate_subprocess_arg("C:\\Users\\test") is not None

    # Invalid — semicolon
    with pytest.raises(ValueError, match="dangerous shell character"):
        validate_subprocess_arg("foo; rm -rf /")

    # Invalid — pipe
    with pytest.raises(ValueError, match="dangerous shell character"):
        validate_subprocess_arg("foo | cat /etc/passwd")


# ── HMAC Whitelist Integrity ───────────────────────────────────

def test_whitelist_hmac_integrity(tmp_path):
    """Whitelist with valid HMAC should load; tampered content should fail."""
    import hashlib
    import hmac
    import secrets

    whitelist_path = tmp_path / "whitelist.txt"

    # Create a fresh HMAC key (simulating what ActionExecutor does)
    key = secrets.token_bytes(32)
    _SIG_PREFIX = "CRABAV_SIG_V1:"

    def sign(lines):
        normalized = "\n".join(sorted(lines)) + "\n"
        sig = hmac.new(key, normalized.encode("utf-8"), "sha256").hexdigest()
        return f"{_SIG_PREFIX}{sig}\n{normalized}"

    # Write a valid signed whitelist
    entries = ["abc123hash", "def456hash"]
    whitelist_path.write_text(sign(entries), encoding="utf-8")

    # Verify signature
    from src.engine.action_executor import _load_and_verify

    result = _load_and_verify(whitelist_path, key)
    assert result is not None
    assert result == set(entries)

    # Tamper: add an entry without re-signing
    whitelist_path.write_text(sign(entries).rstrip() + "\nevilhash\n", encoding="utf-8")

    result = _load_and_verify(whitelist_path, key)
    assert result is None, "Tampered whitelist should be rejected!"

    # Tamper: remove signature header
    whitelist_path.write_text("abc123hash\ndef456hash\n", encoding="utf-8")

    result = _load_and_verify(whitelist_path, key)
    assert result is None, "Unsigned whitelist should be rejected!"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
