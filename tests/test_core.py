"""
Unit tests for CrabAV components
"""

import pytest
import asyncio
from pathlib import Path
from datetime import datetime

# Test Decision Engine
def test_threat_scorer():
    from src.decision import ThreatScorer
    from src.enums import AgentType, ThreatLevel, FindingType
    from src.models import ThreatFinding
    
    scorer = ThreatScorer()
    
    # Create test finding
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


# Test Approval Handler
def test_approval_handler():
    from src.approval import ApprovalHandler
    from src.enums import ActionType
    
    handler = ApprovalHandler()
    
    # Generate request
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
    
    # Approve
    result = handler.approve(
        request.request_id,
        ActionType.QUARANTINE,
        "test_user"
    )
    
    assert result.approved is True
    assert result.approved_action == ActionType.QUARANTINE


# Test Quarantine Manager
def test_quarantine_manager(tmp_path):
    from src.quarantine import QuarantineManager
    
    quar_dir = tmp_path / "quarantine"
    backup_dir = tmp_path / "backup"
    
    manager = QuarantineManager(
        quarantine_dir=str(quar_dir),
        backup_dir=str(backup_dir)
    )
    
    # Create test file
    test_file = tmp_path / "test.txt"
    test_file.write_text("test content")
    
    # Quarantine it
    record = manager.quarantine_file(
        file_path=str(test_file),
        threat_id="test_threat",
        reason="Test quarantine"
    )
    
    assert record is not None
    assert not test_file.exists()  # Original removed
    assert Path(record.quarantined_path).exists()
    assert Path(record.backup_path).exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
