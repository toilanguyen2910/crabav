"""
Performance optimization tests for CrabAV
"""

import pytest
import time
import asyncio
from pathlib import Path


def test_threat_scorer_performance():
    """Test threat scoring performance"""
    from src.decision import ThreatScorer
    from src.enums import AgentType, ThreatLevel, FindingType
    from src.models import ThreatFinding
    
    scorer = ThreatScorer()
    
    # Create 100 findings
    findings = [
        ThreatFinding(
            agent_id=f"agent_{i}",
            agent_type=AgentType.SCANNER,
            finding_type=FindingType.FILE_SIGNATURE,
            threat_name="Test.Threat",
            threat_level=ThreatLevel.HIGH if i % 2 else ThreatLevel.MEDIUM,
            confidence=0.8 + (i % 20) * 0.01,
            evidence={"test": "data"},
            recommended_actions=[],
            metadata={}
        )
        for i in range(100)
    ]
    
    start = time.time()
    score = scorer.calculate_score(findings)
    elapsed = time.time() - start
    
    assert elapsed < 0.1  # Should complete in <100ms
    assert 0 <= score <= 100


@pytest.mark.asyncio
async def test_orchestrator_concurrency():
    """Test orchestrator concurrent agent execution"""
    from src.__main__ import CrabAVApp
    
    app = CrabAVApp()
    await app.start()
    
    try:
        # Run multiple scans concurrently
        start = time.time()
        
        scan_tasks = [
            app.scan("/tmp/test1", "quick"),
            app.scan("/tmp/test2", "quick"),
            app.scan("/tmp/test3", "quick"),
        ]
        
        results = await asyncio.gather(*scan_tasks, return_exceptions=True)
        elapsed = time.time() - start
        
        # Should complete reasonably fast with concurrency
        assert elapsed < 30
        assert len(results) == 3
    
    finally:
        await app.stop()


def test_quarantine_manager_performance(tmp_path):
    """Test quarantine manager I/O performance"""
    from src.quarantine import QuarantineManager
    
    manager = QuarantineManager(
        quarantine_dir=str(tmp_path / "quarantine"),
        backup_dir=str(tmp_path / "backup")
    )
    
    # Create 10 test files
    files = []
    for i in range(10):
        test_file = tmp_path / f"test_{i}.txt"
        test_file.write_text(f"Test content {i}" * 1000)
        files.append(test_file)
    
    start = time.time()
    
    # Quarantine all
    for i, file_path in enumerate(files):
        manager.quarantine_file(
            str(file_path),
            f"threat_{i}",
            "Performance test"
        )
    
    elapsed = time.time() - start
    
    # Should handle 10 files quickly
    assert elapsed < 5.0
