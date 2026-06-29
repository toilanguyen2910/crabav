"""
Integration tests for full scan workflow
"""

import pytest
import asyncio
from pathlib import Path

pytestmark = pytest.mark.asyncio


async def test_full_scan_workflow(tmp_path):
    """Test complete scan workflow from detection to approval"""
    from src.__main__ import CrabAVApp
    from src.enums import ActionType
    
    # Create test file
    test_file = tmp_path / "suspicious.txt"
    test_file.write_text("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    
    # Initialize app
    app = CrabAVApp()
    await app.start()
    
    try:
        # Run scan
        result = await app.scan(str(test_file), "quick")
        
        assert result["status"] in ["completed", "running"]
        
        # Check pending approvals
        pending = app.approval_handler.get_pending_requests()
        
        if pending:
            request = pending[0]
            
            # Approve quarantine
            approval_result = app.approval_handler.approve(
                request.request_id,
                ActionType.QUARANTINE,
                "test_user"
            )
            
            assert approval_result.approved is True
    
    finally:
        await app.stop()


async def test_agent_initialization():
    """Test that all agents initialize correctly"""
    from src.__main__ import CrabAVApp
    
    app = CrabAVApp()
    await app.start()
    
    try:
        status = app.get_status()
        
        assert len(status["agents"]) > 0
        
        for agent in status["agents"]:
            assert "agent_id" in agent
            assert "status" in agent
    
    finally:
        await app.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
