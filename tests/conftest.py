"""
Test configuration and fixtures
"""

import pytest
from pathlib import Path


@pytest.fixture
def test_config():
    """Provide test configuration"""
    return {
        "agents": {
            "file_scanner": {"enabled": True},
            "file_monitor": {"enabled": False}  # Disable for tests
        },
        "quarantine": {
            "storage_path": "./test_data/quarantine",
            "backup_path": "./test_data/backup"
        }
    }


@pytest.fixture
def eicar_file(tmp_path):
    """Create EICAR test file"""
    eicar = tmp_path / "eicar.txt"
    eicar.write_text(
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    return eicar
