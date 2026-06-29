"""
Unit tests for YARA Scanner and VirusTotal client
"""

import pytest
import asyncio
import os
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock


# ── YARA Scanner ───────────────────────────────────────────────

def test_yara_scanner_loads_rules():
    """YARA scanner should compile rules from the rules directory."""
    from src.agents.scanner import YaraScanner

    # Use the default rules directory
    scanner = YaraScanner()
    assert scanner.is_available, "YARA scanner should have compiled rules"

    # Should have at least one rule
    assert scanner.rules is not None


def test_yara_scanner_scan_clean_file(tmp_path):
    """Scanning a clean file should return no matches."""
    from src.agents.scanner import YaraScanner

    scanner = YaraScanner()
    assert scanner.is_available

    # Create a file that shouldn't match any malware rules
    clean_file = tmp_path / "hello.txt"
    clean_file.write_text("Hello, World! This is a clean file.")

    matches = scanner.scan_file(str(clean_file))
    assert matches == [], f"Expected no matches, got {matches}"


def test_yara_scanner_scan_suspicious_file(tmp_path):
    """Scanning a file with malware patterns should return matches."""
    from src.agents.scanner import YaraScanner

    scanner = YaraScanner()
    assert scanner.is_available

    # Create a file containing UPX packer signature
    test_file = tmp_path / "packed.exe"
    test_file.write_bytes(b"\x00" * 100 + b"UPX0" + b"\x00" * 100 + b"UPX1")

    matches = scanner.scan_file(str(test_file))
    assert len(matches) > 0, "Expected at least one YARA match for UPX signature"

    # Should match the UPX packer rule
    rule_names = [m["rule_name"] for m in matches]
    assert any("UPX" in r or "Packer" in r for r in rule_names), (
        f"Expected UPX/Packer rule match, got: {rule_names}"
    )


def test_yara_scanner_double_extension(tmp_path):
    """Double extension rule should catch files containing .pdf.exe patterns."""
    from src.agents.scanner import YaraScanner

    scanner = YaraScanner()
    assert scanner.is_available

    # YARA scans file CONTENT, not filename — embed the pattern in the file
    test_file = tmp_path / "invoice.pdf.exe"
    test_file.write_bytes(
        b"\x00" * 100 + b".pdf.exe\x00" + b"\x00" * 100
    )

    matches = scanner.scan_file(str(test_file))
    rule_names = [m["rule_name"] for m in matches]
    assert "SUSP_DoubleExtension" in rule_names or any(
        "DoubleExtension" in r for r in rule_names
    ), f"Expected DoubleExtension match, got: {rule_names}"


def test_yara_scanner_with_findings(tmp_path):
    """scan_file_with_findings should return ThreatFinding objects."""
    from src.agents.scanner import YaraScanner
    from src.models import ThreatFinding

    scanner = YaraScanner()
    assert scanner.is_available

    # File with process injection APIs
    test_file = tmp_path / "injector.dll"
    content = (
        b"\x00" * 50
        + b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00"
        + b"\x00" * 50
    )
    test_file.write_bytes(content)

    findings = scanner.scan_file_with_findings(str(test_file), "test_agent")
    assert len(findings) > 0

    for finding in findings:
        assert isinstance(finding, ThreatFinding)
        assert finding.agent_id == "test_agent"
        assert finding.confidence > 0


def test_yara_scanner_directory_scan(tmp_path):
    """Scanning a directory should find threats in multiple files."""
    from src.agents.scanner import YaraScanner

    scanner = YaraScanner()
    assert scanner.is_available

    scan_dir = tmp_path / "scandir"
    scan_dir.mkdir()

    # Create some clean files
    (scan_dir / "readme.txt").write_text("README content")
    (scan_dir / "notes.md").write_text("# Notes\nNothing suspicious")

    # Create a suspicious file
    (scan_dir / "bad.exe").write_bytes(
        b"\x00" * 200 + b"UPX0\x00\x00UPX1\x00\x00" + b"\x00" * 200
    )

    # Create a double extension file
    (scan_dir / "report.pdf.scr").write_bytes(b"\x00" * 100)

    findings = scanner.scan_directory(str(scan_dir), "yara_scanner")
    assert len(findings) > 0, "Expected findings in directory scan"


# ── VirusTotal Client ──────────────────────────────────────────

def test_vt_client_no_api_key():
    """Client without API key should report unavailable."""
    from src.agents.analysis import VirusTotalClient

    # Clear env var to ensure no key
    with patch.dict(os.environ, {}, clear=True):
        client = VirusTotalClient(api_key=None)
        assert not client.is_available
        assert client._api_key is None


def test_vt_client_with_api_key():
    """Client with API key should report available."""
    from src.agents.analysis import VirusTotalClient

    client = VirusTotalClient(api_key="test_key_12345")
    assert client.is_available
    assert client._api_key == "test_key_12345"


def test_vt_client_loads_key_from_env():
    """Client should load API key from environment variable."""
    from src.agents.analysis import VirusTotalClient

    with patch.dict(os.environ, {"CRABAV_VT_API_KEY": "env_key_abc123"}):
        client = VirusTotalClient(api_key=None)
        assert client.is_available
        assert client._api_key == "env_key_abc123"


@pytest.mark.asyncio
async def test_vt_lookup_skips_without_key():
    """lookup_hash should return None when no API key."""
    from src.agents.analysis import VirusTotalClient

    with patch.dict(os.environ, {}, clear=True):
        client = VirusTotalClient(api_key=None)
        result = await client.lookup_hash(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert result is None


@pytest.mark.asyncio
async def test_vt_lookup_invalid_hash():
    """lookup_hash should return None for invalid hashes."""
    from src.agents.analysis import VirusTotalClient

    client = VirusTotalClient(api_key="test_key")
    result = await client.lookup_hash("too_short")
    assert result is None


@pytest.mark.asyncio
async def test_vt_lookup_mocked_response():
    """lookup_hash with mocked API should return parsed result."""
    from src.agents.analysis import VirusTotalClient
    import httpx

    mock_response_data = {
        "data": {
            "attributes": {
                "last_analysis_results": {
                    "Engine1": {
                        "category": "malicious",
                        "result": "Trojan.Generic",
                        "method": "blacklist",
                    },
                    "Engine2": {
                        "category": "undetected",
                        "result": "",
                        "method": "",
                    },
                    "Engine3": {
                        "category": "harmless",
                        "result": "",
                        "method": "",
                    },
                },
                "last_analysis_date": 1719000000,
                "meaningful_name": "malware.exe",
                "type_description": "Win32 EXE",
                "size": 12345,
                "popular_threat_classification": {
                    "suggested_threat_label": "trojan"
                },
            }
        }
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = mock_response_data
    mock_response.raise_for_status = MagicMock()

    async def mock_get(*args, **kwargs):
        return mock_response

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        client = VirusTotalClient(api_key="test_key")
        result = await client.lookup_hash(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

        assert result is not None
        assert result["positives"] == 1
        assert result["total"] == 3
        assert result["popular_threat_name"] == "trojan"
        assert "virustotal.com/gui/file" in result["permalink"]

        await client.close()


@pytest.mark.asyncio
async def test_vt_lookup_404():
    """404 response from VirusTotal should return None."""
    from src.agents.analysis import VirusTotalClient
    import httpx

    async def mock_get(*args, **kwargs):
        response = MagicMock()
        response.status_code = 404
        return response

    with patch.object(httpx.AsyncClient, "get", side_effect=mock_get):
        client = VirusTotalClient(api_key="test_key")
        result = await client.lookup_hash(
            "a" * 64  # valid-length but unknown hash
        )
        assert result is None
        await client.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
