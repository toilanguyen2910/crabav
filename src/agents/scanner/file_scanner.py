"""
File Scanner Agent - Signature-based detection using ClamAV
"""

from typing import Any, List, Optional
from pathlib import Path
import subprocess
from datetime import datetime

from ...enums import AgentType, FindingType, ThreatLevel, ActionType
from ...models import ThreatFinding, AgentResult
from ...utils import (
    get_logger,
    calculate_file_hash,
    format_bytes,
    validate_scan_path,
    validate_subprocess_arg,
)
from ..base_agent import ScannerAgent, AgentConfig

logger = get_logger("file_scanner")


# ── Allowed scan roots ────────────────────────────────────────────
# FileScanner will only scan paths within these directories.
# Adjust this list as needed for your environment.
_ALLOWED_SCAN_ROOTS = [
    "C:\\Users",
    "C:\\ProgramData",
    "D:\\",
    "/home",
    "/Users",
    "/tmp",
]


class FileScanner(ScannerAgent):
    """
    Scanner agent using ClamAV for file signature matching
    """

    def __init__(self, config: AgentConfig):
        super().__init__("file_scanner", AgentType.SCANNER, config)
        self.clamav_available = False
        self.clamd_socket = None

    async def initialize(self) -> bool:
        """Check if ClamAV is available"""
        try:
            result = subprocess.run(
                ["clamscan", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                self.clamav_available = True
                logger.info("ClamAV scanner initialized")
                return True
        except Exception as e:
            logger.warning(f"ClamAV not available: {e}")
        return False

    async def scan(self, target: Any) -> AgentResult:
        """Scan file using ClamAV with path validation"""
        findings: List[ThreatFinding] = []
        errors: List[str] = []

        if not self.clamav_available:
            errors.append("ClamAV not available on this system")
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                success=False,
                errors=errors
            )

        try:
            # Validate scan path (defense against path traversal)
            try:
                target_path = validate_scan_path(
                    str(target), allowed_roots=_ALLOWED_SCAN_ROOTS
                )
            except ValueError as e:
                errors.append(f"Invalid scan path: {e}")
                return AgentResult(
                    agent_id=self.agent_id,
                    agent_type=self.agent_type,
                    success=False,
                    errors=errors
                )

            if not target_path.exists():
                errors.append(f"Target path does not exist: {target}")
                return AgentResult(
                    agent_id=self.agent_id,
                    agent_type=self.agent_type,
                    success=False,
                    errors=errors
                )

            # Sanitize path for subprocess arg
            sanitized = str(target_path)
            validate_subprocess_arg(sanitized)

            # Run clamscan (list form — no shell=True)
            result = subprocess.run(
                ["clamscan", "-r", sanitized],
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds
            )

            # Parse output
            findings = self._parse_clamscan_output(result.stdout, target_path)

            success = result.returncode in [0, 1]  # 0=clean, 1=infected

            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                success=success,
                findings=findings,
                errors=errors if not success else []
            )

        except subprocess.TimeoutExpired:
            errors.append(f"Scan timed out after {self.config.timeout_seconds}s")
        except Exception as e:
            errors.append(f"Scan error: {str(e)}")

        return AgentResult(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            success=False,
            errors=errors
        )

    def _parse_clamscan_output(self, output: str, target_path: Path) -> List[ThreatFinding]:
        """Parse clamscan output and extract findings"""
        findings = []

        for line in output.split("\n"):
            if " FOUND" not in line:
                continue

            # Format: /path/to/file: ThreatName FOUND
            parts = line.split(": ")
            if len(parts) != 2:
                continue

            file_path = parts[0].strip()
            threat_info = parts[1].strip()
            threat_name = threat_info.replace(" FOUND", "").strip()

            # Create finding
            try:
                file_size = Path(file_path).stat().st_size
                file_hash = calculate_file_hash(file_path)
            except:
                file_size = 0
                file_hash = None

            finding = ThreatFinding(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                finding_type=FindingType.FILE_SIGNATURE,
                threat_name=threat_name,
                threat_level=ThreatLevel.HIGH,
                confidence=0.95,
                evidence={
                    "file_path": file_path,
                    "detection_method": "ClamAV signature",
                    "file_size": file_size,
                    "threat_name": threat_name
                },
                recommended_actions=[ActionType.QUARANTINE, ActionType.DELETE],
                metadata={
                    "file_hash": file_hash,
                    "scan_type": "signature"
                }
            )
            findings.append(finding)

        return findings
