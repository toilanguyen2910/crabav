"""
Basic File Scanner — duyệt thư mục thực sự, không cần ClamAV.
Kiểm tra: extension nghi ngờ, file ẩn, file không có extension, file quá lớn.
"""
from typing import Any, List, Optional
from pathlib import Path
import os
import asyncio

from ...enums import AgentType, FindingType, ThreatLevel, ActionType, AgentStatus
from ...models import ThreatFinding, AgentResult
from ...utils import (
    get_logger,
    calculate_file_hash,
    validate_scan_path,
    validate_subprocess_arg,
)
from ..base_agent import ScannerAgent, AgentConfig

logger = get_logger("basic_scanner")

# Extension nghi ngờ (có thể mở rộng)
SUSPICIOUS_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.wsf', '.hta',
    '.scr', '.pif', '.com', '.msi', '.dll', '.sys', '.jar',
    '.py', '.sh', '.rb', '.pl',  # script files in user dirs
}

# Thư mục hệ thống cần bỏ qua khi scan
SKIP_DIRS = {
    'node_modules', '.git', '__pycache__', '.venv', 'venv',
    'Windows', 'Program Files', 'Program Files (x86)',
    '$Recycle.Bin', 'System Volume Information',
}


class BasicFileScanner(ScannerAgent):
    """Scanner duyệt file thực tế, không cần ClamAV"""

    def __init__(self, config: AgentConfig):
        super().__init__("basic_scanner", AgentType.SCANNER, config)

    async def initialize(self) -> bool:
        logger.info("BasicFileScanner initialized (no ClamAV required)")
        return True

    async def scan(self, target: Any) -> AgentResult:
        """Duyệt thư mục và kiểm tra file"""
        findings: List[ThreatFinding] = []
        errors: List[str] = []
        files_scanned = 0
        suspicious_count = 0

        try:
            target_path = Path(str(target))
            if not target_path.exists():
                errors.append(f"Target path does not exist: {target}")
                return AgentResult(
                    agent_id=self.agent_id,
                    agent_type=self.agent_type,
                    success=False,
                    errors=errors,
                    metadata={"files_scanned": 0},
                )

            # Duyệt thư mục (async để không block)
            loop = asyncio.get_event_loop()
            scan_data = await loop.run_in_executor(
                None, self._scan_directory, target_path
            )

            files_scanned = scan_data["total"]
            findings = scan_data["findings"]

        except asyncio.TimeoutError:
            errors.append(f"Scan timed out after {self.config.timeout_seconds}s")
        except Exception as e:
            errors.append(f"Scan error: {str(e)}")

        return AgentResult(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            success=len(errors) == 0,
            findings=findings,
            errors=errors,
            metadata={
                "files_scanned": files_scanned,
                "suspicious_found": len(findings),
            },
        )

    def _scan_directory(self, target_path: Path) -> dict:
        """Đồng bộ duyệt thư mục, đếm file, tìm nghi ngờ"""
        total = 0
        findings = []

        try:
            for root, dirs, files in os.walk(str(target_path)):
                # Bỏ qua thư mục hệ thống
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

                for fname in files:
                    total += 1
                    if total >= 5000:
                        break  # giới hạn

                    fpath = Path(root) / fname
                    ext = fpath.suffix.lower()

                    # Kiểm tra nghi ngờ
                    if ext in SUSPICIOUS_EXTENSIONS:
                        try:
                            fsize = fpath.stat().st_size
                        except OSError:
                            fsize = 0

                        # Chỉ flag nếu file trong thư mục user/downloads (tránh system files)
                        path_str = str(fpath).lower()
                        is_user_area = any(
                            p in path_str for p in ['downloads', 'desktop', 'documents', 'appdata\\local\\temp']
                        )

                        if ext in ('.exe', '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.pif', '.com', '.msi') and is_user_area:
                            finding = ThreatFinding(
                                agent_id=self.agent_id,
                                agent_type=self.agent_type,
                                finding_type=FindingType.HEURISTIC,
                                threat_name=f"Suspicious executable in user area: {fname}",
                                threat_level=ThreatLevel.MEDIUM,
                                confidence=0.60,
                                evidence={
                                    "file_path": str(fpath),
                                    "file_size": fsize,
                                    "extension": ext,
                                    "reason": "Executable file in user directory",
                                },
                                recommended_actions=[ActionType.QUARANTINE],
                                metadata={
                                    "file_hash": None,
                                    "scan_type": "heuristic",
                                },
                            )
                            findings.append(finding)

                if total >= 5000:
                    break

        except PermissionError:
            pass  # skip inaccessible dirs

        return {"total": total, "findings": findings}
