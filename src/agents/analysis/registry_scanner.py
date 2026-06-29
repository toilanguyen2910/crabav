"""
Registry Scanner Agent — Windows persistence detection (expanded)

Scans:
- HKCU + HKLM Run/RunOnce keys
- Scheduled Tasks (via schtasks.exe)
- Startup folders (user + common)
- Services registry
- Winlogon Shell / Userinit hijacks
- Browser helper objects (BHO)
- AppInit_DLLs
"""

import asyncio
import subprocess
import os
import re
from pathlib import Path
from typing import Any, List, Dict, Optional

try:
    import winreg
except ImportError:
    winreg = None

from ...enums import AgentType, FindingType, ThreatLevel, ActionType
from ...models import ThreatFinding, AgentResult
from ...utils import get_logger
from ..base_agent import MonitorAgent, AgentConfig

logger = get_logger("registry_scanner")

# ── Registry scan targets ──────────────────────────────────────

# (hive, path, description, category)
_REGISTRY_TARGETS = [
    # HKCU persistence
    (winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Run",
     "HKCU Run", "startup"),
    (winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
     "HKCU RunOnce", "startup"),
    (winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
     "HKCU Policies Explorer Run", "startup"),

    # HKLM persistence
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\Run",
     "HKLM Run", "startup"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
     "HKLM RunOnce", "startup"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
     "HKLM WOW6432Node Run", "startup"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
     "HKLM WOW6432Node RunOnce", "startup"),

    # Winlogon hijacks
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
     "HKLM Winlogon", "hijack"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
     "HKLM AppInit_DLLs", "injection"),

    # Services
    (winreg.HKEY_LOCAL_MACHINE,
     r"System\CurrentControlSet\Services",
     "HKLM Services", "service"),

    # Browser Helper Objects
    (winreg.HKEY_LOCAL_MACHINE,
     r"Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
     "HKLM BHO", "browser"),
]

# ── Suspicious indicators ──────────────────────────────────────

_SUSPICIOUS_PATTERNS = [
    "powershell", "cmd.exe", "rundll32", "regsvr32",
    "wscript", "cscript", "bitsadmin", "certutil",
    "mshta", "msiexec", "reg.exe", "schtasks",
]

_SUSPICIOUS_PATHS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\downloads\\", "\\public\\", "\\users\\public\\",
]

_KNOWN_SAFE_ENTRIES = {
    "securityhealth", "windows defender", "onedrive",
    "microsoftedge", "teams", "vscode", "dropbox",
    "spotify", "discord", "steam",
}


class RegistryScanner(MonitorAgent):
    """
    Registry scanning agent for persistence detection.

    Detects:
    - Startup persistence (HKCU + HKLM Run/RunOnce keys)
    - Winlogon hijacks (Shell, Userinit)
    - AppInit_DLLs injection
    - Suspicious services
    - Browser Helper Objects
    - Scheduled Tasks (via schtasks.exe)
    - Startup folder entries
    """

    def __init__(self, config: AgentConfig):
        super().__init__("registry_scanner", AgentType.MONITOR, config)
        self.baseline: Dict[str, Dict[str, str]] = {}

    async def initialize(self) -> bool:
        if not winreg:
            logger.error("winreg not available (Windows only)")
            return False
        try:
            for hive, path, desc, cat in _REGISTRY_TARGETS:
                self.baseline[f"{desc}"] = self._read_registry(hive, path)
            logger.info(
                f"Registry baseline: {len(self.baseline)} locations, "
                f"{sum(len(v) for v in self.baseline.values())} values"
            )
            self.is_running = True
            return True
        except Exception as e:
            logger.error(f"Registry baseline failed: {e}")
            return False

    async def shutdown(self) -> bool:
        self.is_running = False
        return True

    # ── Registry I/O ───────────────────────────────────────────

    @staticmethod
    def _read_registry(hive: int, path: str) -> Dict[str, str]:
        """Read all values from a registry key."""
        values: Dict[str, str] = {}
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    values[name] = str(value)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except OSError:
            pass  # Key doesn't exist or access denied
        except Exception as e:
            logger.debug(f"Cannot read registry {path}: {e}")
        return values

    @staticmethod
    def _read_registry_subkeys(hive: int, path: str) -> List[str]:
        """List subkey names under a registry key."""
        subkeys: List[str] = []
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
            i = 0
            while True:
                try:
                    subkeys.append(winreg.EnumKey(key, i))
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except OSError:
            pass
        except Exception as e:
            logger.debug(f"Cannot enumerate {path}: {e}")
        return subkeys

    # ── Heuristic analysis ─────────────────────────────────────

    @staticmethod
    def _is_suspicious(value: str) -> tuple[bool, str]:
        """Check if a registry value looks suspicious."""
        lower = value.lower()

        # Known safe
        for safe in _KNOWN_SAFE_ENTRIES:
            if safe in lower:
                return False, ""

        # Suspicious process patterns
        reasons: List[str] = []
        for pat in _SUSPICIOUS_PATTERNS:
            if pat in lower:
                # Check context — some are legitimate
                if pat == "cmd.exe" and "/c" in lower:
                    reasons.append(f"cmd.exe with args")

                elif pat == "powershell" and any(
                    x in lower for x in [
                        "-enc", "-encodedcommand", "invoke-", "downloadstring",
                        "iex", "frombase64", "-windowstyle hidden",
                        "-executionpolicy bypass"
                    ]
                ):
                    reasons.append("suspicious PowerShell flags")

                elif pat == "rundll32" and any(
                    x in lower for x in [",", "javascript:"]
                ):
                    reasons.append("rundll32 with suspicious target")

                elif pat == "wscript" or pat == "cscript":
                    reasons.append(f"script host: {pat}")

                elif pat in ("mshta", "certutil", "bitsadmin"):
                    reasons.append(f"LOLBin: {pat}")

        # Suspicious paths
        for sp in _SUSPICIOUS_PATHS:
            if sp in lower:
                reasons.append(f"temp/download path")

        return bool(reasons), "; ".join(reasons)

    # ── Scheduled Tasks scanning ───────────────────────────────

    @staticmethod
    async def _scan_scheduled_tasks() -> List[Dict[str, str]]:
        """Query scheduled tasks via schtasks.exe."""
        tasks: List[Dict[str, str]] = []
        try:
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "csv", "/v"],
                capture_output=True, text=True, timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            if result.returncode != 0:
                return tasks

            lines = result.stdout.splitlines()
            if len(lines) < 2:
                return tasks

            headers = [h.strip().strip('"') for h in lines[0].split(",")]

            for line in lines[1:]:
                parts = [p.strip().strip('"') for p in line.split(",")]
                if len(parts) < len(headers):
                    continue
                row = dict(zip(headers, parts))

                task_name = row.get("TaskName", "")
                task_to_run = row.get("Task To Run", "")
                author = row.get("Author", "")

                suspicious, reason = RegistryScanner._is_suspicious(task_to_run)
                if suspicious:
                    tasks.append({
                        "name": task_name,
                        "command": task_to_run,
                        "author": author,
                        "reason": reason,
                    })

        except subprocess.TimeoutExpired:
            logger.warning("Scheduled tasks query timed out")
        except Exception as e:
            logger.error(f"Scheduled tasks scan error: {e}")

        return tasks

    # ── Startup folders scanning ────────────────────────────────

    @staticmethod
    def _scan_startup_folders() -> List[Dict[str, str]]:
        """Scan Windows startup folders for suspicious entries."""
        entries: List[Dict[str, str]] = []

        startup_paths = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        ]

        for folder in startup_paths:
            p = Path(folder)
            if not p.exists():
                continue
            for item in p.iterdir():
                if item.is_file() and item.suffix.lower() in (
                    ".exe", ".bat", ".cmd", ".vbs", ".ps1", ".js", ".lnk"
                ):
                    suspicious, reason = RegistryScanner._is_suspicious(str(item))
                    entries.append({
                        "path": str(item),
                        "folder": str(p),
                        "suspicious": suspicious,
                        "reason": reason,
                    })

        return entries

    # ── Main scan ──────────────────────────────────────────────

    async def scan(self, target: Any = None) -> AgentResult:
        """
        Full registry + persistence scan.

        Returns:
            AgentResult with findings
        """
        findings: List[ThreatFinding] = []

        if not winreg:
            return AgentResult(
                agent_id=self.agent_id, agent_type=self.agent_type,
                success=False, errors=["Registry access not available"]
            )

        try:
            # 1. Registry persistence keys
            for hive, path, desc, cat in _REGISTRY_TARGETS:
                current = self._read_registry(hive, path)
                baseline_vals = self.baseline.get(desc, {})

                for name, value in current.items():
                    suspicious, reason = self._is_suspicious(value)
                    if not suspicious:
                        continue

                    is_new = name not in baseline_vals
                    confidence = 0.85 if is_new else 0.70

                    findings.append(ThreatFinding(
                        agent_id=self.agent_id,
                        agent_type=self.agent_type,
                        finding_type=FindingType.REGISTRY,
                        threat_name=f"Suspicious.Registry.{cat.title()}",
                        threat_level=ThreatLevel.HIGH if is_new else ThreatLevel.MEDIUM,
                        confidence=confidence,
                        evidence={
                            "registry_path": path,
                            "hive": desc,
                            "key_name": name,
                            "key_value": value[:200],
                            "reason": reason,
                            "is_new_entry": is_new,
                            "category": cat,
                        },
                        recommended_actions=[ActionType.QUARANTINE],
                        metadata={"detection_type": cat, "source": "registry"}
                    ))

            # 2. Scheduled Tasks
            tasks = await self._scan_scheduled_tasks()
            for task in tasks:
                findings.append(ThreatFinding(
                    agent_id=self.agent_id,
                    agent_type=self.agent_type,
                    finding_type=FindingType.BEHAVIORAL,
                    threat_name="Suspicious.ScheduledTask",
                    threat_level=ThreatLevel.MEDIUM,
                    confidence=0.75,
                    evidence={
                        "task_name": task["name"],
                        "command": task["command"],
                        "author": task["author"],
                        "reason": task["reason"],
                    },
                    recommended_actions=[ActionType.QUARANTINE],
                    metadata={"detection_type": "scheduled_task", "source": "schtasks"}
                ))

            # 3. Startup folders
            startup_entries = self._scan_startup_folders()
            for entry in startup_entries:
                if entry["suspicious"]:
                    findings.append(ThreatFinding(
                        agent_id=self.agent_id,
                        agent_type=self.agent_type,
                        finding_type=FindingType.BEHAVIORAL,
                        threat_name="Suspicious.StartupFolder",
                        threat_level=ThreatLevel.MEDIUM,
                        confidence=0.70,
                        evidence={
                            "file_path": entry["path"],
                            "folder": entry["folder"],
                            "reason": entry["reason"],
                        },
                        recommended_actions=[ActionType.QUARANTINE],
                        metadata={"detection_type": "startup_folder", "source": "filesystem"}
                    ))

            # 4. Services with suspicious ImagePath
            svc_path = r"System\CurrentControlSet\Services"
            subkeys = self._read_registry_subkeys(winreg.HKEY_LOCAL_MACHINE, svc_path)

            # Only check a sample to avoid massive scan time
            for sk in subkeys[:200]:
                try:
                    image_path_key = f"{svc_path}\\{sk}"
                    values = self._read_registry(winreg.HKEY_LOCAL_MACHINE, image_path_key)
                    image_path = values.get("ImagePath", "")
                    suspicious, reason = self._is_suspicious(image_path)
                    if suspicious:
                        findings.append(ThreatFinding(
                            agent_id=self.agent_id,
                            agent_type=self.agent_type,
                            finding_type=FindingType.REGISTRY,
                            threat_name="Suspicious.Service",
                            threat_level=ThreatLevel.HIGH,
                            confidence=0.80,
                            evidence={
                                "service_name": sk,
                                "image_path": image_path[:200],
                                "reason": reason,
                            },
                            recommended_actions=[ActionType.QUARANTINE],
                            metadata={"detection_type": "service", "source": "registry"}
                        ))
                except Exception:
                    continue

            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                success=True,
                findings=findings,
                metadata={
                    "registry_locations": len(_REGISTRY_TARGETS),
                    "scheduled_tasks_scanned": len(tasks),
                    "startup_folders_scanned": 2,
                    "services_scanned": min(len(subkeys), 200),
                    "total_findings": len(findings),
                }
            )

        except Exception as e:
            logger.error(f"Registry scanner error: {e}")
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                success=False,
                errors=[str(e)]
            )
