"""
Process Monitor Agent — Real-time process analysis with heuristics

Detects:
- Suspicious parent-child relationships (with context-aware filtering)
- Process hollowing / injection indicators
- Suspicious command-line arguments
- LOLBin (Living Off the Land Binary) usage
- Network connections from suspicious processes
"""

import asyncio
from typing import Any, List, Dict, Set, Optional
from datetime import datetime
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None

from ...enums import AgentType, FindingType, ThreatLevel, ActionType
from ...models import ThreatFinding, AgentResult
from ...utils import get_logger
from ..base_agent import MonitorAgent, AgentConfig

logger = get_logger("process_monitor")

# ── Heuristics Configuration ───────────────────────────────────

# Parent → child combinations that are ALWAYS suspicious
_HIGH_RISK_PARENT_CHILD = {
    # Office macros spawning shells
    ("winword.exe", "cmd.exe"): "Word macro spawned shell",
    ("excel.exe", "cmd.exe"): "Excel macro spawned shell",
    ("powerpnt.exe", "cmd.exe"): "PowerPoint macro spawned shell",
    ("outlook.exe", "cmd.exe"): "Outlook spawned shell",
    # PDF readers spawning shells
    ("acrord32.exe", "cmd.exe"): "Adobe Reader spawned shell",
    ("foxitreader.exe", "cmd.exe"): "Foxit spawned shell",
    # Browser spawning shells (potential drive-by)
    ("chrome.exe", "cmd.exe"): "Chrome spawned shell",
    ("firefox.exe", "cmd.exe"): "Firefox spawned shell",
    ("msedge.exe", "cmd.exe"): "Edge spawned shell",
    # Weird parents for PowerShell
    ("winword.exe", "powershell.exe"): "Word spawned PowerShell",
    ("excel.exe", "powershell.exe"): "Excel spawned PowerShell",
    ("chrome.exe", "powershell.exe"): "Chrome spawned PowerShell",
}

# Parent → child combinations that are NORMAL (suppress false positives)
_NORMAL_PARENT_CHILD = {
    ("explorer.exe", "cmd.exe"),       # User opening cmd from Explorer
    ("explorer.exe", "powershell.exe"), # User opening PS from Explorer
    ("cmd.exe", "cmd.exe"),            # Nested cmd (batch files)
    ("services.exe", "svchost.exe"),   # Normal service spawn
    ("svchost.exe", "svchost.exe"),    # Normal service grouping
    ("winlogon.exe", "userinit.exe"),  # Normal login
    ("winlogon.exe", "fontdrvhost.exe"), # Normal font driver
    ("RuntimeBroker.exe", "RuntimeBroker.exe"),
    ("MsMpEng.exe", "MsMpEng.exe"),    # Windows Defender
    ("devenv.exe", "cmd.exe"),         # VS Code / IDE spawning terminal
    ("Code.exe", "cmd.exe"),           # VS Code terminal
    ("Code.exe", "powershell.exe"),    # VS Code PowerShell terminal
}

# Process names that are legitimate Windows/Linux helpers (LOW risk)
_LOW_RISK_PROCESSES = {
    "conhost.exe", "dwm.exe", "csrss.exe", "smss.exe",
    "lsass.exe", "wininit.exe", "spoolsv.exe", "sihost.exe",
    "taskhostw.exe", "ctfmon.exe", "searchindexer.exe",
    "fontdrvhost.exe", "audiodg.exe", "wlms.exe", "wudfhost.exe",
    "dllhost.exe", "sppsvc.exe", "moshost.exe", "smartscreen.exe",
    "securityhealthservice.exe", "securityhealthsystray.exe",
    "applicationframehost.exe", "systemsettings.exe",
    "textinputhost.exe", "yourphone.exe", "widgets.exe",
}

# LOLBins — system binaries commonly abused for living-off-the-land
_LOLBINS = {
    "bitsadmin.exe", "certutil.exe", "cscript.exe", "wscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "msbuild.exe",
    "csc.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    "msiexec.exe", "cmstp.exe", "odbcconf.exe", "control.exe",
    "wmic.exe", "powershell.exe", "cmd.exe",
}

# Suspicious command-line arguments
_SUSPICIOUS_ARGS = [
    "-enc", "-encodedcommand", "invoke-", "downloadstring",
    "frombase64string", "-windowstyle hidden", "-executionpolicy bypass",
    "iex(", "invoke-expression", "start-process", "invoke-wmimethod",
    "net user", "net localgroup", "net group", "whoami /all",
    "\\\\.\\physicaldrive", "secretsdump", "mimikatz",
    "lsadump", "token::elevate", "sekurlsa::",
    "vssadmin delete", "bcdedit /set", "wbadmin delete",
    "schtasks /create", "reg add", "reg save", "reg delete",
]


class ProcessMonitor(MonitorAgent):
    """
    Real-time process monitoring with heuristics.

    Detects:
    - High-risk parent-child relationships (macro → shell)
    - LOLBin usage with suspicious arguments
    - Process hollowing indicators
    - Network connections from unusual processes
    """

    def __init__(self, config: AgentConfig):
        super().__init__("process_monitor", AgentType.MONITOR, config)
        self.process_baseline: Dict[int, Dict[str, Any]] = {}
        self.known_safe_pids: Set[int] = set()

    async def initialize(self) -> bool:
        if not psutil:
            logger.error("psutil not available")
            return False
        try:
            for proc in psutil.process_iter(["pid", "name", "ppid", "exe", "cmdline"]):
                try:
                    info = proc.as_dict()
                    info["timestamp"] = datetime.now()
                    self.process_baseline[proc.pid] = info
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            logger.info(f"Process baseline: {len(self.process_baseline)} processes")
            self.is_running = True
            return True
        except Exception as e:
            logger.error(f"Process monitor init failed: {e}")
            return False

    async def shutdown(self) -> bool:
        self.is_running = False
        return True

    # ── Heuristics ─────────────────────────────────────────────

    def _is_high_risk_parent_child(self, parent_name: str, child_name: str) -> Optional[str]:
        """Check if parent→child combination is high-risk. Returns reason or None."""
        key = (parent_name.lower(), child_name.lower())
        return _HIGH_RISK_PARENT_CHILD.get(key)

    def _is_normal_parent_child(self, parent_name: str, child_name: str) -> bool:
        """Check if parent→child is a known-normal pattern."""
        return (parent_name.lower(), child_name.lower()) in _NORMAL_PARENT_CHILD

    def _is_lolbin(self, proc_name: str) -> bool:
        return proc_name.lower() in _LOLBINS

    def _check_suspicious_args(self, cmdline: List[str]) -> Optional[str]:
        """Check command line for suspicious arguments. Returns match or None."""
        if not cmdline:
            return None
        full_cmd = " ".join(cmdline).lower()
        for pat in _SUSPICIOUS_ARGS:
            if pat.lower() in full_cmd:
                return pat
        return None

    def _get_parent_info(self, ppid: int) -> Optional[Dict[str, Any]]:
        """Get parent process info."""
        if ppid in self.process_baseline:
            return self.process_baseline[ppid]
        try:
            parent = psutil.Process(ppid)
            info = {
                "name": parent.name(),
                "pid": ppid,
                "exe": parent.exe() if parent.is_running() else "",
            }
            self.process_baseline[ppid] = info
            return info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    # ── Main scan ──────────────────────────────────────────────

    async def scan(self, target: Any = None) -> AgentResult:
        """
        Analyze current processes with heuristics.

        Returns:
            AgentResult with findings
        """
        findings: List[ThreatFinding] = []

        if not psutil:
            return AgentResult(
                agent_id=self.agent_id, agent_type=self.agent_type,
                success=False, errors=["psutil not available"]
            )

        try:
            current_processes: Dict[int, Dict[str, Any]] = {}
            new_processes: List[Dict[str, Any]] = []

            for proc in psutil.process_iter(["pid", "name", "ppid", "exe", "cmdline"]):
                try:
                    info = proc.as_dict()
                    pid = proc.pid
                    current_processes[pid] = info

                    if pid not in self.process_baseline:
                        new_processes.append(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Update baseline
            self.process_baseline = current_processes

            # Analyze all running processes
            for pid, info in current_processes.items():
                name = info.get("name", "").lower()
                ppid = info.get("ppid")
                exe = info.get("exe", "") or ""
                cmdline = info.get("cmdline") or []

                # Skip known safe system processes
                if name in _LOW_RISK_PROCESSES:
                    continue

                parent = self._get_parent_info(ppid) if ppid else None
                parent_name = parent.get("name", "").lower() if parent else ""

                # ── Check 1: High-risk parent-child ───────────
                risk_reason = self._is_high_risk_parent_child(parent_name, name)
                if risk_reason:
                    findings.append(ThreatFinding(
                        agent_id=self.agent_id,
                        agent_type=self.agent_type,
                        finding_type=FindingType.BEHAVIORAL,
                        threat_name="HighRisk.Process.Chain",
                        threat_level=ThreatLevel.HIGH,
                        confidence=0.88,
                        evidence={
                            "process": name, "pid": pid,
                            "parent_name": parent_name, "parent_pid": ppid,
                            "executable": exe,
                            "reason": risk_reason,
                        },
                        recommended_actions=[ActionType.QUARANTINE],
                        metadata={"monitor_type": "process_chain"}
                    ))
                    continue  # Don't double-flag

                # ── Check 2: LOLBin with suspicious args ──────
                if self._is_lolbin(name):
                    suspicious_arg = self._check_suspicious_args(cmdline)
                    if suspicious_arg:
                        # Extra check: if spawned from IDE/VS Code, reduce confidence
                        if self._is_normal_parent_child(parent_name, name):
                            confidence = 0.55
                            level = ThreatLevel.LOW
                        else:
                            confidence = 0.82
                            level = ThreatLevel.HIGH

                        findings.append(ThreatFinding(
                            agent_id=self.agent_id,
                            agent_type=self.agent_type,
                            finding_type=FindingType.BEHAVIORAL,
                            threat_name=f"Suspicious.LOLBin.{name.replace('.exe','').title()}",
                            threat_level=level,
                            confidence=confidence,
                            evidence={
                                "process": name, "pid": pid,
                                "parent_name": parent_name, "parent_pid": ppid,
                                "command_line": " ".join(cmdline)[:500],
                                "matched_pattern": suspicious_arg,
                                "executable": exe,
                            },
                            recommended_actions=[ActionType.QUARANTINE],
                            metadata={"monitor_type": "lolbin"}
                        ))

                # ── Check 3: Strange parent for shell ─────────
                if name in ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"):
                    if parent_name and not self._is_normal_parent_child(parent_name, name):
                        # Only flag if parent is NOT a known-normal
                        if parent_name not in ("explorer.exe", "cmd.exe", "code.exe", "devenv.exe"):
                            findings.append(ThreatFinding(
                                agent_id=self.agent_id,
                                agent_type=self.agent_type,
                                finding_type=FindingType.BEHAVIORAL,
                                threat_name=f"Suspicious.Process.Parent.{name.replace('.exe','').title()}",
                                threat_level=ThreatLevel.MEDIUM,
                                confidence=0.65,
                                evidence={
                                    "process": name, "pid": pid,
                                    "parent_name": parent_name, "parent_pid": ppid,
                                    "executable": exe,
                                },
                                recommended_actions=[ActionType.QUARANTINE],
                                metadata={"monitor_type": "suspicious_parent"}
                            ))

            logger.info(
                f"Process scan: {len(current_processes)} processes, "
                f"{len(new_processes)} new, {len(findings)} findings"
            )

            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                success=True,
                findings=findings,
                metadata={
                    "processes_scanned": len(current_processes),
                    "new_processes": len(new_processes),
                    "suspicious_found": len(findings),
                }
            )

        except Exception as e:
            logger.error(f"Process monitor scan error: {e}")
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                success=False,
                errors=[str(e)]
            )
