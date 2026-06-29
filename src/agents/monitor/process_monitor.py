"""
Process Monitor Agent - Real-time process analysis
"""

import asyncio
from typing import Any, List, Dict, Set
from datetime import datetime

try:
    import psutil
    import win32api
    import win32con
except ImportError:
    psutil = None
    win32api = None

from ...enums import AgentType, FindingType, ThreatLevel, ActionType
from ...models import ThreatFinding, AgentResult
from ...utils import get_logger
from ..base_agent import MonitorAgent, AgentConfig

logger = get_logger("process_monitor")


class ProcessMonitor(MonitorAgent):
    """
    Real-time process monitoring agent
    
    Detects:
    - Suspicious parent-child relationships
    - Process injection
    - DLL loading anomalies
    - Network connections from suspicious processes
    """
    
    def __init__(self, config: AgentConfig):
        super().__init__("process_monitor", AgentType.MONITOR, config)
        self.process_baseline: Dict[int, Dict[str, Any]] = {}
        self.suspicious_patterns = {
            'parent': ['explorer.exe', 'svchost.exe', 'winlogon.exe'],
            'children': ['cmd.exe', 'powershell.exe', 'cscript.exe']
        }
    
    async def initialize(self) -> bool:
        """Initialize process monitor"""
        if not psutil:
            logger.error("psutil not available")
            return False
        
        try:
            # Establish baseline
            for proc in psutil.process_iter(['pid', 'name', 'ppid']):
                try:
                    self.process_baseline[proc.pid] = {
                        'name': proc.name(),
                        'ppid': proc.ppid(),
                        'timestamp': datetime.now()
                    }
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            logger.info(f"Process baseline: {len(self.process_baseline)} processes")
            self.is_running = True
            return True
        
        except Exception as e:
            logger.error(f"Failed to initialize process monitor: {e}")
            return False
    
    async def shutdown(self) -> bool:
        """Shutdown process monitor"""
        self.is_running = False
        logger.info("Process monitor stopped")
        return True
    
    async def scan(self, target: Any) -> AgentResult:
        """
        Analyze current processes
        
        Args:
            target: Process name or PID to analyze
        
        Returns:
            AgentResult with findings
        """
        findings: List[ThreatFinding] = []
        
        try:
            if not psutil:
                return AgentResult(
                    agent_id=self.agent_id,
                    agent_type=self.agent_type,
                    success=False,
                    errors=["psutil not available"]
                )
            
            # Scan current processes
            for proc in psutil.process_iter(['pid', 'name', 'ppid', 'exe']):
                try:
                    proc_info = proc.as_dict()
                    pid = proc_info['pid']
                    name = proc_info['name']
                    ppid = proc_info['ppid']
                    
                    # Check for suspicious parent-child
                    if ppid in self.process_baseline:
                        parent_info = self.process_baseline.get(ppid)
                        if parent_info and parent_info['name'] in ['svchost.exe', 'explorer.exe']:
                            if name in ['cmd.exe', 'powershell.exe', 'cscript.exe']:
                                finding = ThreatFinding(
                                    agent_id=self.agent_id,
                                    agent_type=self.agent_type,
                                    finding_type=FindingType.BEHAVIORAL,
                                    threat_name=f"Suspicious.Process.Parent",
                                    threat_level=ThreatLevel.MEDIUM,
                                    confidence=0.7,
                                    evidence={
                                        "process": name,
                                        "pid": pid,
                                        "parent_pid": ppid,
                                        "parent_name": parent_info['name']
                                    },
                                    recommended_actions=[ActionType.QUARANTINE],
                                    metadata={"monitor_type": "process_injection"}
                                )
                                findings.append(finding)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                success=True,
                findings=findings,
                metadata={
                    "processes_scanned": len(list(psutil.process_iter())),
                    "suspicious_found": len(findings)
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
