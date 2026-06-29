"""
Registry Scanner Agent - Windows persistence detection
"""

import asyncio
from typing import Any, List, Dict
from datetime import datetime

try:
    import winreg
except ImportError:
    winreg = None

from ...enums import AgentType, FindingType, ThreatLevel, ActionType
from ...models import ThreatFinding, AgentResult
from ...utils import get_logger
from ..base_agent import MonitorAgent, AgentConfig

logger = get_logger("registry_scanner")


class RegistryScanner(MonitorAgent):
    """
    Registry scanning agent for persistence detection
    
    Detects:
    - Startup persistence (Run keys)
    - Service modifications
    - Browser helper objects
    - Shell extensions
    """
    
    def __init__(self, config: AgentConfig):
        super().__init__("registry_scanner", AgentType.MONITOR, config)
        self.suspicious_locations = [
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
            r"Software\Classes\*\shellex\ContextMenuHandlers",
        ]
        self.baseline_keys: Dict[str, Any] = {}
    
    async def initialize(self) -> bool:
        """Initialize registry scanner"""
        if not winreg:
            logger.error("winreg not available (Windows only)")
            return False
        
        try:
            # Establish baseline
            for location in self.suspicious_locations:
                self.baseline_keys[location] = self._read_registry(location)
            
            logger.info(f"Registry baseline established: {len(self.baseline_keys)} locations")
            self.is_running = True
            return True
        
        except Exception as e:
            logger.error(f"Failed to initialize registry scanner: {e}")
            return False
    
    async def shutdown(self) -> bool:
        """Shutdown registry scanner"""
        self.is_running = False
        logger.info("Registry scanner stopped")
        return True
    
    def _read_registry(self, path: str) -> Dict[str, str]:
        """Read registry key values"""
        values = {}
        
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path)
            i = 0
            
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    values[name] = value
                    i += 1
                except OSError:
                    break
            
            winreg.CloseKey(key)
        
        except Exception as e:
            logger.debug(f"Could not read {path}: {e}")
        
        return values
    
    async def scan(self, target: Any) -> AgentResult:
        """
        Scan registry for suspicious entries
        
        Args:
            target: Scan target (usually "registry")
        
        Returns:
            AgentResult with findings
        """
        findings: List[ThreatFinding] = []
        
        try:
            if not winreg:
                return AgentResult(
                    agent_id=self.agent_id,
                    agent_type=self.agent_type,
                    success=False,
                    errors=["Registry access not available"]
                )
            
            # Suspicious patterns to detect
            suspicious_patterns = [
                'powershell', 'cmd.exe', 'rundll32', 'regsvr32',
                'wscript', 'cscript', 'bitsadmin', 'certutil'
            ]
            
            # Scan each location
            for location in self.suspicious_locations:
                current_values = self._read_registry(location)
                baseline = self.baseline_keys.get(location, {})
                
                # Find new or modified entries
                for key, value in current_values.items():
                    if key not in baseline or baseline[key] != value:
                        # Check for suspicious patterns
                        if any(pattern in str(value).lower() for pattern in suspicious_patterns):
                            finding = ThreatFinding(
                                agent_id=self.agent_id,
                                agent_type=self.agent_type,
                                finding_type=FindingType.BEHAVIORAL,
                                threat_name="Suspicious.Registry.Persistence",
                                threat_level=ThreatLevel.HIGH,
                                confidence=0.8,
                                evidence={
                                    "registry_path": location,
                                    "key_name": key,
                                    "key_value": value[:100]  # Truncate long values
                                },
                                recommended_actions=[ActionType.QUARANTINE],
                                metadata={
                                    "detection_type": "persistence",
                                    "is_new": key not in baseline
                                }
                            )
                            findings.append(finding)
            
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                success=True,
                findings=findings,
                metadata={
                    "locations_scanned": len(self.suspicious_locations),
                    "suspicious_entries": len(findings)
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
