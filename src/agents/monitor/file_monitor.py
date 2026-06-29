"""
File System Monitor Agent - Real-time file change detection
"""

import asyncio
from pathlib import Path
from datetime import datetime
from typing import Any, List, Optional, Set

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent

from ...enums import AgentType, FindingType, ThreatLevel, ActionType
from ...models import ThreatFinding, AgentResult
from ...utils import get_logger, calculate_file_hash
from ..base_agent import MonitorAgent, AgentConfig

logger = get_logger("file_monitor")


class FileChangeHandler(FileSystemEventHandler):
    """Watchdog handler for file system events"""
    
    def __init__(self, parent_agent: "FileSystemMonitor"):
        self.parent = parent_agent
        self.suspicious_patterns = [
            '.exe', '.dll', '.scr', '.bat', '.cmd',
            '.vbs', '.js', '.ps1', '.jar', '.zip'
        ]
    
    def on_created(self, event: FileCreatedEvent) -> None:
        """Handle file creation"""
        if event.is_directory:
            return
        
        file_path = event.src_path
        
        # Check if suspicious file type
        if any(file_path.lower().endswith(ext) for ext in self.suspicious_patterns):
            logger.warning(f"Suspicious file created: {file_path}")
            self.parent.suspicious_files.add(file_path)
    
    def on_modified(self, event: FileModifiedEvent) -> None:
        """Handle file modification"""
        if event.is_directory:
            return
        
        file_path = event.src_path
        
        # Check for rapid modifications (possible malware)
        if file_path in self.parent.modification_count:
            self.parent.modification_count[file_path] += 1
        else:
            self.parent.modification_count[file_path] = 1


class FileSystemMonitor(MonitorAgent):
    """
    Real-time file system monitoring agent
    
    Detects:
    - Suspicious file creation
    - Rapid file modifications
    - Changes to critical directories
    - Archive extraction
    """
    
    def __init__(self, config: AgentConfig):
        super().__init__("file_monitor", AgentType.MONITOR, config)
        self.observer: Optional[Observer] = None
        self.watch_paths = [
            str(Path.home() / "Downloads"),
            str(Path.home() / "Desktop"),
            str(Path.home() / "Documents"),
        ]
        self.suspicious_files: Set[str] = set()
        self.modification_count = {}
        self.event_handler = FileChangeHandler(self)
    
    async def initialize(self) -> bool:
        """Initialize file system monitor"""
        try:
            self.observer = Observer()
            
            # Schedule watchers for key directories
            for watch_path in self.watch_paths:
                path = Path(watch_path)
                if path.exists():
                    self.observer.schedule(
                        self.event_handler,
                        str(path),
                        recursive=False
                    )
                    logger.info(f"Monitoring: {watch_path}")
            
            self.observer.start()
            logger.info("File system monitor started")
            self.is_running = True
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize file monitor: {e}")
            return False
    
    async def shutdown(self) -> bool:
        """Shutdown file system monitor"""
        try:
            if self.observer:
                self.observer.stop()
                self.observer.join(timeout=5)
            self.is_running = False
            logger.info("File system monitor stopped")
            return True
        except Exception as e:
            logger.error(f"Failed to shutdown file monitor: {e}")
            return False
    
    async def scan(self, target: Any) -> AgentResult:
        """
        Generate report of suspicious activity
        
        Args:
            target: Target path or "recent" for recent activity
        
        Returns:
            AgentResult with findings
        """
        findings: List[ThreatFinding] = []
        
        try:
            # Analyze suspicious files
            for file_path in list(self.suspicious_files):
                if not Path(file_path).exists():
                    self.suspicious_files.discard(file_path)
                    continue
                
                try:
                    file_size = Path(file_path).stat().st_size
                    file_hash = calculate_file_hash(file_path)
                    
                    # Check modification count
                    mod_count = self.modification_count.get(file_path, 0)
                    
                    # High mod count = possible suspicious behavior
                    if mod_count > 50:
                        finding = ThreatFinding(
                            agent_id=self.agent_id,
                            agent_type=self.agent_type,
                            finding_type=FindingType.BEHAVIORAL,
                            threat_name="Suspicious.File.Behavior",
                            threat_level=ThreatLevel.MEDIUM,
                            confidence=0.7,
                            evidence={
                                "file_path": file_path,
                                "file_size": file_size,
                                "modifications": mod_count,
                                "detection_method": "Behavioral analysis"
                            },
                            recommended_actions=[ActionType.QUARANTINE],
                            metadata={
                                "file_hash": file_hash,
                                "monitor_type": "behavior"
                            }
                        )
                        findings.append(finding)
                
                except Exception as e:
                    logger.error(f"Error analyzing {file_path}: {e}")
            
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                success=True,
                findings=findings,
                metadata={
                    "suspicious_files": len(self.suspicious_files),
                    "files_analyzed": len(findings)
                }
            )
        
        except Exception as e:
            logger.error(f"File monitor scan error: {e}")
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                success=False,
                errors=[str(e)]
            )
