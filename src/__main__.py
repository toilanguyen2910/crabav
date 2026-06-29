"""
CrabAV Main Application Entry Point
"""

import asyncio
import sys
from pathlib import Path
from typing import Optional

from .config import load_config
from .orchestrator import Orchestrator
from .decision import DecisionEngine
from .approval import ApprovalHandler
from .quarantine import QuarantineManager
from .engine import ActionExecutor
from .agents.scanner import FileScanner
from .agents.monitor import FileSystemMonitor
from .agents import AgentConfig
from .utils import setup_logger, get_logger, validate_scan_path

logger = get_logger("main")


class CrabAVApp:
    """
    Main CrabAV Application
    
    Coordinates all components:
    - Orchestrator (agent coordination)
    - Decision Engine (threat scoring)
    - Approval Handler (user control)
    - Quarantine Manager (file isolation)
    - Action Executor (execute decisions)
    """
    
    def __init__(self, config_path: Optional[str] = None):
        # Load configuration
        self.config = load_config(config_path)
        
        # Setup logging
        log_config = self.config.logging
        setup_logger(
            level=log_config.level,
            log_file="./logs/crabav.log"
        )
        
        logger.info("=" * 60)
        logger.info("CrabAV - Free Multi-Agent Antivirus")
        logger.info("Version: 0.1.0")
        logger.info("=" * 60)
        
        # Initialize components
        self.quarantine = QuarantineManager(
            quarantine_dir=self.config.quarantine.storage_path
        )
        
        self.action_executor = ActionExecutor(self.quarantine)
        
        self.approval_handler = ApprovalHandler(
            approval_timeout_minutes=30,
            auto_reject_timeout_minutes=60
        )
        
        self.decision_engine = DecisionEngine(
            config=self.config.decision.model_dump()
        )
        
        self.orchestrator = Orchestrator(
            config=self.config.orchestrator.model_dump()
        )
        
        # Register agents
        self._register_agents()
        
        logger.info("CrabAV initialized successfully")
    
    def _register_agents(self) -> None:
        """Register all available agents"""
        
        # Scanner agents
        if self.config.agents.file_scanner.enabled:
            file_scanner = FileScanner(
                config=AgentConfig(
                    agent_id="file_scanner",
                    enabled=True,
                    timeout_seconds=60
                )
            )
            self.orchestrator.register_agent(file_scanner)
        
        # Monitor agents
        if self.config.agents.file_monitor.enabled:
            file_monitor = FileSystemMonitor(
                config=AgentConfig(
                    agent_id="file_monitor",
                    enabled=True,
                    timeout_seconds=30
                )
            )
            self.orchestrator.register_agent(file_monitor)
        
        logger.info(f"Registered {len(self.orchestrator.agents)} agents")
    
    async def start(self) -> None:
        """Start the application"""
        logger.info("Starting CrabAV...")
        
        # Initialize all agents
        init_results = await self.orchestrator.initialize_all_agents()
        
        success_count = sum(1 for v in init_results.values() if v)
        logger.info(f"Initialized {success_count}/{len(init_results)} agents")
        
        # Start task queue
        await self.orchestrator.task_queue.start()
        
        logger.info("CrabAV is running!")
    
    async def stop(self) -> None:
        """Stop the application"""
        logger.info("Stopping CrabAV...")
        
        # Stop task queue
        await self.orchestrator.task_queue.stop()
        
        # Shutdown agents
        await self.orchestrator.shutdown_all_agents()
        
        logger.info("CrabAV stopped")
    
    async def scan(self, target: str, scan_type: str = "quick") -> dict:
        """
        Run a scan
        
        Args:
            target: Path to scan
            scan_type: Type of scan (quick/full/custom)
        
        Returns:
            Scan result dictionary
        """
        from .enums import ScanType
        
        scan_type_map = {
            "quick": ScanType.QUICK,
            "full": ScanType.FULL,
            "custom": ScanType.CUSTOM
        }
        
        st = scan_type_map.get(scan_type, ScanType.QUICK)
        
        # Run scan
        result = await self.orchestrator.run_scan(st, target)
        
        # Analyze findings
        if result.agent_results:
            threat_report = self.decision_engine.analyze_findings(
                result.agent_results
            )
            
            if threat_report:
                from .enums import ThreatLevel
                tl = threat_report.threat_level
                tl_name = tl.name if hasattr(tl, 'name') else ThreatLevel(tl).name
                
                # Generate approval request
                approval_req = self.approval_handler.generate_request(
                    threat_id=threat_report.threat_id,
                    threat_name=threat_report.threat_name,
                    file_path=threat_report.file_path,
                    risk_score=threat_report.risk_score,
                    threat_level=tl_name,
                    recommended_actions=threat_report.recommended_actions,
                    source_agent="orchestrator"
                )
                
                logger.info(
                    f"Threat detected: {threat_report.threat_name} "
                    f"(score={threat_report.risk_score})"
                )
                logger.info(f"Approval required: {approval_req.request_id}")
        
        return {
            "scan_id": result.scan_id,
            "status": result.status.value,
            "files_scanned": result.files_scanned,
            "threats_found": result.threats_found,
            "duration": result.duration_seconds
        }
    
    def get_status(self) -> dict:
        """Get system status"""
        return {
            "agents": [
                agent.get_status()
                for agent in self.orchestrator.agents.values()
            ],
            "active_scans": len(self.orchestrator.get_active_scans()),
            "pending_approvals": len(self.approval_handler.get_pending_requests()),
            "quarantine_size": self.quarantine.get_quarantine_size()
        }


async def main():
    """Main entry point"""
    app = CrabAVApp()
    
    try:
        await app.start()
        
        # Example: Run a quick scan
        if len(sys.argv) > 1:
            target = sys.argv[1]
            try:
                validated = validate_scan_path(target)
                result = await app.scan(str(validated), "quick")
                print(f"\nScan complete: {result}")
            except ValueError as e:
                print(f"\nError: Invalid scan target — {e}")
                sys.exit(1)
        else:
            # Interactive mode
            print("\nCrabAV is running. Press Ctrl+C to stop.")
            
            # Keep running
            while True:
                await asyncio.sleep(1)
    
    except KeyboardInterrupt:
        print("\n\nShutting down...")
    
    finally:
        await app.stop()


if __name__ == "__main__":
    asyncio.run(main())
