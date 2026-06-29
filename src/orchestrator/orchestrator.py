"""
Main Orchestrator - Coordinates all agents and manages scan workflows
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
import asyncio
import uuid

from ..enums import AgentType, ScanType, Status
from ..models import ScanResult, AgentResult, ThreatReport
from ..agents import BaseAgent
from ..utils import get_logger
from .state_manager import StateManager
from .priority_queue import PriorityTaskQueue

logger = get_logger("orchestrator")


class Orchestrator:
    """
    Central orchestrator that coordinates all agents
    
    Responsibilities:
    - Register and manage agents
    - Execute multi-agent scans
    - Aggregate results from multiple agents
    - Generate threat reports
    - Coordinate with approval workflow
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.agents: Dict[str, BaseAgent] = {}
        self.state_manager = StateManager()
        self.task_queue = PriorityTaskQueue()
        self.active_scans: Dict[str, ScanResult] = {}
        
        self.max_parallel_agents = config.get('max_parallel_agents', 5)
        self.agent_timeout = config.get('agent_timeout_seconds', 30)
        
        logger.info("Orchestrator initialized")
    
    def register_agent(self, agent: BaseAgent) -> None:
        """Register an agent with the orchestrator"""
        self.agents[agent.agent_id] = agent
        logger.info(f"Registered agent: {agent.agent_id} ({agent.agent_type.value})")
    
    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        """Get agent by ID"""
        return self.agents.get(agent_id)
    
    def get_agents_by_type(self, agent_type: AgentType) -> List[BaseAgent]:
        """Get all agents of a specific type"""
        return [
            agent for agent in self.agents.values()
            if agent.agent_type == agent_type
        ]
    
    async def initialize_all_agents(self) -> Dict[str, bool]:
        """Initialize all registered agents"""
        results = {}
        
        for agent_id, agent in self.agents.items():
            try:
                success = await agent.initialize()
                results[agent_id] = success
                logger.info(f"Agent {agent_id}: {'initialized' if success else 'failed'}")
            except Exception as e:
                results[agent_id] = False
                logger.error(f"Failed to initialize {agent_id}: {e}")
        
        return results
    
    async def shutdown_all_agents(self) -> None:
        """Shutdown all agents"""
        for agent_id, agent in self.agents.items():
            try:
                await agent.shutdown()
                logger.info(f"Agent {agent_id} shut down")
            except Exception as e:
                logger.error(f"Error shutting down {agent_id}: {e}")
    
    async def run_scan(
        self,
        scan_type: ScanType,
        target: Any,
        agent_ids: Optional[List[str]] = None
    ) -> ScanResult:
        """
        Execute a multi-agent scan
        
        Args:
            scan_type: Type of scan to perform
            target: Scan target (file path, directory, etc.)
            agent_ids: Specific agents to use (None = all applicable agents)
        
        Returns:
            ScanResult with aggregated findings
        """
        scan_id = f"scan_{uuid.uuid4().hex[:8]}"
        
        logger.info(f"Starting {scan_type.value} scan: {scan_id}")
        
        # Create scan result object
        scan_result = ScanResult(
            scan_id=scan_id,
            scan_type=scan_type.value,
            target=str(target),
            status=Status.RUNNING,
            started_at=datetime.now()
        )
        
        self.active_scans[scan_id] = scan_result
        
        try:
            # Determine which agents to use
            agents_to_run = self._select_agents_for_scan(scan_type, agent_ids)
            
            if not agents_to_run:
                scan_result.status = Status.FAILED
                scan_result.errors.append("No agents available for this scan type")
                return scan_result
            
            scan_result.agents_used = [agent.agent_id for agent in agents_to_run]
            
            # Run agents in parallel
            agent_results = await self._run_agents_parallel(agents_to_run, target)
            
            # Aggregate results
            scan_result.agent_results = agent_results
            scan_result = self._aggregate_results(scan_result)
            
            # Mark as completed
            scan_result.status = Status.COMPLETED
            scan_result.completed_at = datetime.now()
            scan_result.duration_seconds = (
                scan_result.completed_at - scan_result.started_at
            ).total_seconds()
            
            logger.info(
                f"Scan {scan_id} completed: "
                f"{scan_result.files_scanned} files, "
                f"{scan_result.threats_found} threats"
            )
            
        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            scan_result.status = Status.FAILED
            scan_result.errors.append(str(e))
        
        finally:
            # Save state
            self.state_manager.save_scan_result(scan_result)
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]
        
        return scan_result
    
    def _select_agents_for_scan(
        self,
        scan_type: ScanType,
        agent_ids: Optional[List[str]] = None
    ) -> List[BaseAgent]:
        """Select which agents should participate in this scan"""
        
        if agent_ids:
            # Use specific agents requested
            return [
                self.agents[aid] for aid in agent_ids
                if aid in self.agents and self.agents[aid].config.enabled
            ]
        
        # Default: use all scanner agents for now
        # TODO: More sophisticated selection based on scan_type
        return [
            agent for agent in self.agents.values()
            if agent.agent_type == AgentType.SCANNER and agent.config.enabled
        ]
    
    async def _run_agents_parallel(
        self,
        agents: List[BaseAgent],
        target: Any
    ) -> List[AgentResult]:
        """Run multiple agents in parallel with concurrency limit"""
        
        semaphore = asyncio.Semaphore(self.max_parallel_agents)
        
        async def run_with_semaphore(agent: BaseAgent) -> AgentResult:
            async with semaphore:
                logger.info(f"Running agent: {agent.agent_id}")
                try:
                    result = await agent.run_with_timeout(target)
                    return result
                except Exception as e:
                    logger.error(f"Agent {agent.agent_id} error: {e}")
                    return AgentResult(
                        agent_id=agent.agent_id,
                        agent_type=agent.agent_type,
                        success=False,
                        errors=[str(e)]
                    )
        
        # Run all agents
        results = await asyncio.gather(
            *[run_with_semaphore(agent) for agent in agents],
            return_exceptions=True
        )
        
        # Filter out exceptions
        valid_results = [
            r for r in results
            if isinstance(r, AgentResult)
        ]
        
        return valid_results
    
    def _aggregate_results(self, scan_result: ScanResult) -> ScanResult:
        """Aggregate results from all agents"""
        
        total_files = 0
        total_threats = 0
        
        for agent_result in scan_result.agent_results:
            if agent_result.success:
                # Count files scanned (avoid double counting)
                # For now, take max as rough estimate
                files = agent_result.metadata.get('files_scanned', 0)
                total_files = max(total_files, files)
                
                # Count threats
                total_threats += len(agent_result.findings)
        
        scan_result.files_scanned = total_files
        scan_result.threats_found = total_threats
        
        return scan_result
    
    def get_active_scans(self) -> List[ScanResult]:
        """Get all currently active scans"""
        return list(self.active_scans.values())
    
    def get_scan_status(self, scan_id: str) -> Optional[ScanResult]:
        """Get status of a specific scan"""
        # Check active scans first
        if scan_id in self.active_scans:
            return self.active_scans[scan_id]
        
        # Check saved results
        return self.state_manager.load_scan_result(scan_id)
    
    async def stop_scan(self, scan_id: str) -> bool:
        """Stop an active scan"""
        if scan_id not in self.active_scans:
            return False
        
        scan = self.active_scans[scan_id]
        scan.status = Status.STOPPED
        
        logger.info(f"Scan {scan_id} stopped by user")
        
        return True
