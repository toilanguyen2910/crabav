"""
Base agent class for CrabAV
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import asyncio

from ..enums import AgentType, ThreatLevel, Status, AgentStatus
from ..models import ThreatFinding, AgentResult


@dataclass
class AgentConfig:
    """Configuration for an agent"""
    agent_id: str
    enabled: bool = True
    timeout_seconds: int = 30


class BaseAgent(ABC):
    """
    Base class for all CrabAV agents
    
    Each agent should implement:
    - scan(): Execute the main scanning/monitoring logic
    - initialize(): Setup agent resources
    - shutdown(): Cleanup agent resources
    """
    
    def __init__(self, agent_id: str, agent_type: AgentType, config: AgentConfig):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.config = config
        self.status = AgentStatus.IDLE
        self.last_run: Optional[datetime] = None
        self.last_result: Optional[AgentResult] = None
        self.is_running = False
    
    @abstractmethod
    async def scan(self, target: Any) -> AgentResult:
        """Execute the agent's scanning/monitoring logic"""
        pass
    
    async def initialize(self) -> bool:
        """Initialize agent resources. Override if needed."""
        self.status = AgentStatus.IDLE
        return True
    
    async def shutdown(self) -> bool:
        """Cleanup agent resources. Override if needed."""
        self.status = AgentStatus.STOPPED
        self.is_running = False
        return True
    
    async def run_with_timeout(self, target: Any) -> AgentResult:
        """Run scan with timeout protection"""
        try:
            result = await asyncio.wait_for(
                self.scan(target),
                timeout=self.config.timeout_seconds
            )
            return result
        except asyncio.TimeoutError:
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                success=False,
                errors=[f"Agent {self.agent_id} timed out after {self.config.timeout_seconds}s"]
            )
        except Exception as e:
            return AgentResult(
                agent_id=self.agent_id,
                agent_type=self.agent_type,
                success=False,
                errors=[f"Agent {self.agent_id} error: {str(e)}"]
            )
    
    def report_finding(self, finding: ThreatFinding) -> None:
        """Report a finding. Override to add custom behavior."""
        # Default implementation: just store in memory
        pass
    
    def get_status(self) -> Dict[str, Any]:
        """Get agent status"""
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type.value,
            "status": self.status.value,
            "enabled": self.config.enabled,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "last_result_success": self.last_result.success if self.last_result else None,
            "is_running": self.is_running
        }
    
    async def __aenter__(self):
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.shutdown()


class ScannerAgent(BaseAgent):
    """Base class for scanner agents"""
    pass


class MonitorAgent(BaseAgent):
    """Base class for monitor agents"""
    pass


class AnalysisAgent(BaseAgent):
    """Base class for analysis agents"""
    pass
