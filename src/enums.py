"""
Enum definitions for CrabAV
"""

from enum import Enum, IntEnum


class AgentType(Enum):
    """Types of agents in the system"""
    SCANNER = "scanner"
    MONITOR = "monitor"
    ANALYSIS = "analysis"
    DECISION = "decision"


class ThreatLevel(IntEnum):
    """Threat severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    
    @classmethod
    def from_score(cls, score: float) -> "ThreatLevel":
        """Convert threat score (0-100) to threat level"""
        if score < 30:
            return cls.LOW
        elif score < 50:
            return cls.MEDIUM
        elif score < 70:
            return cls.HIGH
        else:
            return cls.CRITICAL


class ScanType(Enum):
    """Types of scans"""
    QUICK = "quick"
    FULL = "full"
    CUSTOM = "custom"
    ON_DEMAND = "on_demand"
    SCHEDULED = "scheduled"


class Status(Enum):
    """Status enums"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED = "paused"
    STOPPED = "stopped"


class ActionType(Enum):
    """User-approved actions"""
    QUARANTINE = "quarantine"
    DELETE = "delete"
    WHITELIST = "whitelist"
    RESTORE = "restore"
    IGNORE = "ignore"


class AgentStatus(Enum):
    """Agent status"""
    IDLE = "idle"
    INITIALIZING = "initializing"
    RUNNING = "running"
    SCANNING = "scanning"
    ERROR = "error"
    STOPPED = "stopped"


class FindingType(Enum):
    """Types of findings"""
    FILE_SIGNATURE = "file_signature"
    HEURISTIC = "heuristic"
    BEHAVIORAL = "behavioral"
    REGISTRY = "registry"
    PROCESS = "process"
    NETWORK = "network"
    MEMORY = "memory"
