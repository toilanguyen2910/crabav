"""
Data models for CrabAV
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict
from .enums import AgentType, ThreatLevel, FindingType, ActionType, Status


class ThreatFinding(BaseModel):
    """A single threat finding from an agent"""
    agent_id: str
    agent_type: AgentType
    finding_type: FindingType
    threat_name: str
    threat_level: ThreatLevel
    evidence: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=datetime.now)
    recommended_actions: List[ActionType] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    model_config = ConfigDict(use_enum_values=True)


class AgentResult(BaseModel):
    """Result from an agent scan"""
    agent_id: str
    agent_type: AgentType
    success: bool
    findings: List[ThreatFinding] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)
    duration_seconds: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.now)
    
    model_config = ConfigDict(use_enum_values=True)


class ScanResult(BaseModel):
    """Result from a complete scan"""
    scan_id: str
    scan_type: str
    target: str
    status: Status
    files_scanned: int = 0
    threats_found: int = 0
    agents_used: List[str] = Field(default_factory=list)
    agent_results: List[AgentResult] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    errors: List[str] = Field(default_factory=list)
    
    model_config = ConfigDict(use_enum_values=True)


class ThreatReport(BaseModel):
    """User-facing threat report"""
    threat_id: str
    threat_name: str
    threat_level: ThreatLevel
    risk_score: float = Field(ge=0.0, le=100.0)
    file_path: str
    file_size: int = 0
    file_hash: Optional[str] = None
    findings: List[ThreatFinding] = Field(default_factory=list)
    recommended_actions: List[ActionType] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.now)
    status: Status = Status.PENDING
    
    model_config = ConfigDict(use_enum_values=True)


class QuarantineRecord(BaseModel):
    """Record of a quarantined file"""
    quarantine_id: str
    threat_id: str
    original_path: str
    quarantined_path: str
    backup_path: Optional[str] = None
    file_hash: Optional[str] = None
    file_size: int = 0
    reason: str = ""
    encrypted: bool = True
    quarantined_at: datetime = Field(default_factory=datetime.now)
    auto_delete_at: Optional[datetime] = None
    
    model_config = ConfigDict(use_enum_values=True)


class WhitelistEntry(BaseModel):
    """Whitelist entry"""
    entry_id: str
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    reason: str = ""
    whitelisted_at: datetime = Field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    
    model_config = ConfigDict(use_enum_values=True)


class ApprovalRequest(BaseModel):
    """User approval request"""
    request_id: str
    threat_report: ThreatReport
    requested_action: ActionType
    requested_at: datetime = Field(default_factory=datetime.now)
    approved: Optional[bool] = None
    approved_at: Optional[datetime] = None
    approved_action: Optional[ActionType] = None
    user_notes: Optional[str] = None
    
    model_config = ConfigDict(use_enum_values=True)
