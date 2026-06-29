"""
Approval models for CrabAV
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from enum import Enum

from ..enums import ActionType


class ApprovalStatus(Enum):
    """Status of an approval request"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class ApprovalRequest:
    """Request for user approval"""
    request_id: str
    threat_id: str
    threat_name: str
    file_path: str
    risk_score: float
    threat_level: str
    recommended_actions: list  # List of ActionType values
    requested_by: str  # Agent/Orchestrator ID
    requested_at: datetime
    expires_at: datetime
    status: ApprovalStatus = ApprovalStatus.PENDING
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    approved_action: Optional[ActionType] = None
    user_notes: Optional[str] = None
    
    def is_expired(self) -> bool:
        """Check if approval request has expired"""
        return datetime.now() > self.expires_at
    
    def is_pending(self) -> bool:
        """Check if request is still pending"""
        return self.status == ApprovalStatus.PENDING


@dataclass
class ApprovalResult:
    """Result of an approval decision"""
    request_id: str
    approved: bool
    approved_action: Optional[ActionType]
    user_notes: Optional[str]
    timestamp: datetime
