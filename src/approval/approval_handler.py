"""
Approval Handler - Manages user approval workflow
"""

import asyncio
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime, timedelta
import uuid

from .models import ApprovalRequest, ApprovalResult, ApprovalStatus
from ..enums import ActionType
from ..utils import get_logger

logger = get_logger("approval_handler")


class ApprovalHandler:
    """
    Handles user approval workflow for threat actions
    
    Features:
    - Generate approval requests
    - Track approval status
    - Handle user responses (approve/reject)
    - Enforce approval timeout
    - Support batch approvals
    """
    
    def __init__(
        self,
        approval_timeout_minutes: int = 30,
        auto_reject_timeout_minutes: int = 60
    ):
        self.approval_timeout = timedelta(minutes=approval_timeout_minutes)
        self.auto_reject_timeout = timedelta(minutes=auto_reject_timeout_minutes)
        
        self.pending_requests: Dict[str, ApprovalRequest] = {}
        self.completed_requests: Dict[str, ApprovalResult] = {}
        
        self._callback: Optional[Callable[[ApprovalRequest], Any]] = None
        
        logger.info(
            f"ApprovalHandler initialized: "
            f"timeout={approval_timeout_minutes}min"
        )
    
    def set_callback(
        self,
        callback: Callable[[ApprovalRequest], Any]
    ) -> None:
        """Set callback function for UI display"""
        self._callback = callback
        logger.info("Approval callback set")
    
    def generate_request(
        self,
        threat_id: str,
        threat_name: str,
        file_path: str,
        risk_score: float,
        threat_level: str,
        recommended_actions: List[ActionType],
        source_agent: str
    ) -> ApprovalRequest:
        """Generate a new approval request"""
        request_id = f"approval_{uuid.uuid4().hex[:8]}"
        
        request = ApprovalRequest(
            request_id=request_id,
            threat_id=threat_id,
            threat_name=threat_name,
            file_path=file_path,
            risk_score=risk_score,
            threat_level=threat_level,
            recommended_actions=[a.value for a in recommended_actions],
            requested_by=source_agent,
            requested_at=datetime.now(),
            expires_at=datetime.now() + self.approval_timeout
        )
        
        self.pending_requests[request_id] = request
        
        logger.info(
            f"Generated approval request: {request_id} "
            f"(threat={threat_name}, risk={risk_score})"
        )
        
        # Notify UI if callback set
        if self._callback:
            try:
                self._callback(request)
            except Exception as e:
                logger.error(f"Error in approval callback: {e}")
        
        return request
    
    def approve(
        self,
        request_id: str,
        action: ActionType,
        user_id: str = "system",
        notes: Optional[str] = None
    ) -> ApprovalResult:
        """Approve an action"""
        if request_id not in self.pending_requests:
            raise ValueError(f"Approval request not found: {request_id}")
        
        request = self.pending_requests[request_id]
        
        if request.is_expired():
            raise ValueError(f"Approval request expired: {request_id}")
        
        request.status = ApprovalStatus.APPROVED
        request.approved_by = user_id
        request.approved_at = datetime.now()
        request.approved_action = action
        
        result = ApprovalResult(
            request_id=request_id,
            approved=True,
            approved_action=action,
            user_notes=notes,
            timestamp=datetime.now()
        )
        
        self._move_to_completed(request_id, result)
        
        logger.info(
            f"Approved request {request_id}: action={action.value}, "
            f"user={user_id}"
        )
        
        return result
    
    def reject(
        self,
        request_id: str,
        user_id: str = "system",
        notes: Optional[str] = None
    ) -> ApprovalResult:
        """Reject an action"""
        if request_id not in self.pending_requests:
            raise ValueError(f"Approval request not found: {request_id}")
        
        request = self.pending_requests[request_id]
        
        if request.is_expired():
            raise ValueError(f"Approval request expired: {request_id}")
        
        request.status = ApprovalStatus.REJECTED
        request.approved_by = user_id
        request.approved_at = datetime.now()
        
        result = ApprovalResult(
            request_id=request_id,
            approved=False,
            approved_action=None,
            user_notes=notes,
            timestamp=datetime.now()
        )
        
        self._move_to_completed(request_id, result)
        
        logger.info(f"Rejected request {request_id}: user={user_id}")
        
        return result
    
    def _move_to_completed(
        self,
        request_id: str,
        result: ApprovalResult
    ) -> None:
        """Move request from pending to completed"""
        self.completed_requests[request_id] = result
        if request_id in self.pending_requests:
            del self.pending_requests[request_id]
    
    def get_pending_requests(self) -> List[ApprovalRequest]:
        """Get all pending approval requests"""
        return [
            r for r in self.pending_requests.values()
            if r.is_pending() and not r.is_expired()
        ]
    
    def get_completed_requests(self) -> List[ApprovalResult]:
        """Get completed approval requests"""
        return list(self.completed_requests.values())
    
    def check_expired(self) -> List[str]:
        """Check for expired requests and return their IDs"""
        expired = []
        
        for request_id, request in list(self.pending_requests.items()):
            if request.is_expired():
                request.status = ApprovalStatus.EXPIRED
                result = ApprovalResult(
                    request_id=request_id,
                    approved=False,
                    approved_action=None,
                    user_notes="Request expired",
                    timestamp=datetime.now()
                )
                self._move_to_completed(request_id, result)
                expired.append(request_id)
        
        if expired:
            logger.info(f"Expired {len(expired)} approval requests")
        
        return expired
    
    async def wait_for_approval(
        self,
        request_id: str,
        timeout_minutes: int = 30
    ) -> Optional[ApprovalResult]:
        """
        Wait for approval result (for non-UI flows)
        
        Args:
            request_id: ID of the approval request
            timeout_minutes: Maximum wait time
        
        Returns:
            ApprovalResult or None if timeout
        """
        end_time = datetime.now() + timedelta(minutes=timeout_minutes)
        
        while datetime.now() < end_time:
            if request_id in self.completed_requests:
                return self.completed_requests[request_id]
            
            await asyncio.sleep(1)
        
        # Timeout - reject automatically
        if request_id in self.pending_requests:
            return self.reject(request_id, notes="Request timed out")
        
        return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get approval statistics"""
        expired_count = len(self.check_expired())
        
        return {
            'pending': len(self.pending_requests),
            'completed': len(self.completed_requests),
            'expired': expired_count,
            'recent': [
                {
                    'request_id': r.request_id,
                    'approved': r.approved,
                    'timestamp': r.timestamp.isoformat()
                }
                for r in list(self.completed_requests.values())[-10:]
            ]
        }
