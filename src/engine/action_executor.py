"""
Action Executor - Executes approved threat actions
"""

from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from ..enums import ActionType, Status
from ..models import ThreatReport, QuarantineRecord
from ..quarantine import QuarantineManager
from ..utils import get_logger

logger = get_logger("action_executor")


class ActionExecutor:
    """
    Executes user-approved actions on threats
    
    Supported Actions:
    - Quarantine: Move file to isolated storage
    - Delete: Permanently remove file (with backup)
    - Whitelist: Add to exception list
    - Restore: Restore from quarantine
    """
    
    def __init__(
        self,
        quarantine_manager: QuarantineManager,
        whitelist_path: str = "./data/whitelist.txt"
    ):
        self.quarantine = quarantine_manager
        self.whitelist_path = Path(whitelist_path)
        self.whitelist: set = self._load_whitelist()
        
        logger.info("ActionExecutor initialized")
    
    def _load_whitelist(self) -> set:
        """Load whitelist from file"""
        whitelist = set()
        if self.whitelist_path.exists():
            try:
                with open(self.whitelist_path, 'r') as f:
                    whitelist = set(line.strip() for line in f if line.strip())
                logger.info(f"Loaded {len(whitelist)} whitelist entries")
            except Exception as e:
                logger.error(f"Failed to load whitelist: {e}")
        return whitelist
    
    def _save_whitelist(self) -> bool:
        """Save whitelist to file"""
        try:
            self.whitelist_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.whitelist_path, 'w') as f:
                for entry in sorted(self.whitelist):
                    f.write(f"{entry}\n")
            return True
        except Exception as e:
            logger.error(f"Failed to save whitelist: {e}")
            return False
    
    def execute_action(
        self,
        action: ActionType,
        threat_report: ThreatReport
    ) -> Dict[str, Any]:
        """
        Execute an approved action
        
        Args:
            action: Action to execute
            threat_report: Threat report with file details
        
        Returns:
            Result dict with success status and details
        """
        logger.info(
            f"Executing {action.value} on {threat_report.threat_name} "
            f"(file: {threat_report.file_path})"
        )
        
        result = {
            'action': action.value,
            'threat_id': threat_report.threat_id,
            'success': False,
            'timestamp': datetime.now().isoformat(),
            'details': {}
        }
        
        try:
            if action == ActionType.QUARANTINE:
                result.update(self._execute_quarantine(threat_report))
            
            elif action == ActionType.DELETE:
                result.update(self._execute_delete(threat_report))
            
            elif action == ActionType.WHITELIST:
                result.update(self._execute_whitelist(threat_report))
            
            elif action == ActionType.RESTORE:
                result.update(self._execute_restore(threat_report))
            
            else:
                result['details']['error'] = f"Unknown action: {action}"
        
        except Exception as e:
            logger.error(f"Action execution failed: {e}")
            result['details']['error'] = str(e)
        
        return result
    
    def _execute_quarantine(self, threat_report: ThreatReport) -> Dict[str, Any]:
        """Quarantine a file"""
        file_path = threat_report.file_path
        
        if not Path(file_path).exists():
            return {
                'success': False,
                'details': {'error': 'File not found'}
            }
        
        # Move to quarantine
        record = self.quarantine.quarantine_file(
            file_path=file_path,
            threat_id=threat_report.threat_id,
            reason=f"Threat: {threat_report.threat_name}, Risk: {threat_report.risk_score}"
        )
        
        if record:
            logger.info(f"Successfully quarantined: {record.quarantine_id}")
            return {
                'success': True,
                'details': {
                    'quarantine_id': record.quarantine_id,
                    'original_path': record.original_path,
                    'quarantined_path': record.quarantined_path,
                    'backup_path': record.backup_path
                }
            }
        else:
            return {
                'success': False,
                'details': {'error': 'Quarantine operation failed'}
            }
    
    def _execute_delete(self, threat_report: ThreatReport) -> Dict[str, Any]:
        """Delete a file"""
        file_path = threat_report.file_path
        
        if not Path(file_path).exists():
            return {
                'success': False,
                'details': {'error': 'File not found'}
            }
        
        # First quarantine, then delete
        record = self.quarantine.quarantine_file(
            file_path=file_path,
            threat_id=threat_report.threat_id,
            reason=f"DELETE action: {threat_report.threat_name}"
        )
        
        if record:
            # Delete from quarantine
            deleted = self.quarantine.delete_quarantined_file(record.quarantine_id)
            
            if deleted:
                logger.info(f"Successfully deleted: {file_path}")
                return {
                    'success': True,
                    'details': {
                        'deleted_path': file_path,
                        'backup_kept': record.backup_path
                    }
                }
        
        return {
            'success': False,
            'details': {'error': 'Delete operation failed'}
        }
    
    def _execute_whitelist(self, threat_report: ThreatReport) -> Dict[str, Any]:
        """Add file to whitelist"""
        file_path = threat_report.file_path
        file_hash = threat_report.file_hash
        
        # Add by hash for security
        if file_hash:
            self.whitelist.add(file_hash)
            self._save_whitelist()
            
            logger.info(f"Added to whitelist: {file_hash} ({file_path})")
            return {
                'success': True,
                'details': {
                    'whitelisted': file_hash,
                    'file_path': file_path
                }
            }
        else:
            return {
                'success': False,
                'details': {'error': 'File hash not available'}
            }
    
    def _execute_restore(self, threat_report: ThreatReport) -> Dict[str, Any]:
        """Restore file from quarantine"""
        # Would need quarantine_id from threat report metadata
        quarantine_id = threat_report.metadata.get('quarantine_id')
        
        if not quarantine_id:
            return {
                'success': False,
                'details': {'error': 'Quarantine ID not found'}
            }
        
        original_path = threat_report.metadata.get('original_path')
        success = self.quarantine.restore_file(quarantine_id, original_path)
        
        if success:
            logger.info(f"Restored from quarantine: {quarantine_id}")
            return {
                'success': True,
                'details': {'quarantine_id': quarantine_id}
            }
        else:
            return {
                'success': False,
                'details': {'error': 'Restore operation failed'}
            }
    
    def is_whitelisted(self, file_hash: str) -> bool:
        """Check if file is whitelisted"""
        return file_hash in self.whitelist
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get executor statistics"""
        return {
            'whitelist_entries': len(self.whitelist),
            'quarantine_size_bytes': self.quarantine.get_quarantine_size(),
            'quarantine_records': len(self.quarantine.get_quarantine_records())
        }
