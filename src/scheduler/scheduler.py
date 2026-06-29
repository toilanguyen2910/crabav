"""
Scheduled scan features for CrabAV
"""

from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from ..utils import get_logger

logger = get_logger("scheduler")


class ScanScheduler:
    """
    Manages scheduled and recurring scans
    
    Features:
    - Schedule one-time scans
    - Recurring scans (daily, weekly)
    - Exclude paths
    - Custom scan profiles
    """
    
    def __init__(self):
        self.schedules: Dict[str, Dict[str, Any]] = {}
        self.next_runs: Dict[str, datetime] = {}
    
    def schedule_scan(
        self,
        name: str,
        scan_type: str,
        target_path: str,
        schedule_time: Optional[datetime] = None,
        recurrence: Optional[str] = None
    ) -> str:
        """
        Schedule a scan
        
        Args:
            name: Schedule name
            scan_type: Type of scan (quick/full/custom)
            target_path: Path to scan
            schedule_time: When to run (None = ASAP)
            recurrence: daily/weekly/monthly or None for one-time
        
        Returns:
            Schedule ID
        """
        schedule_id = f"sched_{name}_{datetime.now().timestamp()}"
        
        self.schedules[schedule_id] = {
            'name': name,
            'scan_type': scan_type,
            'target_path': target_path,
            'recurrence': recurrence,
            'created_at': datetime.now(),
            'last_run': None,
            'next_run': schedule_time or datetime.now()
        }
        
        self.next_runs[schedule_id] = schedule_time or datetime.now()
        
        logger.info(f"Scheduled scan: {name} ({schedule_id})")
        return schedule_id
    
    def get_due_scans(self) -> Dict[str, Dict[str, Any]]:
        """Get scans that are due to run"""
        now = datetime.now()
        due = {}
        
        for schedule_id, schedule in self.schedules.items():
            next_run = self.next_runs.get(schedule_id)
            
            if next_run and next_run <= now:
                due[schedule_id] = schedule
        
        return due
    
    def mark_completed(self, schedule_id: str) -> bool:
        """Mark scan as completed"""
        if schedule_id not in self.schedules:
            return False
        
        schedule = self.schedules[schedule_id]
        schedule['last_run'] = datetime.now()
        
        # Calculate next run if recurring
        if schedule['recurrence']:
            if schedule['recurrence'] == 'daily':
                delta = timedelta(days=1)
            elif schedule['recurrence'] == 'weekly':
                delta = timedelta(weeks=1)
            elif schedule['recurrence'] == 'monthly':
                delta = timedelta(days=30)
            else:
                delta = None
            
            if delta:
                self.next_runs[schedule_id] = datetime.now() + delta
        
        return True
    
    def list_schedules(self) -> Dict[str, Dict[str, Any]]:
        """Get all schedules"""
        return self.schedules.copy()
