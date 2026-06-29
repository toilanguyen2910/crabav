"""
State Manager - Persists scan results and agent state
"""

from typing import Dict, Any, Optional, List
from pathlib import Path
import json
import sqlite3
from datetime import datetime
from contextlib import contextmanager

from ..models import ScanResult, ThreatReport, QuarantineRecord
from ..utils import get_logger, ensure_directory

logger = get_logger("state_manager")


class StateManager:
    """
    Manages persistent state for CrabAV
    
    Responsibilities:
    - Save/load scan results
    - Persist threat reports
    - Track quarantine records
    - Maintain agent status
    """
    
    def __init__(self, db_path: str = "./data/crabav.db"):
        self.db_path = Path(db_path)
        self._ensure_database()
        logger.info(f"StateManager initialized with DB: {db_path}")
    
    def _ensure_database(self) -> None:
        """Ensure database and tables exist"""
        ensure_directory(self.db_path.parent)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Scan results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    scan_id TEXT PRIMARY KEY,
                    scan_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    status TEXT NOT NULL,
                    files_scanned INTEGER DEFAULT 0,
                    threats_found INTEGER DEFAULT 0,
                    agents_used TEXT,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    duration_seconds REAL,
                    result_json TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Threat reports table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_reports (
                    threat_id TEXT PRIMARY KEY,
                    threat_name TEXT NOT NULL,
                    threat_level TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size INTEGER,
                    file_hash TEXT,
                    status TEXT DEFAULT 'pending',
                    report_json TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Quarantine records table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS quarantine_records (
                    quarantine_id TEXT PRIMARY KEY,
                    threat_id TEXT NOT NULL,
                    original_path TEXT NOT NULL,
                    quarantined_path TEXT NOT NULL,
                    backup_path TEXT,
                    file_hash TEXT,
                    file_size INTEGER,
                    reason TEXT,
                    encrypted BOOLEAN DEFAULT TRUE,
                    quarantined_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    auto_delete_at TEXT,
                    FOREIGN KEY (threat_id) REFERENCES threat_reports(threat_id)
                )
            """)
            
            # Agent status table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS agent_status (
                    agent_id TEXT PRIMARY KEY,
                    agent_type TEXT NOT NULL,
                    status TEXT DEFAULT 'idle',
                    last_run TEXT,
                    last_result TEXT,
                    error_message TEXT,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
    
    @contextmanager
    def _get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def save_scan_result(self, scan_result: ScanResult) -> bool:
        """Save scan result to database"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT OR REPLACE INTO scan_results
                    (scan_id, scan_type, target, status, files_scanned, 
                     threats_found, agents_used, started_at, completed_at, 
                     duration_seconds, result_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_result.scan_id,
                    scan_result.scan_type,
                    scan_result.target,
                    scan_result.status.value,
                    scan_result.files_scanned,
                    scan_result.threats_found,
                    json.dumps(scan_result.agents_used),
                    scan_result.started_at.isoformat(),
                    scan_result.completed_at.isoformat() if scan_result.completed_at else None,
                    scan_result.duration_seconds,
                    scan_result.model_dump_json()
                ))
                
                conn.commit()
                logger.info(f"Saved scan result: {scan_result.scan_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to save scan result: {e}")
            return False
    
    def load_scan_result(self, scan_id: str) -> Optional[ScanResult]:
        """Load scan result from database"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT result_json FROM scan_results WHERE scan_id = ?",
                    (scan_id,)
                )
                row = cursor.fetchone()
                
                if row:
                    return ScanResult.model_validate_json(row['result_json'])
                return None
                
        except Exception as e:
            logger.error(f"Failed to load scan result: {e}")
            return None
    
    def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent scan results"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT scan_id, scan_type, target, status, 
                           files_scanned, threats_found, started_at, 
                           completed_at, duration_seconds
                    FROM scan_results
                    ORDER BY started_at DESC
                    LIMIT ?
                """, (limit,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Failed to get recent scans: {e}")
            return []
    
    def save_threat_report(self, threat_report: ThreatReport) -> bool:
        """Save threat report to database"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT OR REPLACE INTO threat_reports
                    (threat_id, threat_name, threat_level, risk_score,
                     file_path, file_size, file_hash, status, report_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    threat_report.threat_id,
                    threat_report.threat_name,
                    threat_report.threat_level.value,
                    threat_report.risk_score,
                    threat_report.file_path,
                    threat_report.file_size,
                    threat_report.file_hash,
                    threat_report.status.value,
                    threat_report.model_dump_json()
                ))
                
                conn.commit()
                logger.info(f"Saved threat report: {threat_report.threat_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to save threat report: {e}")
            return False
    
    def get_pending_threats(self) -> List[ThreatReport]:
        """Get all threats pending user approval"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT report_json FROM threat_reports
                    WHERE status = 'pending'
                    ORDER BY created_at DESC
                """)
                
                return [
                    ThreatReport.model_validate_json(row['report_json'])
                    for row in cursor.fetchall()
                ]
                
        except Exception as e:
            logger.error(f"Failed to get pending threats: {e}")
            return []
    
    def save_quarantine_record(self, record: QuarantineRecord) -> bool:
        """Save quarantine record"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO quarantine_records
                    (quarantine_id, threat_id, original_path, quarantined_path,
                     backup_path, file_hash, file_size, reason, encrypted,
                     quarantined_at, auto_delete_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record.quarantine_id,
                    record.threat_id,
                    record.original_path,
                    record.quarantined_path,
                    record.backup_path,
                    record.file_hash,
                    record.file_size,
                    record.reason,
                    record.encrypted,
                    record.quarantined_at.isoformat(),
                    record.auto_delete_at.isoformat() if record.auto_delete_at else None
                ))
                
                conn.commit()
                logger.info(f"Saved quarantine record: {record.quarantine_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to save quarantine record: {e}")
            return False
