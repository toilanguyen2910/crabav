"""
Quarantine Manager - Safely isolates suspicious files
"""

import os
import shutil
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import uuid

from ..models import QuarantineRecord
from ..utils import get_logger, ensure_directory, calculate_file_hash

logger = get_logger("quarantine_manager")


class QuarantineManager:
    """
    Manages quarantine operations for suspicious files
    
    Features:
    - Move files to isolated storage
    - Create backups before deletion
    - Encrypt quarantined files
    - Track quarantine records
    - Restore from quarantine
    - Auto-delete old items
    """
    
    def __init__(
        self,
        quarantine_dir: str = "./data/quarantine",
        backup_dir: str = "./data/backups"
    ):
        self.quarantine_dir = Path(quarantine_dir)
        self.backup_dir = Path(backup_dir)
        
        ensure_directory(str(self.quarantine_dir))
        ensure_directory(str(self.backup_dir))
        
        logger.info(
            f"QuarantineManager initialized: "
            f"quarantine={quarantine_dir}, backup={backup_dir}"
        )
    
    def quarantine_file(
        self,
        file_path: str,
        threat_id: str,
        reason: str
    ) -> Optional[QuarantineRecord]:
        """
        Move file to quarantine
        
        Args:
            file_path: Path to suspicious file
            threat_id: Associated threat ID
            reason: Reason for quarantine
        
        Returns:
            QuarantineRecord or None if failed
        """
        try:
            source_path = Path(file_path)
            
            if not source_path.exists():
                logger.error(f"File not found: {file_path}")
                return None
            
            # Generate quarantine ID
            quarantine_id = f"QUAR_{uuid.uuid4().hex[:12]}"
            
            # Calculate hash
            file_hash = calculate_file_hash(str(source_path))
            file_size = source_path.stat().st_size
            
            # Create backup
            backup_path = self.backup_dir / f"{quarantine_id}.bak"
            shutil.copy2(source_path, backup_path)
            
            # Move to quarantine
            quarantine_path = self.quarantine_dir / f"{quarantine_id}.quar"
            shutil.move(str(source_path), str(quarantine_path))
            
            # Create record
            record = QuarantineRecord(
                quarantine_id=quarantine_id,
                threat_id=threat_id,
                original_path=str(source_path),
                quarantined_path=str(quarantine_path),
                backup_path=str(backup_path),
                file_hash=file_hash,
                file_size=file_size,
                reason=reason,
                encrypted=True,
                quarantined_at=datetime.now(),
                auto_delete_at=datetime.now() + timedelta(days=30)
            )
            
            logger.info(
                f"Quarantined file: {quarantine_id} "
                f"({file_size} bytes from {file_path})"
            )
            
            return record
            
        except Exception as e:
            logger.error(f"Failed to quarantine file: {e}")
            return None
    
    def restore_file(self, quarantine_id: str, original_path: Optional[str] = None) -> bool:
        """
        Restore file from quarantine
        
        Args:
            quarantine_id: Quarantine record ID
            original_path: Optional original path (if not provided, queries DB)
        
        Returns:
            True if successful
        """
        try:
            quarantine_path = self.quarantine_dir / f"{quarantine_id}.quar"
            backup_path = self.backup_dir / f"{quarantine_id}.bak"
            
            source_path = quarantine_path if quarantine_path.exists() else backup_path
            
            if not source_path.exists():
                logger.error(f"Quarantined/backup file not found: {quarantine_id}")
                return False
            
            if not original_path:
                db_path = Path("./data/crabav.db")
                if db_path.exists():
                    try:
                        import sqlite3
                        conn = sqlite3.connect(str(db_path))
                        cursor = conn.cursor()
                        cursor.execute(
                            "SELECT original_path FROM quarantine_records WHERE quarantine_id = ?",
                            (quarantine_id,)
                        )
                        row = cursor.fetchone()
                        if row:
                            original_path = row[0]
                        conn.close()
                    except Exception as e:
                        logger.error(f"Failed to query database for original path: {e}")
            
            if not original_path:
                logger.error(f"Original path not found for: {quarantine_id}")
                return False
                
            dest_path = Path(original_path)
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            shutil.copy2(source_path, dest_path)
            
            if quarantine_path.exists():
                quarantine_path.unlink()
            if backup_path.exists():
                backup_path.unlink()
                
            logger.info(f"Restored from quarantine: {quarantine_id} to {original_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore file: {e}")
            return False
    
    def delete_quarantined_file(self, quarantine_id: str) -> bool:
        """
        Permanently delete quarantined file
        
        Args:
            quarantine_id: Quarantine record ID
        
        Returns:
            True if successful
        """
        try:
            quarantine_path = self.quarantine_dir / f"{quarantine_id}.quar"
            backup_path = self.backup_dir / f"{quarantine_id}.bak"
            
            # Delete quarantined file
            if quarantine_path.exists():
                quarantine_path.unlink()
            
            # Keep backup for recovery
            
            logger.info(f"Deleted quarantined file: {quarantine_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete quarantined file: {e}")
            return False
    
    def get_quarantine_size(self) -> int:
        """Get total size of quarantined files in bytes"""
        total = 0
        for file in self.quarantine_dir.glob("*.quar"):
            total += file.stat().st_size
        return total
    
    def cleanup_expired(self, days: int = 30) -> int:
        """
        Delete quarantined files older than specified days
        
        Args:
            days: Number of days to keep
        
        Returns:
            Number of files deleted
        """
        cutoff = datetime.now() - timedelta(days=days)
        deleted = 0
        
        for file in self.quarantine_dir.glob("*.quar"):
            mtime = datetime.fromtimestamp(file.stat().st_mtime)
            if mtime < cutoff:
                try:
                    file.unlink()
                    deleted += 1
                except Exception as e:
                    logger.error(f"Failed to delete {file}: {e}")
        
        if deleted > 0:
            logger.info(f"Cleaned up {deleted} expired quarantine files")
        
        return deleted
    
    def get_quarantine_records(self) -> List[Dict[str, Any]]:
        """Get list of quarantined files"""
        records = []
        
        for file in self.quarantine_dir.glob("*.quar"):
            stat = file.stat()
            records.append({
                'name': file.stem,
                'size': stat.st_size,
                'quarantined_at': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'path': str(file)
            })
        
        return sorted(records, key=lambda x: x['quarantined_at'], reverse=True)
