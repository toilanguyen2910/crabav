"""
Exclusion and custom rules for CrabAV
"""

from typing import List, Set, Dict, Any
from pathlib import Path
import fnmatch

from ..utils import get_logger

logger = get_logger("exclusions")


class ExclusionManager:
    """
    Manages scan exclusions and custom rules
    
    Features:
    - Path exclusions (wildcards)
    - File type exclusions
    - Process exclusions
    - Custom threat rules
    """
    
    def __init__(self):
        self.path_exclusions: Set[str] = set()
        self.file_exclusions: Set[str] = set()
        self.process_exclusions: Set[str] = set()
        self.custom_rules: Dict[str, Any] = {}
    
    def add_path_exclusion(self, path_pattern: str) -> bool:
        """
        Add path to exclusion list
        
        Args:
            path_pattern: Path pattern (supports wildcards)
        
        Returns:
            True if added
        """
        self.path_exclusions.add(path_pattern)
        logger.info(f"Added path exclusion: {path_pattern}")
        return True
    
    def add_file_exclusion(self, extension: str) -> bool:
        """Add file extension to exclusion"""
        self.file_exclusions.add(extension.lower())
        logger.info(f"Added file exclusion: {extension}")
        return True
    
    def add_process_exclusion(self, process_name: str) -> bool:
        """Add process to exclusion"""
        self.process_exclusions.add(process_name.lower())
        logger.info(f"Added process exclusion: {process_name}")
        return True
    
    def should_exclude_path(self, file_path: str) -> bool:
        """Check if path should be excluded"""
        for pattern in self.path_exclusions:
            if fnmatch.fnmatch(file_path, pattern):
                return True
        return False
    
    def should_exclude_file(self, file_path: str) -> bool:
        """Check if file extension should be excluded"""
        ext = Path(file_path).suffix.lower()
        return ext in self.file_exclusions
    
    def should_exclude_process(self, process_name: str) -> bool:
        """Check if process should be excluded"""
        return process_name.lower() in self.process_exclusions
    
    def add_custom_rule(
        self,
        rule_id: str,
        rule: Dict[str, Any]
    ) -> bool:
        """
        Add custom threat rule
        
        Args:
            rule_id: Unique rule identifier
            rule: Rule definition
        
        Returns:
            True if added
        """
        self.custom_rules[rule_id] = rule
        logger.info(f"Added custom rule: {rule_id}")
        return True
    
    def get_default_exclusions(self) -> Dict[str, Any]:
        """Get default exclusions"""
        return {
            'paths': [
                r"C:\Windows\*",
                r"C:\Program Files\*",
                r"C:\Program Files (x86)\*",
            ],
            'extensions': ['.sys', '.drv'],
            'processes': ['svchost.exe', 'explorer.exe', 'winlogon.exe']
        }
