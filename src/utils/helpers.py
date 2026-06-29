"""
Utility functions for CrabAV
"""

from pathlib import Path
import hashlib
import json
from typing import Any, Dict, List, Optional


def calculate_file_hash(file_path: str, algorithm: str = "sha256") -> Optional[str]:
    """Calculate hash of a file"""
    try:
        hash_func = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception:
        return None


def ensure_directory(path: str) -> Path:
    """Ensure directory exists, create if not"""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def load_json_file(file_path: str) -> Optional[Dict[str, Any]]:
    """Load JSON file"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_json_file(file_path: str, data: Dict[str, Any]) -> bool:
    """Save data to JSON file"""
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


def format_bytes(size: int) -> str:
    """Format bytes to human readable string"""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def sanitize_path(path: str) -> str:
    """Clean up path for safe usage"""
    return path.replace("\\", "/").strip()
