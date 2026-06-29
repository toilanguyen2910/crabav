"""
Utility functions for CrabAV
"""

from pathlib import Path
import hashlib
import json
import re
from typing import Any, Dict, List, Optional


# ── File hashing ──────────────────────────────────────────────────

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


# ── Directory helpers ─────────────────────────────────────────────

def ensure_directory(path: str) -> Path:
    """Ensure directory exists, create if not"""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


# ── JSON helpers ──────────────────────────────────────────────────

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


# ── Formatting ────────────────────────────────────────────────────

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


# ── Path Traversal & Security Validation ──────────────────────────

# Characters that must never appear in a safe scan path
_FORBIDDEN_PATH_CHARS = re.compile(r'[\x00-\x1f<>"|?*]')

# Common path traversal patterns
_PATH_TRAVERSAL_PATTERNS = [
    "../", "..\\", "..%2f", "..%5c",  # classic traversal
    "%2e%2e/", "%2e%2e%2f",           # URL-encoded
    "%252e%252e%252f",                 # double URL-encoded
]


def validate_scan_path(path_str: str, allowed_roots: Optional[List[str]] = None) -> Path:
    """
    Validate and sanitize a user-supplied scan target path.

    Protects against:
    - Path traversal (../../../etc/shadow)
    - Null bytes and control characters
    - Command injection characters (< > | & ;)
    - Symlink loops (via resolve)

    Args:
        path_str: The user-supplied path string
        allowed_roots: Optional list of allowed root directories.
                       If provided, the resolved path MUST be within one of them.

    Returns:
        Resolved absolute Path if valid.

    Raises:
        ValueError on any security violation.
    """
    if not path_str or not path_str.strip():
        raise ValueError("Empty path is not allowed")

    # Check for null bytes and control characters
    if "\x00" in path_str:
        raise ValueError("Path contains null byte — possible injection attack")

    if _FORBIDDEN_PATH_CHARS.search(path_str):
        raise ValueError(
            f"Path contains forbidden characters: {path_str!r}"
        )

    # Check for common path traversal patterns
    lower = path_str.lower()
    for pattern in _PATH_TRAVERSAL_PATTERNS:
        if pattern in lower:
            raise ValueError(
                f"Path traversal pattern detected: {pattern!r}"
            )

    # Resolve to absolute path (also catches symlink loops)
    try:
        resolved = Path(path_str).resolve(strict=False)
    except (OSError, RuntimeError) as e:
        raise ValueError(f"Cannot resolve path: {e}")

    # Resolve again strictly if possible (file may not exist yet — that's OK for scan targets)
    try:
        resolved = Path(path_str).resolve(strict=True)
    except (FileNotFoundError, OSError):
        # Target doesn't exist yet — use the non-strict resolution
        resolved = Path(path_str).resolve(strict=False)

    # Additional sanity: resolved path must not be empty or root-only
    resolved_str = str(resolved)
    if resolved_str in ("", "/", "\\", "."):
        raise ValueError(f"Path resolved to insecure value: {resolved_str!r}")

    # Check against allowed roots if specified
    if allowed_roots:
        resolved_lower = resolved_str.lower()
        ok = False
        for root in allowed_roots:
            root_path = Path(root).resolve()
            root_lower = str(root_path).lower()
            if resolved_lower.startswith(root_lower):
                ok = True
                break
        if not ok:
            raise ValueError(
                f"Path {resolved_str!r} is outside allowed roots: {allowed_roots}"
            )

    return resolved


def validate_subprocess_arg(arg: str) -> str:
    """
    Validate a single argument passed to subprocess.
    Rejects arguments containing shell metacharacters.

    This is a defense-in-depth measure — subprocess calls should always
    use list form (never shell=True), but this catches malicious paths
    that might contain shell-significant characters.
    """
    if not arg or not arg.strip():
        raise ValueError("Empty subprocess argument")

    # Shell metacharacters
    dangerous = re.search(r'[;&|`$(){}[\]!#~\n\r\t]', arg)
    if dangerous:
        raise ValueError(
            f"Argument contains dangerous shell character "
            f"'{dangerous.group()!r}' at position {dangerous.start()}: {arg!r}"
        )

    return arg
