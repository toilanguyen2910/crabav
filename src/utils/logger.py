"""
Logger setup for CrabAV
"""

from loguru import logger
import sys
from pathlib import Path
from typing import Optional


def setup_logger(
    level: str = "INFO",
    log_file: Optional[str] = None,
    format: str = "[{time:YYYY-MM-DD HH:mm:ss}] {level} | {message}",
    rotation: str = "10 MB",
    retention: str = "30 days",
    colorize: bool = True,
    diagnose: bool = False  # Disabled by default — enable only for debugging
) -> None:
    """Configure logging for the application"""
    
    # Remove default handler
    logger.remove()
    
    # Add console handler
    logger.add(
        sys.stderr,
        level=level,
        format=format,
        colorize=colorize,
        backtrace=True,
        diagnose=diagnose
    )
    
    # Add file handler if specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        logger.add(
            str(log_path),
            level=level,
            format=format,
            rotation=rotation,
            retention=retention,
            backtrace=True,
            diagnose=diagnose
        )


# Convenience functions
def get_logger(name: str = "crabav") -> logger:
    """Get a logger instance"""
    return logger.bind(name=name)


# Setup default logger on import
setup_logger()
