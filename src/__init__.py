"""
CrabAV - Free Multi-Agent Antivirus System

Version: 0.1.0
Description: Antivirus system powered by specialized AI agents with user approval workflow
"""

__version__ = "0.1.0"
__author__ = "Súp Cua AI"
__license__ = "Apache License 2.0"
__copyright__ = "Copyright 2026 CrabAV Contributors"

from .enums import AgentType, ThreatLevel, ScanType, Status
from .config import load_config, Config
from .models import ThreatFinding, AgentResult, ScanResult, ThreatReport
from .utils.logger import setup_logger

__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "AgentType",
    "ThreatLevel", 
    "ScanType",
    "Status",
    "load_config",
    "Config",
    "ThreatFinding",
    "AgentResult",
    "ScanResult",
    "ThreatReport",
    "setup_logger",
]
