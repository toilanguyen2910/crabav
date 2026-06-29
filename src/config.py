"""
Configuration management for CrabAV
"""

from typing import List, Dict, Any, Optional
from pathlib import Path
import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class AgentConfig(BaseModel):
    """Configuration for individual agents"""
    enabled: bool = True
    use_clamav: bool = True
    use_yara: bool = True
    scan_archives: bool = True
    max_recursion_depth: int = 3
    monitor_startup: bool = True
    monitor_services: bool = True
    monitor_browser: bool = True
    check_process_signatures: bool = True
    detect_injection: bool = True
    watch_downloads: bool = True
    watch_documents: bool = True
    watch_system: bool = False
    detect_parent_anomalies: bool = True
    detect_suspicious_paths: bool = True


class ScanningConfig(BaseModel):
    """Scanning configuration"""
    real_time: bool = True
    scan_on_access: bool = False
    max_file_size_mb: int = 100
    timeout_seconds: int = 60
    exclude_paths: List[str] = Field(default_factory=list)
    exclude_extensions: List[str] = Field(default_factory=list)


class AgentsConfig(BaseModel):
    """All agents configuration"""
    file_scanner: AgentConfig = Field(default_factory=AgentConfig)
    registry_scanner: AgentConfig = Field(default_factory=AgentConfig)
    memory_scanner: AgentConfig = Field(default_factory=AgentConfig)
    file_monitor: AgentConfig = Field(default_factory=AgentConfig)
    process_monitor: AgentConfig = Field(default_factory=AgentConfig)


class OrchestratorConfig(BaseModel):
    """Orchestrator configuration"""
    max_parallel_agents: int = 5
    agent_timeout_seconds: int = 30
    result_aggregation_timeout: int = 10


class DecisionConfig(BaseModel):
    """Decision engine configuration"""
    min_confidence_threshold: float = 0.5
    min_agents_for_high_risk: int = 2
    auto_quarantine_critical: bool = False
    threat_level_thresholds: Dict[str, int] = Field(
        default_factory=lambda: {
            "low": 30,
            "medium": 50,
            "high": 70,
            "critical": 85
        }
    )


class QuarantineConfig(BaseModel):
    """Quarantine configuration"""
    enabled: bool = True
    storage_path: str = "./data/quarantine"
    backup_path: str = "./data/backups"
    max_size_mb: int = 1024
    encryption: bool = True
    auto_delete_days: int = 30
    create_restore_point: bool = True


class DatabaseConfig(BaseModel):
    """Database configuration"""
    path: str = "./data/crabav.db"
    echo: bool = False
    pool_size: int = 5


class LoggingConfig(BaseModel):
    """Logging configuration"""
    level: str = "INFO"
    format: str = "[{time:YYYY-MM-DD HH:mm:ss}] {level} | {message}"
    rotation: str = "10 MB"
    retention: str = "30 days"
    outputs: List[Dict[str, Any]] = Field(default_factory=list)


class Config(BaseSettings):
    """Main configuration"""
    application: Dict[str, Any] = Field(default_factory=dict)
    scanning: ScanningConfig = Field(default_factory=ScanningConfig)
    agents: AgentsConfig = Field(default_factory=AgentsConfig)
    orchestrator: OrchestratorConfig = Field(default_factory=OrchestratorConfig)
    decision: DecisionConfig = Field(default_factory=DecisionConfig)
    quarantine: QuarantineConfig = Field(default_factory=QuarantineConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    
    class Config:
        env_prefix = "CRABAV_"
        env_nested_delimiter = "__"


def load_config(config_path: Optional[str] = None) -> Config:
    """Load configuration from YAML file"""
    if config_path is None:
        config_path = "config.yaml"
    
    path = Path(config_path)
    if not path.exists():
        return Config()
    
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    
    return Config(**data)
