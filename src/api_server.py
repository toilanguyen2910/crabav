"""
CrabAV Backend API Server — FastAPI

Provides REST endpoints for the Electron UI. All IPC handlers in
electron/main.js forward calls to this server.
"""

import asyncio
import sys
import uuid
import time
import sqlite3
import json
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import load_config
from src.orchestrator import Orchestrator
from src.decision import DecisionEngine
from src.approval import ApprovalHandler
from src.quarantine import QuarantineManager
from src.engine import ActionExecutor
from src.agents.scanner import FileScanner, BasicFileScanner
from src.agents.monitor import FileSystemMonitor
from src.agents import AgentConfig
from src.enums import ActionType, ThreatLevel, Status
from src.utils import setup_logger, get_logger

logger = get_logger("api")

app = FastAPI(title="CrabAV API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Database ────────────────────────────────────────────────────

DB_PATH = Path("./data/crabav.db")


def get_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id TEXT PRIMARY KEY,
            scan_type TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            files_scanned INTEGER DEFAULT 0,
            threats_found INTEGER DEFAULT 0,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            duration_seconds REAL DEFAULT 0,
            errors TEXT DEFAULT '[]'
        );

        CREATE TABLE IF NOT EXISTS threats (
            id TEXT PRIMARY KEY,
            threat_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_hash TEXT,
            file_size INTEGER DEFAULT 0,
            risk_score REAL DEFAULT 0,
            threat_level TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            quarantine_id TEXT,
            detected_by TEXT DEFAULT '[]',
            evidence TEXT DEFAULT '{}',
            created_at TEXT NOT NULL,
            resolved_at TEXT
        );

        CREATE TABLE IF NOT EXISTS quarantine_records (
            quarantine_id TEXT PRIMARY KEY,
            threat_id TEXT,
            original_path TEXT NOT NULL,
            quarantined_path TEXT NOT NULL,
            backup_path TEXT,
            file_hash TEXT,
            file_size INTEGER DEFAULT 0,
            reason TEXT DEFAULT '',
            encrypted INTEGER DEFAULT 1,
            quarantined_at TEXT NOT NULL,
            auto_delete_at TEXT
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()


# ── App State ────────────────────────────────────────────────────

class AppState:
    def __init__(self):
        self.config = load_config()
        self.quarantine = QuarantineManager(
            quarantine_dir=self.config.quarantine.storage_path
        )
        self.action_executor = ActionExecutor(self.quarantine)
        self.approval_handler = ApprovalHandler(
            approval_timeout_minutes=30, auto_reject_timeout_minutes=60
        )
        self.decision_engine = DecisionEngine(
            config=self.config.decision.model_dump()
        )
        self.orchestrator = Orchestrator(
            config=self.config.orchestrator.model_dump()
        )
        self._register_agents()
        self._running_scan: Optional[Dict[str, Any]] = None

    def _register_agents(self):
        # Luôn đăng ký BasicFileScanner (không cần ClamAV)
        agent = BasicFileScanner(AgentConfig(
            agent_id="basic_scanner", enabled=True, timeout_seconds=120
        ))
        self.orchestrator.register_agent(agent)
        if self.config.agents.file_scanner.enabled:
            self.orchestrator.register_agent(
                FileScanner(AgentConfig(
                    agent_id="file_scanner", enabled=True, timeout_seconds=60
                ))
            )
        if self.config.agents.file_monitor.enabled:
            self.orchestrator.register_agent(
                FileSystemMonitor(AgentConfig(
                    agent_id="file_monitor", enabled=True, timeout_seconds=30
                ))
            )


state = AppState()


# ── Models ──────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "quick"


class ApprovalRequest(BaseModel):
    threat_id: str
    action: str


class SettingsUpdate(BaseModel):
    key: str
    value: Any


# ── API Endpoints ───────────────────────────────────────────────

@app.get("/api/status")
async def get_system_status():
    """Get overall system status."""
    threats_pending = 0
    threats_total = 0
    try:
        conn = get_db()
        threats_pending = conn.execute(
            "SELECT COUNT(*) FROM threats WHERE status = 'pending'"
        ).fetchone()[0]
        threats_total = conn.execute(
            "SELECT COUNT(*) FROM threats"
        ).fetchone()[0]
        conn.close()
    except Exception:
        pass

    agent_count = len(state.orchestrator.agents)
    scan_running = state._running_scan is not None

    return {
        "status": "protected",
        "message": "All systems operational",
        "agents_active": agent_count,
        "threats_pending": threats_pending,
        "threats_total": threats_total,
        "scan_running": scan_running,
        "quarantine_size": state.quarantine.get_quarantine_size(),
        "timestamp": datetime.now().isoformat(),
    }


@app.post("/api/scan/start")
async def start_scan(req: ScanRequest):
    """Start a new scan."""
    if state._running_scan is not None:
        raise HTTPException(400, "A scan is already running")

    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    state._running_scan = {
        "id": scan_id,
        "type": req.scan_type,
        "target": req.target,
        "status": "running",
        "progress": 0,
        "started_at": datetime.now().isoformat(),
    }

    # Save to DB
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO scan_history (id, scan_type, target, status, started_at) VALUES (?, ?, ?, ?, ?)",
            (scan_id, req.scan_type, req.target, "running", state._running_scan["started_at"])
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"DB error: {e}")

    # Run scan in background
    asyncio.create_task(_run_scan_background(scan_id, req.target, req.scan_type))

    return {"success": True, "scan_id": scan_id}


async def _run_scan_background(scan_id: str, target: str, scan_type: str):
    """Background scan execution using Orchestrator."""
    from src.enums import ScanType
    conn = get_db()
    try:
        target_path = target.replace('\\\\', '/')
        logger.info(f"Scan {scan_id}: target={target_path}")

        try:
            stype = ScanType(scan_type.lower())
        except ValueError:
            stype = ScanType.QUICK

        # Run real scan using orchestrator
        scan_result = await state.orchestrator.run_scan(stype, target_path)

        if state._running_scan:
            state._running_scan["progress"] = 100
            state._running_scan["status"] = scan_result.status.value

        # Analyze findings
        threats_found = scan_result.threats_found
        files_scanned = scan_result.files_scanned
        
        if scan_result.agent_results:
            threat_report = state.decision_engine.analyze_findings(scan_result.agent_results)
            if threat_report:
                # Determine severity name
                tl = threat_report.threat_level
                tl_name = tl.name if hasattr(tl, 'name') else str(tl)
                
                detected_by = list(set(f.agent_id for f in threat_report.findings))
                
                # Insert threat to DB
                conn.execute(
                    "INSERT INTO threats (id, threat_name, file_path, file_hash, file_size, risk_score, threat_level, detected_by, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        threat_report.threat_id,
                        threat_report.threat_name,
                        threat_report.file_path,
                        threat_report.file_hash,
                        threat_report.file_size,
                        threat_report.risk_score,
                        tl_name,
                        json.dumps(detected_by),
                        datetime.now().isoformat()
                    )
                )
                threats_found = max(threats_found, 1)

        duration = scan_result.duration_seconds
        
        conn.execute(
            "UPDATE scan_history SET status=?, files_scanned=?, "
            "threats_found=?, completed_at=?, duration_seconds=? WHERE id=?",
            (
                scan_result.status.value,
                files_scanned,
                threats_found,
                datetime.now().isoformat(),
                duration,
                scan_id
            )
        )
        conn.commit()

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        try:
            conn.execute(
                "UPDATE scan_history SET status='failed', completed_at=?, errors=? WHERE id=?",
                (datetime.now().isoformat(), json.dumps([str(e)]), scan_id)
            )
            conn.commit()
        except Exception:
            pass
        if state._running_scan:
            state._running_scan["status"] = "failed"
    finally:
        conn.close()
        await asyncio.sleep(5)
        if state._running_scan and state._running_scan.get("id") == scan_id:
            state._running_scan = None


@app.get("/api/scan/status")
async def get_scan_status(scan_id: Optional[str] = None):
    """Get current scan status."""
    if state._running_scan:
        return state._running_scan
    if scan_id:
        conn = get_db()
        row = conn.execute("SELECT * FROM scan_history WHERE id=?", (scan_id,)).fetchone()
        conn.close()
        if row:
            return dict(row)
    return {"status": "idle", "progress": 0}


@app.post("/api/scan/stop")
async def stop_scan():
    """Stop current scan."""
    if state._running_scan:
        scan_id = state._running_scan["id"]
        state._running_scan["status"] = "stopped"
        conn = get_db()
        conn.execute("UPDATE scan_history SET status='stopped', completed_at=? WHERE id=?",
                     (datetime.now().isoformat(), scan_id))
        conn.commit()
        conn.close()
        state._running_scan = None
        return {"success": True}
    return {"success": False, "error": "No scan running"}


@app.get("/api/threats")
async def get_threats():
    """Get all threats from database."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM threats ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.get("/api/threats/{threat_id}")
async def get_threat_detail(threat_id: str):
    """Get detailed threat information."""
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM threats WHERE id=?", (threat_id,)
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Threat not found")
    return dict(row)


@app.post("/api/threats/approve")
async def approve_threat_action(req: ApprovalRequest):
    """Approve an action on a threat."""
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM threats WHERE id=?", (req.threat_id,)
    ).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Threat not found")

    threat_data = dict(row)

    # Execute action
    from src.models import ThreatReport
    from src.enums import ThreatLevel as TL

    try:
        action = ActionType(req.action)
    except ValueError:
        conn.close()
        raise HTTPException(400, f"Invalid action: {req.action}")

    threat_report = ThreatReport(
        threat_id=threat_data["id"],
        threat_name=threat_data["threat_name"],
        threat_level=TL(threat_data["threat_level"]),
        risk_score=threat_data["risk_score"],
        file_path=threat_data["file_path"],
        file_hash=threat_data.get("file_hash"),
        file_size=threat_data.get("file_size", 0),
    )

    result = state.action_executor.execute_action(action, threat_report)

    if result["success"]:
        new_status = {
            "quarantine": "quarantined",
            "delete": "deleted",
            "whitelist": "whitelisted",
            "restore": "restored",
        }.get(req.action, "resolved")

        quarantine_id = result.get("details", {}).get("quarantine_id")
        conn.execute(
            "UPDATE threats SET status=?, quarantine_id=?, resolved_at=? WHERE id=?",
            (new_status, quarantine_id, datetime.now().isoformat(), req.threat_id)
        )
        conn.commit()

    conn.close()
    return {"success": result["success"], "details": result.get("details", {})}


@app.get("/api/agents")
async def get_agent_status():
    """Get status of all agents."""
    agents = []
    for agent in state.orchestrator.agents.values():
        agents.append({
            "id": agent.agent_id,
            "type": agent.agent_type.value,
            "status": agent.status.value,
            "enabled": agent.config.enabled,
            "last_run": agent.last_run.isoformat() if agent.last_run else None,
        })
    return agents


@app.get("/api/settings")
async def get_settings():
    """Get all settings."""
    conn = get_db()
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    conn.close()

    settings = {
        "realTimeScan": True,
        "autoUpdate": True,
        "emailNotifications": False,
        "quietHours": False,
        "excludeDownloads": False,
        "backupBeforeDelete": True,
    }
    for row in rows:
        settings[row["key"]] = json.loads(row["value"])

    return settings


@app.post("/api/settings")
async def update_settings(req: SettingsUpdate):
    """Update a single setting."""
    conn = get_db()
    conn.execute(
        "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
        (req.key, json.dumps(req.value), datetime.now().isoformat()),
    )
    conn.commit()
    conn.close()
    return {"success": True}


@app.get("/api/scans/history")
async def get_scan_history(limit: int = Query(20, le=100)):
    """Get scan history."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM scan_history ORDER BY started_at DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Startup ─────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    init_db()
    setup_logger(level="INFO", log_file="./logs/crabav.log")
    logger.info("CrabAV API server started")


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=19527, log_level="info")
