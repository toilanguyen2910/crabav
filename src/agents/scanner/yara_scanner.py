"""
YARA Scanner Agent — pattern-based detection using YARA rules
"""

from typing import Any, List, Dict, Optional
from pathlib import Path
from datetime import datetime

import yara

from ...enums import AgentType, FindingType, ThreatLevel, ActionType
from ...models import ThreatFinding, AgentResult
from ...utils import get_logger, validate_scan_path

logger = get_logger("yara_scanner")


# ── Rule severity → ThreatLevel mapping ─────────────────────────

_SEVERITY_MAP = {
    "critical": ThreatLevel.CRITICAL,
    "high": ThreatLevel.HIGH,
    "medium": ThreatLevel.MEDIUM,
    "low": ThreatLevel.LOW,
}

_RULETYPE_MAP = {
    "malware": FindingType.FILE_SIGNATURE,
    "suspicious": FindingType.HEURISTIC,
}


class YaraScanner:
    """
    YARA-based pattern scanner.

    Compiles YARA rule files from disk and scans targets against them.
    Rules are automatically reloaded when files change (for development).
    Not a full BaseAgent subclass — designed to be used by FileScanner
    or standalone.
    """

    def __init__(self, rules_dir: str = "./rules/yara"):
        self.rules_dir = Path(rules_dir)
        self.rules: Optional[yara.Rules] = None
        self._compile_time: Dict[str, float] = {}
        self._load_rules()

    @property
    def is_available(self) -> bool:
        return self.rules is not None

    def _load_rules(self) -> None:
        """Compile all .yar files in the rules directory."""
        if not self.rules_dir.exists():
            logger.warning(f"YARA rules directory not found: {self.rules_dir}")
            self.rules = None
            return

        rule_files = list(self.rules_dir.glob("*.yar"))
        if not rule_files:
            logger.warning(f"No .yar files found in {self.rules_dir}")
            self.rules = None
            return

        filepaths = {str(f): str(f) for f in rule_files}
        try:
            self.rules = yara.compile(filepaths=filepaths)
            logger.info(
                f"YARA rules loaded: {len(rule_files)} file(s) from {self.rules_dir}"
            )
        except yara.SyntaxError as e:
            logger.error(f"YARA syntax error: {e}")
            self.rules = None
        except Exception as e:
            logger.error(f"Failed to compile YARA rules: {e}")
            self.rules = None

    def reload(self) -> None:
        """Force reload rules from disk."""
        self._load_rules()

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Scan a single file against all compiled YARA rules.

        Returns:
            List of match dicts: {rule_name, tags, meta, strings, namespace}
        """
        if self.rules is None:
            return []

        path = Path(file_path)
        if not path.is_file():
            return []

        try:
            matches = self.rules.match(str(path), timeout=10)
            return [
                {
                    "rule_name": m.rule,
                    "tags": list(m.tags),
                    "meta": dict(m.meta),
                    "strings": [
                        {
                            "identifier": s.identifier,
                            "offset": s.instances[0].offset if s.instances else -1,
                            "data": s.instances[0].matched_data.hex()
                            if s.instances and s.instances[0].matched_data is not None
                            else "",
                        }
                        for s in m.strings
                        if s.instances
                    ],
                    "namespace": m.namespace,
                }
                for m in matches
            ]
        except yara.TimeoutError:
            logger.warning(f"YARA timeout scanning {file_path}")
            return []
        except Exception as e:
            logger.error(f"YARA scan error on {file_path}: {e}")
            return []

    def scan_file_with_findings(self, file_path: str, agent_id: str) -> List[ThreatFinding]:
        """
        Scan a single file and return ThreatFinding objects ready for the orchestrator.

        Args:
            file_path: Absolute path to the file
            agent_id: ID of the calling agent (e.g., 'yara_scanner')

        Returns:
            List of ThreatFinding objects
        """
        matches = self.scan_file(file_path)
        findings: List[ThreatFinding] = []

        for m in matches:
            meta = m["meta"]
            rule_type = meta.get("type", "suspicious")
            finding_type = _RULETYPE_MAP.get(rule_type, FindingType.HEURISTIC)

            severity = meta.get("severity", "medium")
            threat_level = _SEVERITY_MAP.get(severity, ThreatLevel.MEDIUM)

            confidence_str = meta.get("confidence", "0.75")
            try:
                confidence = float(confidence_str)
            except (ValueError, TypeError):
                confidence = 0.75

            string_hits = []
            for s in m["strings"]:
                string_hits.append(
                    f"{s['identifier']} @ offset {s['offset']}"
                )

            finding = ThreatFinding(
                agent_id=agent_id,
                agent_type=AgentType.ANALYSIS,
                finding_type=finding_type,
                threat_name=f"YARA:{m['rule_name']}",
                threat_level=threat_level,
                confidence=confidence,
                evidence={
                    "rule_name": m["rule_name"],
                    "tags": m["tags"],
                    "description": meta.get("description", ""),
                    "strings_matched": string_hits,
                    "file_path": file_path,
                    "detection_method": "YARA pattern matching",
                },
                recommended_actions=[ActionType.QUARANTINE],
                metadata={
                    "yara_rule": m["rule_name"],
                    "yara_tags": m["tags"],
                    "scan_type": "yara",
                },
            )
            findings.append(finding)

        return findings

    def scan_directory(self, dir_path: str, agent_id: str = "yara_scanner") -> List[ThreatFinding]:
        """
        Recursively scan a directory with YARA rules.

        Args:
            dir_path: Directory to scan
            agent_id: Agent ID for findings

        Returns:
            Aggregated list of ThreatFindings
        """
        all_findings: List[ThreatFinding] = []
        root = Path(dir_path)

        if not root.is_dir():
            return all_findings

        for file_path in root.rglob("*"):
            if not file_path.is_file():
                continue
            # Skip files that are too large (100 MB)
            try:
                if file_path.stat().st_size > 100 * 1024 * 1024:
                    continue
            except OSError:
                continue

            findings = self.scan_file_with_findings(str(file_path), agent_id)
            all_findings.extend(findings)

        return all_findings
