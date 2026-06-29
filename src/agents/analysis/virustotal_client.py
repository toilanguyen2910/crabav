"""
VirusTotal API Client — hash lookup for suspicious files

This module queries the VirusTotal API v3 to check file hashes against
their malware database. It's used as a supplementary detection layer:
when CrabAV's internal scanners find a suspicious file but can't
definitively classify it, the hash is checked against VirusTotal.

API Key: must be set via environment variable CRABAV_VT_API_KEY
or in config.yaml under vt.api_key.

Rate limits (free tier): 4 requests/minute, 500/day.
The client enforces a 15-second cooldown between requests.
"""

from typing import Dict, Any, Optional
from pathlib import Path
from datetime import datetime, timedelta
import os

import httpx
import yaml

from ...utils import get_logger

logger = get_logger("virustotal")

# ── Constants ───────────────────────────────────────────────────

VT_API_BASE = "https://www.virustotal.com/api/v3"
VT_MIN_COOLDOWN_SECONDS = 15  # 4 req/min = 15s between requests
VT_DEFAULT_TIMEOUT = 10


class VirusTotalClient:
    """
    VirusTotal API v3 client for file hash lookups.

    Usage:
        client = VirusTotalClient(api_key="...")
        report = await client.lookup_hash("abc123...")
        if report:
            print(f"Detections: {report['positives']}/{report['total']}")
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        config_path: Optional[str] = None,
    ):
        """
        Args:
            api_key: VirusTotal API key. If None, reads from env var or config.
            config_path: Optional path to config.yaml for VT settings.
        """
        self._api_key = api_key or self._load_api_key(config_path)
        self._last_request_time: Optional[datetime] = None
        self._http_client: Optional[httpx.AsyncClient] = None

    @property
    def is_available(self) -> bool:
        """Check if VirusTotal is configured and ready."""
        return bool(self._api_key)

    @staticmethod
    def _load_api_key(config_path: Optional[str]) -> Optional[str]:
        """Load API key from environment or config file."""
        # 1. Environment variable (highest priority)
        env_key = os.environ.get("CRABAV_VT_API_KEY")
        if env_key:
            logger.info("VirusTotal API key loaded from environment")
            return env_key

        # 2. Config file
        if config_path is None:
            config_path = "config.yaml"

        config_file = Path(config_path)
        if config_file.exists():
            try:
                with open(config_file, "r", encoding="utf-8") as f:
                    config = yaml.safe_load(f) or {}
                vt_config = config.get("virustotal", {})
                api_key = vt_config.get("api_key")
                if api_key and api_key != "YOUR_API_KEY_HERE":
                    logger.info("VirusTotal API key loaded from config.yaml")
                    return api_key
            except Exception as e:
                logger.warning(f"Failed to read config for VT key: {e}")

        logger.info(
            "VirusTotal API key not configured. "
            "Set CRABAV_VT_API_KEY env var or virustotal.api_key in config.yaml"
        )
        return None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                base_url=VT_API_BASE,
                headers={
                    "x-apikey": self._api_key,
                    "Accept": "application/json",
                },
                timeout=VT_DEFAULT_TIMEOUT,
            )
        return self._http_client

    async def _enforce_rate_limit(self) -> None:
        """Enforce cooldown between requests."""
        if self._last_request_time is None:
            return

        elapsed = (datetime.now() - self._last_request_time).total_seconds()
        if elapsed < VT_MIN_COOLDOWN_SECONDS:
            wait = VT_MIN_COOLDOWN_SECONDS - elapsed
            import asyncio
            logger.debug(f"VirusTotal rate limit: waiting {wait:.1f}s")
            await asyncio.sleep(wait)

    async def lookup_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """
        Look up a file hash (SHA-256, SHA-1, or MD5) on VirusTotal.

        Args:
            file_hash: Hash string (recommend SHA-256)

        Returns:
            Dict with keys: hash, positives, total, permalink, scan_date,
            results (dict of engine_name → {category, result, method}),
            or None on error/not found.
        """
        if not self._api_key:
            logger.warning("VirusTotal lookup skipped: no API key configured")
            return None

        # Basic hash validation
        file_hash = file_hash.strip().lower()
        if not file_hash or len(file_hash) < 32:
            logger.error(f"Invalid hash format: {file_hash[:20]}...")
            return None

        await self._enforce_rate_limit()

        try:
            client = await self._get_client()
            response = await client.get(f"/files/{file_hash}")
            self._last_request_time = datetime.now()

            if response.status_code == 404:
                logger.info(f"Hash not found on VirusTotal: {file_hash[:16]}...")
                return None

            if response.status_code == 429:
                logger.warning("VirusTotal rate limit exceeded (429)")
                return None

            response.raise_for_status()
            data = response.json()

            return self._parse_response(data, file_hash)

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                logger.error("VirusTotal API key is invalid (401)")
            elif e.response.status_code == 403:
                logger.error("VirusTotal API access forbidden (403)")
            else:
                logger.error(f"VirusTotal API error: {e.response.status_code}")
            return None
        except httpx.TimeoutException:
            logger.error("VirusTotal API request timed out")
            return None
        except Exception as e:
            logger.error(f"VirusTotal lookup failed: {e}")
            return None

    @staticmethod
    def _parse_response(data: Dict[str, Any], file_hash: str) -> Dict[str, Any]:
        """Parse VirusTotal v3 API response into a friendly format."""
        attributes = data.get("data", {}).get("attributes", {})

        # Parse detection results
        last_analysis = attributes.get("last_analysis_results", {})
        detections: Dict[str, Dict[str, str]] = {}
        positives = 0

        for engine, result in last_analysis.items():
            category = result.get("category", "undetected")
            if category == "malicious":
                positives += 1
            detections[engine] = {
                "category": category,
                "result": result.get("result", ""),
                "method": result.get("method", ""),
            }

        total = len(last_analysis) if last_analysis else 0

        return {
            "hash": file_hash,
            "positives": positives,
            "total": total,
            "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
            "scan_date": attributes.get("last_analysis_date"),
            "popular_threat_name": attributes.get("popular_threat_classification", {}).get(
                "suggested_threat_label", ""
            ),
            "results": detections,
            "meaningful_name": attributes.get("meaningful_name", ""),
            "type_description": attributes.get("type_description", ""),
            "size": attributes.get("size", 0),
        }

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
