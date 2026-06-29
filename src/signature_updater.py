"""
Signature Updater — Auto-download latest virus definitions

Supports:
- ClamAV CVD database updates (via freshclam)
- YARA rule updates from online sources
- Local signature cache management
"""

import asyncio
import subprocess
import hashlib
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import httpx

from .utils import get_logger, ensure_directory

logger = get_logger("signature_updater")


class SignatureUpdater:
    """
    Manages automatic signature database updates.

    Sources:
    - ClamAV (via freshclam CLI)
    - YARA rules from GitHub/community repos
    """

    def __init__(
        self,
        signatures_dir: str = "./data/signatures",
        yara_rules_dir: str = "./rules/yara",
        update_interval_hours: int = 6,
    ):
        self.signatures_dir = Path(signatures_dir)
        self.yara_rules_dir = Path(yara_rules_dir)
        self.update_interval = timedelta(hours=update_interval_hours)
        self._last_update: Optional[datetime] = None
        self._state_file = self.signatures_dir / "update_state.json"

        ensure_directory(str(self.signatures_dir))

    # ── State persistence ──────────────────────────────────────

    def _load_state(self) -> Dict[str, Any]:
        if self._state_file.exists():
            try:
                return json.loads(self._state_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    def _save_state(self, state: Dict[str, Any]) -> None:
        state["updated_at"] = datetime.now().isoformat()
        self._state_file.write_text(json.dumps(state, indent=2), encoding="utf-8")

    # ── ClamAV updates ─────────────────────────────────────────

    async def update_clamav(self) -> bool:
        """
        Update ClamAV virus definitions via freshclam.

        Returns:
            True if update succeeded
        """
        logger.info("Updating ClamAV signatures...")
        try:
            result = subprocess.run(
                ["freshclam", "--stdout", "--no-dns"],
                capture_output=True,
                text=True,
                timeout=120,
                creationflags=subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW")
                else 0,
            )

            if "Database updated" in result.stdout or "is up to date" in result.stdout:
                logger.info("ClamAV signatures updated successfully")
                self._last_update = datetime.now()
                return True
            else:
                logger.warning(f"freshclam output: {result.stdout[:200]}")
                if result.stderr:
                    logger.warning(f"freshclam errors: {result.stderr[:200]}")
                return False

        except FileNotFoundError:
            logger.warning(
                "freshclam not found — install ClamAV for signature updates"
            )
            return False
        except subprocess.TimeoutExpired:
            logger.error("ClamAV update timed out")
            return False
        except Exception as e:
            logger.error(f"ClamAV update error: {e}")
            return False

    # ── YARA rule updates ──────────────────────────────────────

    async def update_yara_rules(self) -> bool:
        """
        Download latest YARA rules from community sources.

        Returns:
            True if any rules were updated
        """
        logger.info("Checking for YARA rule updates...")
        updated = False

        # Sources: community YARA rule repos (raw URLs)
        sources = [
            {
                "name": "crabav_rules",
                "url": "https://raw.githubusercontent.com/toilanguyen2910/crabav/main/rules/yara/malware_index.yar",
                "file": self.yara_rules_dir / "malware_index.yar",
            },
        ]

        state = self._load_state()
        yara_state = state.get("yara_etags", {})

        async with httpx.AsyncClient(timeout=30) as client:
            for source in sources:
                try:
                    headers = {}
                    etag = yara_state.get(source["name"])
                    if etag:
                        headers["If-None-Match"] = etag

                    response = await client.get(
                        source["url"], headers=headers
                    )

                    if response.status_code == 304:
                        logger.debug(f"YARA rules up-to-date: {source['name']}")
                        continue

                    if response.status_code == 200:
                        content = response.text
                        # Simple validation: must contain 'rule' keyword
                        if "rule " not in content[:500]:
                            logger.warning(
                                f"Skipping {source['name']}: doesn't look like YARA rules"
                            )
                            continue

                        source["file"].parent.mkdir(parents=True, exist_ok=True)
                        source["file"].write_text(content, encoding="utf-8")

                        new_etag = response.headers.get("ETag", "")
                        if new_etag:
                            yara_state[source["name"]] = new_etag

                        logger.info(f"Updated YARA rules: {source['name']}")
                        updated = True

                    elif response.status_code == 404:
                        logger.debug(f"YARA source not found: {source['url']}")

                except httpx.TimeoutException:
                    logger.warning(f"Timeout fetching {source['name']}")
                except Exception as e:
                    logger.error(f"Failed to fetch {source['name']}: {e}")

        if updated:
            state["yara_etags"] = yara_state
            self._save_state(state)

        return updated

    # ── Main update flow ───────────────────────────────────────

    async def update_all(self) -> Dict[str, bool]:
        """
        Run all signature updates.

        Returns:
            Dict of update source → success
        """
        results: Dict[str, bool] = {}

        # Only update if interval has passed
        if self._last_update and (datetime.now() - self._last_update) < self.update_interval:
            logger.info(
                f"Update skipped — last update was "
                f"{(datetime.now() - self._last_update).seconds // 60} min ago"
            )
            return {"skipped": True}

        # ClamAV
        results["clamav"] = await self.update_clamav()

        # YARA rules
        results["yara"] = await self.update_yara_rules()

        self._last_update = datetime.now()

        return results

    async def update_loop(self, interval_hours: int = 6) -> None:
        """
        Run periodic updates forever.

        Args:
            interval_hours: Hours between updates
        """
        logger.info(f"Starting signature update loop (every {interval_hours}h)")
        while True:
            try:
                await self.update_all()
            except Exception as e:
                logger.error(f"Update loop error: {e}")

            await asyncio.sleep(interval_hours * 3600)
