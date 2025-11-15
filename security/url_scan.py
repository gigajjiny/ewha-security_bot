# security/url_scan.py
import re
import asyncio
from collections import OrderedDict
from typing import List, Tuple, Dict, Any, Optional

import aiohttp

from .config import SecurityConfig

URL_REGEX = re.compile(r"(https?://[^\s]+)", re.IGNORECASE)


class UrlScanResult:
    __slots__ = ("url", "is_malicious", "reason")

    def __init__(self, url: str, is_malicious: bool, reason: str = ""):
        self.url = url
        self.is_malicious = is_malicious
        self.reason = reason


class UrlScanner:
    def __init__(self, cfg: SecurityConfig):
        self.cfg = cfg
        self.cache_size = cfg.url_cache_size
        self._cache: "OrderedDict[str, UrlScanResult]" = OrderedDict()

    @staticmethod
    def extract_urls(text: str) -> List[str]:
        return list({m.group(0).rstrip(".,)") for m in URL_REGEX.finditer(text)})

    def _get_from_cache(self, url: str) -> Optional[UrlScanResult]:
        res = self._cache.get(url)
        if res:
            self._cache.move_to_end(url)
        return res

    def _put_to_cache(self, res: UrlScanResult):
        self._cache[res.url] = res
        self._cache.move_to_end(res.url)
        if len(self._cache) > self.cache_size:
            self._cache.popitem(last=False)

    async def _safe_browsing_check(self, url: str) -> Optional[str]:
        """
        Google Safe Browsing API 호출.
        - 악성일 경우 reason 문자열 반환
        - 아니면 None
        """
        if not (self.cfg.enable_safe_browsing and self.cfg.safe_browsing_api_key):
            return None

        body: Dict[str, Any] = {
            "client": {"clientId": "discord-security-bot", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        params = {"key": self.cfg.safe_browsing_api_key}

        async with aiohttp.ClientSession() as session:
            async with session.post(self.cfg.safe_browsing_endpoint, json=body, params=params) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json()
                if "matches" in data:
                    return "Google Safe Browsing 매칭"

        return None

    async def _scan_single_url(self, url: str) -> UrlScanResult:
        await asyncio.sleep(0)

        reason_parts: List[str] = []

        # 2) Safe Browsing
        sb_reason = await self._safe_browsing_check(url)
        if sb_reason:
            reason_parts.append(sb_reason)

        is_malicious = len(reason_parts) > 0
        reason = "; ".join(reason_parts)
        return UrlScanResult(url, is_malicious, reason)

    async def scan_urls(self, urls: List[str]) -> List[UrlScanResult]:
        results: List[UrlScanResult] = []
        tasks: List[Tuple[str, asyncio.Task]] = []

        for url in urls:
            cached = self._get_from_cache(url)
            if cached:
                results.append(cached)
            else:
                task = asyncio.create_task(self._scan_single_url(url))
                tasks.append((url, task))

        for url, task in tasks:
            res = await task
            self._put_to_cache(res)
            results.append(res)

        return results
