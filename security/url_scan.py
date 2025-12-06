# security/url_scan.py

import re
import asyncio
from collections import OrderedDict
from typing import List, Tuple, Dict, Any, Optional

import aiohttp
from urllib.parse import urlparse, urljoin

from .config import SecurityConfig


# ==========================================================
# URL 추출 정규식 (LinkWarden 수준)
# ==========================================================
URL_EXTRACT_REGEX = re.compile(
    r"(?i)\bhttps?://[^\s<>'\"(){}\[\]]+"
)

MAX_URL_LENGTH = 2000


class UrlScanResult:
    __slots__ = ("url", "is_malicious", "reason")

    def __init__(self, url: str, is_malicious: bool, reason: str):
        self.url = url
        self.is_malicious = is_malicious
        self.reason = reason


class UrlScanner:
    def __init__(self, cfg: SecurityConfig):
        self.cfg = cfg
        self.cache_size = cfg.url_cache_size
        self._cache: "OrderedDict[str, UrlScanResult]" = OrderedDict()
        self.max_redirects = 5

    # ==========================================================
    # URL 추출
    # ==========================================================
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        if not text:
            return []
        urls = []
        for m in URL_EXTRACT_REGEX.finditer(text):
            url = m.group(0).rstrip("),.!?")
            if len(url) <= MAX_URL_LENGTH:
                urls.append(url)

        # 중복 제거
        seen = set()
        out = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out

    # ==========================================================
    # LRU 캐시
    # ==========================================================
    def _get_from_cache(self, key: str) -> Optional[UrlScanResult]:
        res = self._cache.get(key)
        if res:
            self._cache.move_to_end(key)
        return res

    def _put_to_cache(self, key: str, res: UrlScanResult):
        self._cache[key] = res
        self._cache.move_to_end(key)
        if len(self._cache) > self.cache_size:
            self._cache.popitem(last=False)

    # ==========================================================
    # URL 확장 (HEAD → GET → HTML redirect)
    # ==========================================================
    async def _expand_url(self, url: str) -> str:
        """
        1) HEAD 요청으로 3xx redirect 감지
        2) 실패하면 GET fallback
        3) HTML 내부의 meta refresh / JS redirect 탐지
        """
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=8)
            ) as session:

                current = url

                # ---------------------------
                # 1) HEAD 기반 redirect 추적
                # ---------------------------
                for _ in range(self.max_redirects):
                    try:
                        async with session.head(current, allow_redirects=False) as resp:
                            if 300 <= resp.status < 400:
                                loc = resp.headers.get("Location")
                                if not loc:
                                    return current
                                current = urljoin(current, loc)
                                continue
                            return current
                    except Exception:
                        # ---------------------------
                        # 2) GET fallback
                        # ---------------------------
                        try:
                            async with session.get(current, allow_redirects=True) as g:
                                return str(g.url)
                        except Exception:
                            return current

                # ---------------------------
                # 3) HTML 내부 soft redirect 탐지
                # ---------------------------
                try:
                    async with session.get(current) as r3:
                        if r3.status == 200 and "text/html" in r3.headers.get("Content-Type", ""):
                            html = await r3.text()

                            # meta refresh
                            m = re.search(
                                r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+url=([^"\'>]+)',
                                html,
                                re.IGNORECASE
                            )
                            if m:
                                new_url = urljoin(current, m.group(1))
                                return await self._expand_url(new_url)

                            # JavaScript redirect 패턴들
                            JS_PATTERNS = [
                                r'window\.location\s*=\s*["\']([^"\']+)["\']',
                                r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
                                r'location\.href\s*=\s*["\']([^"\']+)["\']',
                                r'top\.location\s*=\s*["\']([^"\']+)["\']',
                                r'self\.location(?:\.replace)?\s*\(\s*["\']([^"\']+)["\']'
                            ]

                            for pat in JS_PATTERNS:
                                m2 = re.search(pat, html, re.IGNORECASE)
                                if m2:
                                    new_url = urljoin(current, m2.group(1))
                                    return await self._expand_url(new_url)

                        return current
                except Exception:
                    return current

        except Exception:
            return url

    # ==========================================================
    # 로컬 악성 URL 룰
    # ==========================================================
    @staticmethod
    def _local_rule_check(url: str) -> Optional[str]:
        lowered = url.lower()

        # 테스트 패턴
        TEST_PATTERNS = ["eicar", "malware.test", "phishing.test"]
        if any(p in lowered for p in TEST_PATTERNS):
            return "Local rule: Test malicious pattern"

        # 민감 키워드 + http
        SUSPICIOUS_KEYWORDS = [
            "login", "verify", "account", "secure", "password",
            "bank", "wallet", "update", "certificate", "auth"
        ]
        if lowered.startswith("http://") and any(k in lowered for k in SUSPICIOUS_KEYWORDS):
            return "Local rule: Sensitive keyword over insecure HTTP"

        # 일반 피싱 패턴
        PHISH_PATTERNS = [
            "account-security", "verify-account",
            "reset-password", "secure-login",
            "bank-login", "wallet-auth"
        ]
        if any(p in lowered for p in PHISH_PATTERNS):
            return "Local rule: Common phishing pattern"

        # 한국형 키워드
        KR = ["본인확인", "명의도용", "계좌", "농협", "신한", "카카오", "인증", "보안"]
        if any(k in lowered for k in KR):
            return "Local rule: KR phishing keyword"

        return None

    # ==========================================================
    # Safe Browsing
    # ==========================================================
    async def _safe_browsing_check(self, url: str) -> Optional[str]:
        if not (self.cfg.enable_safe_browsing and self.cfg.safe_browsing_api_key):
            return None

        body = {
            "client": {"clientId": "discord-security-bot", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        params = {"key": self.cfg.safe_browsing_api_key}

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.cfg.safe_browsing_endpoint,
                    json=body,
                    params=params
                ) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
                    if data.get("matches"):
                        return "Google Safe Browsing match"
        except Exception:
            return None
        return None

    # ==========================================================
    # URL 스캔 (단건)
    # ==========================================================
    async def _scan_single_url(self, url: str) -> UrlScanResult:
        expanded = await self._expand_url(url)

        reasons = []

        local_reason = self._local_rule_check(expanded)
        if local_reason:
            reasons.append(local_reason)

        sb_reason = await self._safe_browsing_check(expanded)
        if sb_reason:
            reasons.append(sb_reason)

        malicious = len(reasons) > 0
        reason = "; ".join(reasons)
        return UrlScanResult(url, malicious, reason)

    # ==========================================================
    # URL 스캔 (여러 URL)
    # ==========================================================
    async def scan_urls(self, urls: List[str]) -> List[UrlScanResult]:
        results = []
        tasks: List[Tuple[str, asyncio.Task]] = []

        for url in urls:
            cached = self._get_from_cache(url)
            if cached:
                results.append(cached)
            else:
                t = asyncio.create_task(self._scan_single_url(url))
                tasks.append((url, t))

        for url, t in tasks:
            r = await t
            self._put_to_cache(url, r)
            results.append(r)

        return results
