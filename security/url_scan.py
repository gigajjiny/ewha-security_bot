# security/url_scan.py
import re
import asyncio
from collections import OrderedDict
from typing import List, Tuple, Dict, Any, Optional

import aiohttp
from aiohttp import ClientResponse
from urllib.parse import urlparse, urljoin

from .config import SecurityConfig


# ============================
# URL 정규식 (LinkWarden 수준)
# ============================
URL_EXTRACT_REGEX = re.compile(
    r"(?i)\bhttps?://[^\s<>'\"(){}\[\]]+"
)

ALLOWED_CHARS_REGEX = re.compile(r'^[a-zA-Z0-9\-\.\/\?=&%#_:]*$')
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
        self.max_redirects = 5    # 요청한 값

    # -----------------------------
    # URL 추출
    # -----------------------------
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        if not text:
            return []

        urls = []
        for m in URL_EXTRACT_REGEX.finditer(text):
            url = m.group(0).rstrip("),.!?")
            if len(url) <= MAX_URL_LENGTH:
                urls.append(url)

        # 중복 제거 + 순서 유지
        seen = set()
        out = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out

    # -----------------------------
    # LRU 캐시
    # -----------------------------
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

    # -----------------------------
    # URL 확장(단축 URL 자동 해석)
    # -----------------------------
    async def _expand_url(self, url: str) -> str:
        """
        HEAD → 302 redirect 따라가며 최종 URL 획득
        너무 완고하면 실패할 수 있어서 GET fallback 있음
        """
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=8)
            ) as session:
                current = url
                for _ in range(self.max_redirects):
                    try:
                        async with session.head(current, allow_redirects=False) as resp:
                            # 3xx redirect인 경우
                            if 300 <= resp.status < 400:
                                loc = resp.headers.get("Location")
                                if not loc:
                                    return current
                                current = urljoin(current, loc)
                                continue
                            return current
                    except Exception:
                        # fallback: GET 으로 확인
                        async with session.get(current, allow_redirects=True) as r2:
                            return str(r2.url)
                return current
        except Exception:
            return url  # 확장 실패 시 원본 URL 반환

    # -----------------------------
    # 로컬 악성 URL 룰 (목적지 기준)
    # -----------------------------
    @staticmethod
    def _local_rule_check(url: str) -> Optional[str]:
        lowered = url.lower()
        domain = urlparse(lowered).netloc

        # 1) 테스트용 패턴
        TEST_PATTERNS = [
            "eicar", "malware.test", "phishing.test"
        ]
        if any(p in lowered for p in TEST_PATTERNS):
            return "Local rule: Test malicious pattern"

        # 2) 민감 키워드 + http
        SUSPICIOUS_KEYWORDS = [
            "login", "verify", "account", "secure", "password",
            "bank", "wallet", "update", "certificate", "auth"
        ]
        if lowered.startswith("http://") and any(k in lowered for k in SUSPICIOUS_KEYWORDS):
            return "Local rule: Sensitive keyword over insecure HTTP"

        # 3) 피싱 사이트에서 자주 쓰는 패턴 (일반적 heuristic)
        PHISH_PATTERNS = [
            "account-security",
            "verify-account",
            "reset-password",
            "secure-login",
            "bank-login",
            "wallet-auth"
        ]
        if any(p in lowered for p in PHISH_PATTERNS):
            return "Local rule: Common phishing keyword pattern"

        # 4) 한국형 피싱 패턴
        KR_KEYWORDS = [
            "명의도용", "본인확인", "계좌", "신한", "농협", "카카오",
            "금융센터", "인증", "보안"
        ]
        if any(k in lowered for k in KR_KEYWORDS):
            return "Local rule: KR phishing-related keyword"

        return None

    # -----------------------------
    # Safe Browsing
    # -----------------------------
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

    # -----------------------------
    # URL 스캔 (단축→확장→정상 URL→검사)
    # -----------------------------
    async def _scan_single_url(self, url: str) -> UrlScanResult:
        # 1) 단축 URL 확장
        expanded = await self._expand_url(url)

        reasons = []

        # 2) 로컬 룰
        local = self._local_rule_check(expanded)
        if local:
            reasons.append(local)

        # 3) Safe Browsing
        sb = await self._safe_browsing_check(expanded)
        if sb:
            reasons.append(sb)

        malicious = len(reasons) > 0
        reason = "; ".join(reasons)
        return UrlScanResult(url, malicious, reason)

    # -----------------------------
    # 여러 URL 처리
    # -----------------------------
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

# fallback: HTML 내부에서 meta refresh / JS redirect 탐지
try:
    async with session.get(current) as r3:
        if r3.status == 200 and "text/html" in r3.headers.get("Content-Type", ""):
            html = await r3.text()

            # 1) meta refresh
            import re
            m = re.search(
                r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+url=([^"\'>]+)',
                html,
                re.IGNORECASE
            )
            if m:
                new_url = urljoin(current, m.group(1))
                return await self._expand_url(new_url)

            # 2) JavaScript redirect
            m2 = re.search(
                r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
                html,
                re.IGNORECASE
            )
            if m2:
                new_url = urljoin(current, m2.group(1))
                return await self._expand_url(new_url)

        return current
except Exception:
    return current
