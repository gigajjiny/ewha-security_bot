# security/file_scan.py

import os
import asyncio
import tempfile
import hashlib
import aiosqlite
from collections import OrderedDict
from typing import List, Optional

import discord

from .config import SecurityConfig
from .clamav_client import ClamAVClient
from .yara_client import YaraClient
from .rabbitmq_client import RabbitMQClient


class FileScanResult:
    # file_hash 필드 추가
    __slots__ = ("attachment", "is_malicious", "reason", "file_hash")

    def __init__(self, attachment: discord.Attachment, is_malicious: bool, reason: str = "", file_hash: str = None):
        self.attachment = attachment
        self.is_malicious = is_malicious
        self.reason = reason
        self.file_hash = file_hash


class FileScanner:
    def __init__(self, cfg: SecurityConfig):
        self.cfg = cfg
        self.cache_size = cfg.file_cache_size
        self._cache: "OrderedDict[str, FileScanResult]" = OrderedDict()

        self.blocked_extensions = {".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar"}

        self.clamav = ClamAVClient(cfg.clamav_host, cfg.clamav_port) if cfg.enable_clamav else None
        self.yara = YaraClient(cfg.yara_rules_path) if cfg.enable_yara else None
        self.rabbitmq = RabbitMQClient(cfg.rabbitmq_url) if cfg.enable_rabbitmq else None

    def _cache_key(self, attachment: discord.Attachment) -> str:
        return f"{attachment.id}_{attachment.filename}"

    def _get_from_cache(self, key: str) -> Optional[FileScanResult]:
        if key in self._cache:
            return self._cache[key]
        return None

    # 파일 해시 계산
    def _calculate_file_hash(self, filepath: str) -> str:
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.hexdigest()

    # DB에서 해시 차단 여부 확인
    async def _check_hash_in_db(self, file_hash: str) -> Optional[str]:
        if not self.cfg.enable_sqlite_log:
            return None
        
        async with aiosqlite.connect(self.cfg.sqlite_path) as db:
            async with db.execute("SELECT reason FROM file_hashes WHERE file_hash = ?", (file_hash,)) as cursor:
                row = await cursor.fetchone()
                if row:
                    return row[0]
        return None

    async def _scan_single_attachment(self, attachment: discord.Attachment) -> FileScanResult:
        # 1) 확장자 필터
        ext = os.path.splitext(attachment.filename)[1].lower()
        
        # 임시 파일 다운로드
        fd, tmp_path = tempfile.mkstemp(suffix="_" + attachment.filename)
        os.close(fd)

        try:
            await attachment.save(tmp_path)
            
            # 해시 계산 + 블랙리스트 검사
            file_hash = await asyncio.to_thread(self._calculate_file_hash, tmp_path)
            blocked_reason = await self._check_hash_in_db(file_hash)
            
            if blocked_reason:
                return FileScanResult(attachment, True, f"🚫 차단된 파일 재업로드 감지 ({blocked_reason})", file_hash)

            # 3) 확장자 차단
            if ext in self.blocked_extensions:
                return FileScanResult(attachment, True, f"차단된 확장자: {ext}", file_hash)

            # 4) ClamAV / YARA 스캔
            reasons = []
            malicious = False

            if self.clamav:
                is_bad, virus_name = await self.clamav.scan_file(tmp_path)
                if is_bad:
                    malicious = True
                    reasons.append(f"ClamAV: {virus_name}")

            if self.yara:
                matches = await self.yara.scan_file(tmp_path)
                if matches:
                    malicious = True
                    reasons.append("YARA: " + ", ".join(matches))

            # 5) RabbitMQ offload
            if self.rabbitmq:
                await self.rabbitmq.send_task(
                    {
                        "type": "file_scan",
                        "filename": attachment.filename,
                        "size": attachment.size,
                        "tmp_path": tmp_path,
                    }
                )

            reason_str = "; ".join(reasons)
            return FileScanResult(attachment, malicious, reason_str, file_hash)

        finally:
            if not self.cfg.enable_rabbitmq:
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    async def scan_attachments(self, attachments: List[discord.Attachment]) -> List[FileScanResult]:
        results: List[FileScanResult] = []
        tasks = []

        for att in attachments:
            key = self._cache_key(att)
            cached = self._get_from_cache(key)
            if cached:
                results.append(cached)
            else:
                task = asyncio.create_task(self._scan_single_attachment(att))
                tasks.append((key, task))

        for key, task in tasks:
            res = await task
            # 캐싱
            self._cache[key] = res
            if len(self._cache) > self.cache_size:
                self._cache.popitem(last=False)
            results.append(res)

        return results
