# security/file_scan.py
import os
import asyncio
import tempfile
from collections import OrderedDict
from typing import List, Optional

import discord

from .config import SecurityConfig
from .clamav_client import ClamAVClient
from .yara_client import YaraClient
from .rabbitmq_client import RabbitMQClient


class FileScanResult:
    __slots__ = ("attachment", "is_malicious", "reason")

    def __init__(self, attachment: discord.Attachment, is_malicious: bool, reason: str = ""):
        self.attachment = attachment
        self.is_malicious = is_malicious
        self.reason = reason


class FileScanner:
    """
    - 경량 확장자 필터
    - ClamAV 실시간 스캔
    - YARA 룰 스캔
    - RabbitMQ로 추가 offloading
    """

    def __init__(self, cfg: SecurityConfig):
        self.cfg = cfg
        self.cache_size = cfg.file_cache_size
        self._cache: "OrderedDict[str, FileScanResult]" = OrderedDict()

        self.blocked_extensions = {".exe", ".scr", ".bat", ".cmd", ".js"}

        self.clamav = ClamAVClient(cfg.clamav_host, cfg.clamav_port) if cfg.enable_clamav else None
        self.yara = YaraClient(cfg.yara_rules_path) if cfg.enable_yara else None
        self.rabbitmq = RabbitMQClient(cfg.rabbitmq_url) if cfg.enable_rabbitmq else None

    def _cache_key(self, attachment: discord.Attachment) -> str:
        return f"{attachment.filename}:{attachment.size}"

    def _get_from_cache(self, key: str) -> Optional[FileScanResult]:
        res = self._cache.get(key)
        if res:
            self._cache.move_to_end(key)
        return res

    def _put_to_cache(self, key: str, res: FileScanResult):
        self._cache[key] = res
        self._cache.move_to_end(key)
        if len(self._cache) > self.cache_size:
            self._cache.popitem(last=False)

    async def _download_to_temp(self, attachment: discord.Attachment) -> str:
        suffix = os.path.splitext(attachment.filename or "")[1]
        fd, path = tempfile.mkstemp(suffix=suffix)
        os.close(fd)
        await attachment.save(path)
        return path

    async def _scan_single_attachment(self, attachment: discord.Attachment) -> FileScanResult:
        # 0) 확장자 필터
        filename = (attachment.filename or "").lower()
        for ext in self.blocked_extensions:
            if filename.endswith(ext):
                return FileScanResult(attachment, True, f"차단 확장자({ext})")

        # 1) 파일 다운로드
        tmp_path = await self._download_to_temp(attachment)

        try:
            reasons: List[str] = []
            malicious = False

            # 2) ClamAV
            if self.clamav:
                is_bad, virus_name = await self.clamav.scan_file(tmp_path)
                if is_bad:
                    malicious = True
                    reasons.append(f"ClamAV: {virus_name}")

            # 3) YARA
            if self.yara:
                matches = await self.yara.scan_file(tmp_path)
                if matches:
                    malicious = True
                    reasons.append("YARA rules: " + ", ".join(matches))

            # 4) RabbitMQ offload (비동기 추가 분석용)
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
            return FileScanResult(attachment, malicious, reason_str)
        finally:
            # ClamAV/YARA 쪽에서 tmp_path를 직접 쓸 수도 있으니
            # offload용으로 쓰고 싶으면 삭제를 늦추거나 worker에서 처리하게 구조 조정 가능.
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
            self._put_to_cache(key, res)
            results.append(res)

        return results
