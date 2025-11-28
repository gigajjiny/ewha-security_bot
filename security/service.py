# security/service.py
from typing import Optional

import discord

from .config import SecurityConfig
from .db import log_scan_result, log_event, log_message
from .spam import SpamDetector
from .url_scan import UrlScanner
from .file_scan import FileScanner


class SecurityService:
    def __init__(self, config: SecurityConfig):
        self.cfg = config
        self.url_scanner = UrlScanner(config)
        self.file_scanner = FileScanner(config)
        self.spam_detector = SpamDetector() if config.enable_spam_detection else None

    async def log_message_basic(self, message: discord.Message):
        if not self.cfg.enable_sqlite_log:
            return
        await log_message(
            self.cfg.sqlite_path,
            message.guild.id if message.guild else None,
            message.channel.id,
            message.id,
            message.author.id,
            str(message.author),
            message.content or "",
        )

    async def log_event(self, message: discord.Message, event_type: str, detail: str):
        if not self.cfg.enable_sqlite_log:
            return
        await log_event(
            self.cfg.sqlite_path,
            message.guild.id if message.guild else None,
            message.channel.id,
            message.id,
            message.author.id,
            event_type,
            detail,
        )

    async def handle_message(self, message: discord.Message):
        # URL 검사
        if self.cfg.enable_url_scan:
            await self._handle_url_scan(message)

        # 첨부파일 검사
        if self.cfg.enable_file_scan and message.attachments:
            await self._handle_file_scan(message)

    async def _handle_url_scan(self, message: discord.Message):
        content = message.content or ""
        urls = self.url_scanner.extract_urls(content)
        if not urls:
            return

        results = await self.url_scanner.scan_urls(urls)
        malicious = [r for r in results if r.is_malicious]

        # 로그
        if self.cfg.enable_sqlite_log:
            for r in results:
                await log_scan_result(
                    self.cfg.sqlite_path,
                    message.guild.id if message.guild else None,
                    message.channel.id,
                    message.id,
                    message.author.id,
                    "url",
                    r.url,
                    r.is_malicious,
                    r.reason,
                )

        if malicious:
            joined = ", ".join(f"{r.url} ({r.reason})" for r in malicious)
            warn_text = (
                f"**경고**: 잠재적으로 위험한 URL이 감지되었습니다.\n"
                f"{joined}"
            )
            await message.channel.send(warn_text, reference=message)

            # 필요하면 삭제
            # await message.delete()

    async def _handle_file_scan(self, message: discord.Message):
        results = await self.file_scanner.scan_attachments(message.attachments)
        malicious = [r for r in results if r.is_malicious]

        # 로그
        if self.cfg.enable_sqlite_log:
            for r in results:
                await log_scan_result(
                    self.cfg.sqlite_path,
                    message.guild.id if message.guild else None,
                    message.channel.id,
                    message.id,
                    message.author.id,
                    "file",
                    r.attachment.filename or "",
                    r.is_malicious,
                    r.reason,
                )

        if malicious:
            files_text = ", ".join(
                f"{r.attachment.filename} ({r.reason})" for r in malicious
            )
            warn_text = (
                f"**경고**: 잠재적으로 위험한 첨부파일이 감지되었습니다.\n"
                f"{files_text}"
            )
            await message.channel.send(warn_text, reference=message)
            # await message.delete()
