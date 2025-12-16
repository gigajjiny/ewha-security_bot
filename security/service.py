# security/service.py

import io
import hashlib
import aiohttp
import aiosqlite
import discord
from typing import Optional

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

    def _calculate_hash(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    # 보안 전송 기능
    async def process_secure_upload(self, message: discord.Message):
        # 1. 원본 즉시 삭제 시도
        try:
            await message.delete()
        except discord.Forbidden:
            # 권한 없음 안내
            await message.channel.send("봇에게 권한이 없습니다.)", delete_after=5)
        except discord.NotFound:
            pass 

        if not message.attachments:
            await message.channel.send(f"{message.author.mention} 첨부파일이 존재하지 않습니다.", delete_after=5)
            return

        # 2. 봇이 다시 전송
        async with aiohttp.ClientSession() as session:
            for attachment in message.attachments:
                # 다운로드
                async with session.get(attachment.url) as resp:
                    if resp.status != 200:
                        continue
                    data = await resp.read()

                file_obj = discord.File(io.BytesIO(data), filename=attachment.filename)
                
                embed = discord.Embed(
                    title="보안 전송된 파일입니다",
                    description=f"**발신 : ** {message.author.mention}\n**파일 : ** {attachment.filename}",
                    color=0x2ecc71 
                )
                embed.set_footer(text="이 파일은 만료되었습니다.")

                # 이미지 판별
                is_image = False
                if attachment.content_type and attachment.content_type.startswith("image/"):
                    is_image = True
                else:
                    ext = (attachment.filename or "").lower()
                    if ext.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp")):
                        is_image = True
                
                if is_image:
                    embed.set_image(url=f"attachment://{attachment.filename}")
                
                await message.channel.send(embed=embed, file=file_obj)

    # 악성 파일의 해시를 DB에 추가
    async def _register_malicious_hash(self, filename: str, reason: str, file_hash: str = None, file_data: bytes = None):
        if not self.cfg.enable_sqlite_log:
            return
        
        # 해시가 없으면 계산
        if not file_hash and file_data:
            file_hash = self._calculate_hash(file_data)
        
        if file_hash:
            async with aiosqlite.connect(self.cfg.sqlite_path) as db:
                try:
                    await db.execute(
                        "INSERT OR IGNORE INTO file_hashes (file_hash, filename, reason, created_at) VALUES (?, ?, ?, datetime('now'))",
                        (file_hash, filename, reason)
                    )
                    await db.commit()
                    print(f"[Auto-Ban] 악성 해시 등록 완료 : {filename} ({reason})")
                except Exception as e:
                    print(f"[Error] 등록에 실패하였습니다 : {e}")

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

    # --- 메인 핸들러 ---
    async def handle_message(self, message: discord.Message):
        # 1. 스팸 검사
        if self.spam_detector:
            res = self.spam_detector.check_message(message)
            if res.is_spam:
                try:
                    await message.delete()
                    await message.channel.send(f"{message.author.mention} 도배 감지! 메세지가 삭제되었습니다.", delete_after=5)
                    
                    # 스팸 로그 기록
                    if self.cfg.enable_sqlite_log:
                        await log_event(
                            self.cfg.sqlite_path,
                            message.guild.id if message.guild else None,
                            message.channel.id,
                            message.id,
                            message.author.id,
                            "spam_detected",
                            f"Count: {res.count} / Window: {res.window_sec}s"
                        )
                except:
                    pass
                return

        # 2. 보안 전송 명령어 인식
        content = (message.content or "").strip()
        if content == "!s" or content.startswith("!s ") or content == "!보안" or content.startswith("!보안 "):
            await self.process_secure_upload(message)
            return 

        # 3. 로그 기록
        await self.log_message_basic(message)

        # 4. 일반 보안 검사
        try:
            await self._handle_url_scan(message)
        except Exception as e:
            print(f"[ERROR] URL scan failed: {e!r}")

        if message.attachments:
            try:
                await self._handle_file_scan(message)
            except Exception as e:
                print(f"[ERROR] File scan failed: {e!r}")

    # URL 스캔 핸들러
    async def _handle_url_scan(self, message: discord.Message):
        urls = UrlScanner.extract_urls(message.content or "")
        if not urls:
            return

        results = await self.url_scanner.scan_urls(urls)
        # 악성 url만 필터링
        malicious_results = [r for r in results if r.is_malicious]
        
        if malicious_results:
            if self.cfg.enable_sqlite_log:
                for r in malicious_results:
                    await log_scan_result(
                        self.cfg.sqlite_path,
                        message.guild.id if message.guild else None,
                        message.channel.id,
                        message.id,
                        message.author.id,
                        "url",
                        r.url,
                        True,
                        r.reason,
                    )

            joined = "\n".join(f"- {r.url} ({r.reason})" for r in malicious_results)
            await message.channel.send(f" 위험한 URL입니다.**\n{joined}", reference=message)

    # 파일 스캔 핸들러
    async def _handle_file_scan(self, message: discord.Message):
        results = await self.file_scanner.scan_attachments(message.attachments)
        malicious_results = [r for r in results if r.is_malicious]

        # 로그 저장
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

        # 악성 파일 처리
        if malicious_results:
            warn_files = []
            for r in malicious_results:
                warn_files.append(f"{r.attachment.filename} ({r.reason})")
                
                # 자동 차단
                if r.file_hash:
                    await self._register_malicious_hash(
                        filename=r.attachment.filename,
                        reason=r.reason,
                        file_hash=r.file_hash
                    )

            warn_text = f"**악성 파일이 차단되었습니다. :**\n" + "\n".join(warn_files)
            await message.channel.send(warn_text, reference=message)
            
            try:
                await message.delete()
            except:
                pass
