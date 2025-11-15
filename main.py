# main.py
import os
import asyncio
from datetime import datetime

import discord
from discord.ext import commands
from dotenv import load_dotenv

from security.config import SecurityConfig
from security.service import SecurityService
from security.db import init_db

load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN")
if not TOKEN:
    raise ValueError("DISCORD_TOKEN이 .env에서 로드되지 않았습니다.")

# ===== Discord Intents =====
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.members = True

bot = commands.Bot(command_prefix="!", intents=intents)

# ===== SecurityConfig =====
cfg = SecurityConfig(
    enable_url_scan=True,
    enable_file_scan=True,
    enable_spam_detection=True,
    enable_clamav=True,
    enable_yara=True,
    enable_rabbitmq=True,
    enable_sqlite_log=True,
    enable_safe_browsing=True,
)

security_service = SecurityService(config=cfg)


@bot.event
async def on_ready():
    print(f"Logged in as {bot.user} (ID: {bot.user.id})")

    # SQLite 초기화
    if cfg.enable_sqlite_log:
        await init_db(cfg.sqlite_path)
        print("SQLite DB 초기화 완료")


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot:
        return

    # DB에 원본 메시지 기록
    if cfg.enable_sqlite_log:
        await security_service.log_message_basic(message)

    # 스팸 / 과도한 대화 속도 감지
    if cfg.enable_spam_detection:
        spam_result = security_service.spam_detector.check_message(message)
        if spam_result.is_spam:
            # 경고 + 로그
            await message.channel.send(
                f"⚠️ {message.author.mention} 채팅 속도가 너무 빠릅니다. (최근 {spam_result.count}회 / {spam_result.window_sec}초)",
                reference=message,
            )
            # 필요하면 메시지 삭제
            # await message.delete()
            # 스팸 로그
            if cfg.enable_sqlite_log:
                await security_service.log_event(
                    message,
                    event_type="spam_detected",
                    detail=f"{spam_result.count} msgs / {spam_result.window_sec}s",
                )

    # URL / 첨부파일 검사
    try:
        await security_service.handle_message(message)
    except Exception as e:
        print(f"[ERROR] handle_message 실패: {e!r}")

    await bot.process_commands(message)


@bot.command(name="ping")
async def ping(ctx: commands.Context):
    await ctx.send("pong")


if __name__ == "__main__":
    asyncio.run(bot.start(TOKEN))
