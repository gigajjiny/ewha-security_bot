# main.py

import discord
from discord.ext import commands

from dotenv import load_dotenv
import os

from security.config import SecurityConfig
from security.service import SecurityService


# ============================
# 환경변수 로딩
# ============================
load_dotenv()
TOKEN = os.getenv("DISCORD_TOKEN")
if not TOKEN:
    raise ValueError("DISCORD_TOKEN not found in environment (.env)")


# ============================
# Intents
# ============================
intents = discord.Intents.default()
intents.message_content = True     # URL, file 읽기 위해 필수
intents.members = True


# ============================
# Bot 초기화
# ============================
bot = commands.Bot(
    command_prefix="!",
    intents=intents
)


# ============================
# Security Config & Service
# ============================
cfg = SecurityConfig()
security_service = SecurityService(config=cfg)


# ============================
# Debug: on_message 로그 확인
# ============================
def debug_print(*args):
    print("[DEBUG]", *args)


# ============================
# Events
# ============================
@bot.event
async def on_ready():
    print(f"[INFO] Logged in as {bot.user} (ID: {bot.user.id})")


@bot.event
async def on_message(message: discord.Message):

    # ---- 1) 자기 자신 메시지 무시 ----
    if message.author == bot.user:
        return

    # ---- 2) 디버그 출력 ----
    debug_print("on_message:", message.content, "attachments:", message.attachments)

    # ---- 3) 보안 스캔 실행 ----
    try:
        await security_service.handle_message(message)
    except Exception as e:
        print("[ERROR] handle_message:", repr(e))

    # ---- 4) 명령어 처리 ----
    await bot.process_commands(message)


# ============================
# Commands
# ============================
@bot.command()
async def ping(ctx):
    await ctx.send("pong")


# ============================
# 실행
# ============================
bot.run(TOKEN)

