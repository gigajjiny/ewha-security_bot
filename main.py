# main.py

import discord
from discord.ext import commands
from discord import app_commands

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
# 임베드 메시지 생성
# ============================
def create_welcome_embed():
    embed = discord.Embed(
        title="PoliceCat 봇 사용을 환영합니다!",
        description="안녕하세요. PoliceCat 디스코드 보안 봇입니다. 다양한 도움말은 슬래시 명령어를 사용해주세요!",
        color=0xffc2ef
    )
    embed.set_author(name="🔒PoliteCat Discord Bot")
    embed.add_field(name="🛡️ 악성파일 탐지", value="첨부된 파일이 악성 프로그램을 포함하는지 검사하고 자동으로 차단합니다", inline=True)
    embed.add_field(name="🔗 악성 URL 탐지", value="업로드 된 url이 안전한지 검사합니다", inline=True)
    embed.add_field(name="⛔ 블랙리스트 관리", value="멤버들이 도배성 메시지를 보내거나 위험한 행동을 할 경우, 블랙리스트 차단 기능을 제공합니다", inline=True)
    return embed

# ===========================
# 도움말 메시지
# ===========================
class HelpButtons(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    # 1) 악성파일 탐지 버튼
    @discord.ui.button(label="악성파일 탐지", style=discord.ButtonStyle.primary)
    async def malware_scan(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_message("clamAV, YARA 등 다양한 백신API를 활용하여 디스코드에 첨부된 파일이 안전한지 탐지합니다. \n 악성파일이 탐지되었다면 경고 안내 메세지를 출력합니다.", ephemeral=True)

    # 2) 악성 URL 탐지 버튼
    @discord.ui.button(label="악성 URL 탐지", style=discord.ButtonStyle.success)
    async def url_scan(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_message("채팅창에 url 링크를 업로드 할 경우, 해당 링크를 스캔하여 악성 url인지 확인하고 \n 위험할 경우 해당 링크에 대한 경고 메세지를 출력합니다.", ephemeral=True)

    # 3) 블랙리스트 기능 버튼
    @discord.ui.button(label="블랙리스트 기능", style=discord.ButtonStyle.secondary)
    async def blacklist(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_message("멤버 블랙리스트를 관리할 수 있습니다. \n 채팅창에 도배성 메세지를 입력할 경우 채팅 속도가 빠르다는 경고 메세지를 출력합니다. ", ephemeral=True)

# ============================
# Events
# ============================
@bot.event
async def on_ready():
    await bot.tree.sync() 
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

# -------------------------------------------------
# 봇이 서버에 초대되었을 때 자동 메시지 출력
# -------------------------------------------------
@bot.event
async def on_guild_join(guild):

    channel = None

    if guild.system_channel is not None:
        channel = guild.system_channel
    else:
        for ch in guild.text_channels:
            if ch.permissions_for(guild.me).send_messages:
                channel = ch
                break

    if channel is not None:
        embed = create_welcome_embed()
        await channel.send(embed=embed)
    else:
        print(f"[경고] {guild.name} 서버에서 보낼 채널을 찾을 수 없음.")

# ------------------------------------
# /hello -> 서버 초대와 동일한 메시지 출력
# ------------------------------------
@bot.tree.command(name="hello", description="PoliteCat 초대 메시지를 출력")
async def hello(interaction: discord.Interaction):
    embed = create_welcome_embed()
    await interaction.response.send_message(embed=embed)

# ------------------------------------
# /help -> 도움말 메시지 출력
# ------------------------------------
@bot.tree.command(name="help", description="PoliceCat 도움말")
async def help_cmd(interaction: discord.Interaction):

    embed = discord.Embed(
        title="PoliceCat 도움말",
        description="PoliceCat의 주요 기능에 대해 설명드릴게요!",
        color=0xffc2ef
    )
    embed.set_author(name="🔒PoliteCat Discord Bot")

    await interaction.response.send_message(embed=embed, view=HelpButtons())

@bot.tree.command(name="ping", description="Ping test")
async def ping(interaction: discord.Interaction):
    await interaction.response.send_message("test-pong!")

# ============================
# 실행
# ============================
bot.run(TOKEN)




