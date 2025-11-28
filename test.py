# test_bot_simple.py (수정된 형태)
import os, asyncio, socket, threading, tracemalloc, discord
from discord.ext import commands
from discord import app_commands
from dotenv import load_dotenv

# ===== .env 로드 =====
load_dotenv()
TOKEN = os.getenv("BOT_TOKEN")
if not TOKEN:
    raise ValueError("BOT_TOKEN이 .env에서 로드되지 않았습니다.")

# ===== Health Check 서버 =====
def run_health_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 8001))  # ← 포트 8001로 변경 (main.py와 충돌 방지)
    s.listen(1)
    s.settimeout(5)
    while True:
        try:
            conn, _ = s.accept()
            conn.close()
        except socket.timeout:
            continue

threading.Thread(target=run_health_server, daemon=True).start()

# ===== Discord Intents =====
intents = discord.Intents.all()
intents.message_content = True
intents.members = True

# ===== Test용 간단한 봇 =====
class TestBot(commands.Bot):
    def __init__(self, **kwargs):
        super().__init__(command_prefix='!', intents=intents, **kwargs)
        self.synced = False

    async def on_ready(self):
        print(f"테스트 봇 로그인 완료: {self.user}")
        if not self.synced:
            await self.tree.sync()
            print("슬래시 명령어 동기화 완료")
            self.synced = True
        tracemalloc.start()

    async def on_message(self, message: discord.Message):
        if message.author.bot:
            return
        if message.content == "핑":
            await message.channel.send("퐁")

# ===== 명령어 =====
bot = TestBot()

@bot.tree.command(name="안녕", description="테스트 봇에게 인사를 보냅니다.")
async def greet(interaction: discord.Interaction):
    await interaction.response.send_message("안녕하세요! 테스트 봇입니다.")

# ===== 실행부 =====
async def main():
    async with bot:
        await bot.start(TOKEN)

if __name__ == "__main__":
    asyncio.run(main())
