# worker.py
import asyncio
import json
import os

import aio_pika
from dotenv import load_dotenv

from security.config import SecurityConfig
from security.clamav_client import ClamAVClient
from security.yara_client import YaraClient

load_dotenv()

cfg = SecurityConfig()

clamav = ClamAVClient(cfg.clamav_host, cfg.clamav_port) if cfg.enable_clamav else None
yara_client = YaraClient(cfg.yara_rules_path) if cfg.enable_yara else None


async def handle_task(message: aio_pika.IncomingMessage):
    async with message.process():
        try:
            task = json.loads(message.body)
        except json.JSONDecodeError:
            print("[worker] 잘못된 JSON, 무시")
            return

        ttype = task.get("type")
        if ttype == "file_scan":
            tmp_path = task.get("tmp_path")
            filename = task.get("filename")
            if not tmp_path or not os.path.exists(tmp_path):
                print("[worker] tmp_path 존재하지 않음, 무시")
                return

            reasons = []
            malicious = False

            if clamav:
                is_bad, virus_name = await clamav.scan_file(tmp_path)
                if is_bad:
                    malicious = True
                    reasons.append(f"ClamAV: {virus_name}")

            if yara_client:
                matches = await yara_client.scan_file(tmp_path)
                if matches:
                    malicious = True
                    reasons.append("YARA: " + ", ".join(matches))

            print(f"[worker] 파일 분석 결과: {filename}, 악성={malicious}, 이유={'; '.join(reasons)}")

            # 여기에서:
            # - DB에 추가 로그 기록
            # - 웹훅으로 디스코드 채널에 결과 전송
            # 등을 수행할 수 있음

            try:
                os.remove(tmp_path)
            except OSError:
                pass

        else:
            print(f"[worker] 알 수 없는 작업 타입: {ttype}")


async def main():
    connection = await aio_pika.connect_robust(cfg.rabbitmq_url)
    channel = await connection.channel()
    queue = await channel.declare_queue("security_tasks", durable=True)
    print("[worker] 대기 중...")

    await queue.consume(handle_task)
    await asyncio.Future()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
