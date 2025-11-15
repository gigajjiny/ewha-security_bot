# security/spam.py
from dataclasses import dataclass
from collections import defaultdict, deque
from time import time

import discord


@dataclass
class SpamCheckResult:
    is_spam: bool
    count: int
    window_sec: int


class SpamDetector:
    """
    단순 속도 기반 스팸 감지:
    - 최근 window_sec 초 동안 message_limit 회 이상이면 스팸으로 판단
    """

    def __init__(self, window_sec: int = 10, message_limit: int = 8):
        self.window_sec = window_sec
        self.message_limit = message_limit
        # (guild_id, user_id) -> deque[timestamps]
        self.history = defaultdict(lambda: deque())

    def check_message(self, message: discord.Message) -> SpamCheckResult:
        now = time()
        key = (message.guild.id if message.guild else 0, message.author.id)
        dq = self.history[key]

        dq.append(now)

        # window 밖의 오래된 기록 제거
        while dq and now - dq[0] > self.window_sec:
            dq.popleft()

        is_spam = len(dq) >= self.message_limit
        return SpamCheckResult(is_spam=is_spam, count=len(dq), window_sec=self.window_sec)
