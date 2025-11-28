# security/yara_client.py
import os
import asyncio
from typing import Optional, List

import yara


class YaraClient:
    def __init__(self, rules_path: str = "./rules"):
        self.rules_path = rules_path
        self._rules: Optional[yara.Rules] = None

    def _load_rules(self):
        if self._rules is not None:
            return
        # rules_path 내 모든 .yar 파일을 하나의 룰셋으로 컴파일
        rule_files = {}
        for filename in os.listdir(self.rules_path):
            if filename.endswith(".yar") or filename.endswith(".yara"):
                key = filename
                rule_files[key] = os.path.join(self.rules_path, filename)
        if not rule_files:
            self._rules = None
            return
        self._rules = yara.compile(filepaths=rule_files)

    async def scan_file(self, file_path: str) -> List[str]:
        """
        :return: 매칭된 룰 이름 리스트
        """
        def _scan():
            self._load_rules()
            if self._rules is None:
                return []
            matches = self._rules.match(file_path)
            return [m.rule for m in matches]

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _scan)
