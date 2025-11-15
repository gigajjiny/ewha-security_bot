# security/clamav_client.py
import asyncio
from typing import Optional

import clamd

#구동 환경에 맞게 조정 필요.

class ClamAVClient:
    """
    ClamAV (clamd) 클라이언트 래퍼.
    - 실환경에 맞게 host/port 조정 필요.
    """

    #특히 여기를 수정해줘야 제대로 돌아감
    def __init__(self, host: str = "127.0.0.1", port: int = 3310):
        self.host = host
        self.port = port
        self._client: Optional[clamd.ClamdNetworkSocket] = None

    def _ensure_client(self):
        if self._client is None:
            self._client = clamd.ClamdNetworkSocket(self.host, self.port)

    async def ping(self) -> bool:
        def _ping():
            self._ensure_client()
            return self._client.ping() == "PONG"

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _ping)

    async def scan_file(self, file_path: str) -> tuple[bool, str]:
        """
        :return: (is_malicious, reason)
        """
        def _scan():
            self._ensure_client()
            result = self._client.scan(file_path)
            # result 형식 예시: {'/path/to/file': ('FOUND', 'Win.Test.EICAR_HDB-1')}
            if not result:
                return False, " "
            _, (status, virus_name) = next(iter(result.items()))
            if status == "FOUND":
                return True, virus_name
            return False, ""

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _scan)
