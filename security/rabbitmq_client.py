# security/rabbitmq_client.py
import json
import asyncio
from typing import Any, Dict

import aio_pika


class RabbitMQClient:
    def __init__(self, amqp_url: str, queue_name: str = "security_tasks"):
        self.amqp_url = amqp_url
        self.queue_name = queue_name
        self._lock = asyncio.Lock()
        self._connection: aio_pika.RobustConnection | None = None
        self._channel: aio_pika.abc.AbstractChannel | None = None

    async def _ensure_connection(self):
        async with self._lock:
            if self._connection and not self._connection.is_closed:
                return
            self._connection = await aio_pika.connect_robust(self.amqp_url)
            self._channel = await self._connection.channel()

    async def send_task(self, task: Dict[str, Any]):
        await self._ensure_connection()
        assert self._channel is not None

        queue = await self._channel.declare_queue(self.queue_name, durable=True)
        body = json.dumps(task).encode("utf-8")

        await self._channel.default_exchange.publish(
            aio_pika.Message(body=body, delivery_mode=aio_pika.DeliveryMode.PERSISTENT),
            routing_key=queue.name,
        )
