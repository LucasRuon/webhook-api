from __future__ import annotations

import aio_pika
import json
import logging
from typing import Optional
from app.config import RABBITMQ_URL, RABBITMQ_QUEUE

logger = logging.getLogger(__name__)

_connection: Optional[aio_pika.abc.AbstractRobustConnection] = None
_channel: Optional[aio_pika.abc.AbstractChannel] = None


async def connect():
    global _connection, _channel
    try:
        _connection = await aio_pika.connect_robust(RABBITMQ_URL)
        _channel = await _connection.channel()
        logger.info("RabbitMQ conectado: %s", RABBITMQ_URL)
    except Exception as e:
        logger.warning("RabbitMQ indisponivel, webhooks serao salvos mas nao publicados: %s", e)
        _connection = None
        _channel = None


async def disconnect():
    global _connection, _channel
    if _connection:
        await _connection.close()
    _connection = None
    _channel = None


async def publish(exchange_name: str, routing_key: str, queue_name: str, message: dict) -> bool:
    """Publica mensagem no RabbitMQ. Retorna True se publicou, False se falhou."""
    if not _channel:
        logger.warning("RabbitMQ nao conectado, mensagem nao publicada")
        return False

    # Usa fila padrão da env se canal não especificou
    queue_name = queue_name or RABBITMQ_QUEUE

    try:
        if exchange_name:
            exchange = await _channel.declare_exchange(
                exchange_name, aio_pika.ExchangeType.TOPIC, durable=True
            )
        else:
            exchange = _channel.default_exchange

        queue = await _channel.declare_queue(queue_name, durable=True)
        if exchange_name:
            await queue.bind(exchange, routing_key=routing_key or queue_name)

        await exchange.publish(
            aio_pika.Message(
                body=json.dumps(message, ensure_ascii=False).encode(),
                content_type="application/json",
                delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
            ),
            routing_key=routing_key or queue_name,
        )
        return True

    except Exception as e:
        logger.error("Erro ao publicar no RabbitMQ: %s", e)
        return False


async def get_status() -> dict:
    """Retorna status da conexao RabbitMQ."""
    if _connection and not _connection.is_closed:
        return {"connected": True, "url": RABBITMQ_URL.split("@")[-1], "default_queue": RABBITMQ_QUEUE}
    return {"connected": False, "url": RABBITMQ_URL.split("@")[-1], "default_queue": RABBITMQ_QUEUE}
