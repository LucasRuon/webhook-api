import os
from dotenv import load_dotenv

load_dotenv()

WEBHOOK_TOKEN = os.getenv("WEBHOOK_TOKEN", "")
RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
RABBITMQ_QUEUE = os.getenv("RABBITMQ_QUEUE", "webhook_events")
