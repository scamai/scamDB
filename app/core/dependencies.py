from motor.motor_asyncio import AsyncIOMotorClient
from typing import Optional
from ..models.models import indexes
from .config import settings
import logging

LOGGER = logging.getLogger(__name__)

class Database:
    def __init__(self):
        self.client: Optional[AsyncIOMotorClient] = None
        self.db = None

    async def connect_mongodb(self):
        try:
            self.client = AsyncIOMotorClient(settings.MONGODB_URL)
            self.db = self.client[settings.MONGODB_DB_NAME]

            collection = self.db["scammers"]
            await collection.delete_many({"email": None})
            for index in indexes:
                await collection.create_index(
                    index["fields"],
                    unique=index.get("unique", False),
                    background=True
                )
            LOGGER.info("Successfully connected to MongoDB!")
        except Exception as e:
            LOGGER.error(f"Error connecting to MongoDB: {e}")
            raise e

    async def close_mongodb(self):
        if self.client:
            self.client.close()

db = Database()
