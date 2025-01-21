from pydantic_settings import BaseSettings
from functools import lru_cache
import os

class Settings(BaseSettings):
    APP_NAME: str = "ScamAI MongoDB App"
    DEBUG_MODE: bool = True

    JWT_ALGORITHM : str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES : int = 60

    APP_SECRET_KEY: str = os.getenv('APP_SECRET_KEY')
    MONGODB_URL: str  = os.getenv('MONGODB_URL')
    MONGODB_DB_NAME: str = 'scamdb'


@lru_cache()
def get_settings() -> Settings:
    return Settings()

settings = get_settings()
