from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings."""

    # Поля API
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Secret Service"

    # Поля для базы данных
    POSTGRES_HOST: str
    POSTGRES_PORT: str
    POSTGRES_DB: str
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str

    # Поля безопасности
    SECRET_KEY: str
    ALGORITHM: str = "AES-GCM"

    # Настройки кеширования
    CACHE_MIN_TTL_SECONDS: int = 300  # 5 минут минимально
    DEFAULT_TTL_SECONDS: int = 86400  # 24 часа, дефолтная настройка TTL

    @property
    def DATABASE_URL(self) -> str:
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"


settings = Settings()
