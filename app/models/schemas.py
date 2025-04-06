from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class SecretCreate(BaseModel):
    """Схема для создания нового секрета."""

    secret: str = Field(
        ...,
        description="Конфиденциальные данные должны храниться в надёжном месте.",
        example="my_super_secret_password"
    )
    passphrase: Optional[str] = Field(
        None,
        description="Кодовая фраза для доп. защиты (требуется для удаления).",
        example="secure_passphrase"
    )
    ttl_seconds: Optional[int] = Field(
        None,
        description="Время жизни (Time-to-live) в секундах (минимум 300 секунд, по умолчанию 86400)",
        example=3600,
        ge=300
    )

    class Config:
        schema_extra = {
            "example": {
                "secret": "my_super_secret_password",
                "passphrase": "secure_passphrase",
                "ttl_seconds": 3600
            }
        }


class SecretResponse(BaseModel):
    """Схема для ответа о создании секрета."""

    secret_key: str = Field(
        ...,
        description="Уникальный идентификатор для получения секрета.",
        example="550e8400-e29b-41d4-a716-446655440000"
    )

    class Config:
        schema_extra = {
            "example": {
                "secret_key": "550e8400-e29b-41d4-a716-446655440000"
            }
        }


class SecretData(BaseModel):
    """Схема для получения данных секрета."""

    secret: str = Field(
        ...,
        description="Полученные данные секрета.",
        example="my_super_secret_password"
    )

    class Config:
        schema_extra = {
            "example": {
                "secret": "my_super_secret_password"
            }
        }


class SecretDeleteResponse(BaseModel):
    """Схема для просмотра статуса удаления секрета."""

    status: str = Field(
        ...,
        description="Статус операции удаления.",
        example="secret_deleted"
    )

    class Config:
        schema_extra = {
            "example": {
                "status": "secret_deleted"
            }
        }


class ErrorResponse(BaseModel):
    """Схема для описания деталей ошибок."""

    detail: str = Field(
        ...,
        description="Детали ошибки.",
        example="Secret not found or already accessed"
    )

    class Config:
        schema_extra = {
            "example": {
                "detail": "Secret not found or already accessed"
            }
        }


class SecretLogCreate(BaseModel):
    """Схема для создания записи в логах."""

    secret_key: str
    action: str
    ip_address: str
    ttl_seconds: Optional[int] = None
    has_passphrase: bool = False
    log_metadata: Optional[str] = None  # Updated to use log_metadata instead of metadata


class SecretLogResponse(BaseModel):
    """Схема для ответа на запись в логах."""

    id: int
    secret_key: str
    action: str
    timestamp: datetime

    class Config:
        orm_mode = True
