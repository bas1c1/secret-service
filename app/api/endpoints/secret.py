from fastapi import APIRouter, Depends, HTTPException, Request, status, Response
from sqlalchemy.orm import Session
from app.models.database import get_db
from app.models.schemas import SecretCreate, SecretResponse, SecretData, SecretDeleteResponse
from app.services.secret_service import SecretService
from typing import Optional

router = APIRouter()


def get_client_ip(request: Request) -> str:
    """Получение клиентского IP с запроса."""
    if "x-forwarded-for" in request.headers:
        return request.headers["x-forwarded-for"]
    return request.client.host if request.client else "unknown"


def set_no_cache_headers(response: Response) -> None:
    """Заголовки для предотвращения кеширования."""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"


@router.post("/", response_model=SecretResponse, status_code=status.HTTP_201_CREATED)
async def create_secret(
    secret_data: SecretCreate,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Создание нового секрета

    - **secret**: Конфеденциальные данные
    - **passphrase**: Опциональное: ключ для доп. защиты
    - **ttl_seconds**: Опциональное: время жизни в секундах
    """
    set_no_cache_headers(response)

    service = SecretService(db)
    ip_address = get_client_ip(request)

    secret_key = service.create_secret(
        secret_data=secret_data.secret,
        passphrase=secret_data.passphrase,
        ttl_seconds=secret_data.ttl_seconds,
        ip_address=ip_address
    )

    return {"secret_key": secret_key}


@router.get("/{secret_key}", response_model=SecretData)
async def get_secret(
    secret_key: str,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Получение секрета по ключу. Секрет нельзя получить повторно.
    """
    set_no_cache_headers(response)

    service = SecretService(db)
    ip_address = get_client_ip(request)

    secret = service.get_secret(secret_key=secret_key, ip_address=ip_address)

    if not secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found or already accessed"
        )

    return {"secret": secret}


@router.delete("/{secret_key}", response_model=SecretDeleteResponse)
async def delete_secret(
    secret_key: str,
    request: Request,
    response: Response,
    passphrase: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Удаление секрета по ключу. Если он был создан с паролем, то его нужно указать.
    """
    set_no_cache_headers(response)

    service = SecretService(db)
    ip_address = get_client_ip(request)

    success = service.delete_secret(
        secret_key=secret_key,
        passphrase=passphrase,
        ip_address=ip_address
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to delete secret. It may not exist, be expired, or require a valid passphrase."
        )

    return {"status": "secret_deleted"}
