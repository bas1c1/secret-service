from app.models.database import Secret, SecretLog
from app.services.encryption_service import EncryptionService
from sqlalchemy.orm import Session
import uuid
import datetime
from typing import Optional
import json
from fastapi import HTTPException, status


class SecretService:
    """Небольшой сервис управления секретами."""

    def __init__(self, db: Session):
        self.db = db
        self.encryption_service = EncryptionService()

    def create_secret(self, secret_data: str, passphrase: Optional[str] = None, ttl_seconds: Optional[int] = None, ip_address: str = None) -> str:
        """Генериурет новый секрет и возвращает его ключ."""
        from app.config import settings

        # Генерация уникального ключа
        secret_key = str(uuid.uuid4())

        # Установка TTL
        if ttl_seconds is None:
            ttl_seconds = settings.DEFAULT_TTL_SECONDS
        else:
            ttl_seconds = max(ttl_seconds, settings.CACHE_MIN_TTL_SECONDS)

        # Рассчитывание времени истечения срока
        expires_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=ttl_seconds)

        encrypted_data, iv = self.encryption_service.encrypt(secret_data, passphrase)

        passphrase_hash = None
        if passphrase:
            passphrase_hash = self.encryption_service.hash_passphrase(passphrase)

        # Объект секрета
        secret = Secret(
            secret_key=secret_key,
            encrypted_data=encrypted_data,
            iv=iv,
            passphrase_hash=passphrase_hash,
            expires_at=expires_at,
            is_accessed=False,
            is_deleted=False
        )

        self.db.add(secret)
        self.db.commit()

        # Логирование создания секрета
        self._log_action(
            secret_key=secret_key,
            action="create",
            ip_address=ip_address,
            ttl_seconds=ttl_seconds,
            has_passphrase=bool(passphrase),
            metadata=json.dumps({"expires_at": expires_at.isoformat()})
        )

        return secret_key

    def get_secret(self, secret_key: str, ip_address: str = None) -> Optional[str]:
        """Получает секрет по ключу. Возвращает None если секрет не найден или уже использован."""
        # Поиск секрета
        secret = self.db.query(Secret).filter(
            Secret.secret_key == secret_key,
            Secret.is_accessed == False,
            Secret.is_deleted == False,
            Secret.expires_at > datetime.datetime.utcnow()
        ).first()

        if not secret:
            self._log_action(
                secret_key=secret_key,
                action="read_failed",
                ip_address=ip_address,
                metadata=json.dumps({"reason": "not_found_or_expired_or_accessed"})
            )
            return None

        # Дешифровка секрета
        try:
            decrypted_data = self.encryption_service.decrypt(
                secret.encrypted_data,
                secret.iv
            )

            secret.is_accessed = True
            self.db.commit()

            # Логирование доступа
            self._log_action(
                secret_key=secret_key,
                action="read",
                ip_address=ip_address
            )

            return decrypted_data

        except Exception as e:
            self._log_action(
                secret_key=secret_key,
                action="read_failed",
                ip_address=ip_address,
                metadata=json.dumps({"reason": str(e)})
            )
            return None

    def delete_secret(self, secret_key: str, passphrase: Optional[str] = None, ip_address: str = None) -> bool:
        """Удаляет секрет по ключу. При успехе возвращает True."""
        # Поиск секрета
        secret = self.db.query(Secret).filter(
            Secret.secret_key == secret_key,
            Secret.is_deleted == False,
            Secret.expires_at > datetime.datetime.utcnow()
        ).first()

        if not secret:
            self._log_action(
                secret_key=secret_key,
                action="delete_failed",
                ip_address=ip_address,
                metadata=json.dumps({"reason": "not_found_or_expired"})
            )
            return False

        # Проверка на необходимость ключ-фразы
        if secret.passphrase_hash:
            if not passphrase:
                self._log_action(
                    secret_key=secret_key,
                    action="delete_failed",
                    ip_address=ip_address,
                    metadata=json.dumps({"reason": "passphrase_required"})
                )
                return False

            passphrase_hash = self.encryption_service.hash_passphrase(passphrase)
            if passphrase_hash != secret.passphrase_hash:
                self._log_action(
                    secret_key=secret_key,
                    action="delete_failed",
                    ip_address=ip_address,
                    metadata=json.dumps({"reason": "invalid_passphrase"})
                )
                return False

        secret.is_deleted = True
        self.db.commit()

        # Логирование удаления.
        self._log_action(
            secret_key=secret_key,
            action="delete",
            ip_address=ip_address,
            has_passphrase=bool(passphrase)
        )

        return True

    def _log_action(self, secret_key: str, action: str, ip_address: str = None, ttl_seconds: Optional[int] = None, has_passphrase: bool = False, metadata: Optional[str] = None) -> None:
        """Логирование действия над секретом."""
        log = SecretLog(
            secret_key=secret_key,
            action=action,
            ip_address=ip_address,
            ttl_seconds=ttl_seconds,
            has_passphrase=has_passphrase,
            log_metadata=metadata  # Updated to use log_metadata instead of metadata
        )
        self.db.add(log)
        self.db.commit()
