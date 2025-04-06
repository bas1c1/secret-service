from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime
from app.config import settings

engine = create_engine(settings.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


class SecretLog(Base):
    """Схема для логирования операций над секретами."""

    __tablename__ = "secret_logs"

    id = Column(Integer, primary_key=True, index=True)
    secret_key = Column(String, index=True)
    action = Column(String)  # create, read, delete
    ip_address = Column(String)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    ttl_seconds = Column(Integer, nullable=True)
    has_passphrase = Column(Boolean, default=False)
    log_metadata = Column(Text, nullable=True)


class Secret(Base):
    """Модель для хранения зашифрованных секретов."""

    __tablename__ = "secrets"

    id = Column(Integer, primary_key=True, index=True)
    secret_key = Column(String, unique=True, index=True)
    encrypted_data = Column(Text)
    iv = Column(String)  # Инициализация вектора для шифрования
    passphrase_hash = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime)
    is_accessed = Column(Boolean, default=False)
    is_deleted = Column(Boolean, default=False)

def create_tables():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
