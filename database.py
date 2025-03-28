from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# Pobieranie konfiguracji z zmiennych środowiskowych
DB_HOST = os.getenv("DB_HOST", "db")
DB_PORT = os.getenv("DB_PORT", "3306")
DB_NAME = os.getenv("DB_NAME", "testdb")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "example")

DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Konfiguracja SQLAlchemy
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class CapturedPacket(Base):
    __tablename__ = "captured_packets"

    id = Column(Integer, primary_key=True, index=True)
    src_ip = Column(String(45), nullable=True)  # IPv4/IPv6 maks. długość
    dst_ip = Column(String(45), nullable=True)
    protocol = Column(String(10), nullable=True)
    timestamp = Column(DateTime, nullable=False)

# Funkcja do uzyskiwania sesji bazy danych
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()