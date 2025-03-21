import os

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

DATABASE_URL = "sqlite:///./network_data.db"
# DATABASE_URL = f"sqlite:///{os.path.join(os.getcwd(), 'new_network_data.db')}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
# Base = declarative_base()
# class Packet(Base):
#     __tablename__ = "packets"
#     id = Column(Integer, primary_key=True, index=True)
#     timestamp = Column(DateTime, default=datetime.utcnow)
#     src_ip = Column(String, index=True)
#     dst_ip = Column(String, index=True)
#     protocol = Column(String, index=True)

Base = declarative_base()

class Packet(Base):
    __tablename__ = "network_traffic"
    id = Column(Integer, primary_key=True, index=True)
    src_ip = Column(String, index=True)
    dst_ip = Column(String, index=True)
    src_mac = Column(String, index=True)
    dst_mac = Column(String, index=True)
    src_port = Column(Integer, index=True)
    dst_port = Column(Integer, index=True)
    protocol = Column(String, index=True)
    length = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()