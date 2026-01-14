from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.sql import func
from database import Base  # <--- Changed from .database to database

class Device(Base):
    __tablename__ = "devices"
    id = Column(String, primary_key=True, index=True)
    name = Column(String)
    user = Column(String)
    ip = Column(String)
    status = Column(String)
    risk = Column(Integer)
    os = Column(String)
    cpu_usage = Column(String)
    ram_usage = Column(String)
    last_seen = Column(DateTime(timezone=True), server_default=func.now())

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    severity = Column(String)
    description = Column(String)
    source_device_id = Column(String)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

class Command(Base):
    __tablename__ = "commands"
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, index=True)
    type = Column(String) # "deep_scan", "isolate"
    status = Column(String) # "pending", "processing", "completed"
    result = Column(Text) # JSON Report string
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Log(Base):
    __tablename__ = "logs"
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String)
    event = Column(String)
    details = Column(String)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())