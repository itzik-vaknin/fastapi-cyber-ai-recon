import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Database configuration URL
DATABASE_URL = "sqlite:///./recon.db"

# Engine setup
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Session manager setup
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Declarative Base for models
Base = declarative_base()

class ScanResult(Base):
    """
    SQLAlchemy Database model for structured history logs.
    """
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, index=True)
    resolved_ip = Column(String)
    open_ports = Column(String)  # Stored as comma-separated string
    ai_report = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

def init_db():
    """
    Initializes database tables on application launch.
    """
    Base.metadata.create_create_all(bind=engine)

def get_db():
    """
    Dependency generator function to yield unique thread-safe database sessions.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
