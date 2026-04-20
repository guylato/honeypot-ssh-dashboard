from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship

from app.database import Base


class SessionAttack(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    ip_source = Column(String, index=True, nullable=False)
    username = Column(String, nullable=True)
    password = Column(String, nullable=True)
    success = Column(Boolean, default=False, nullable=False)
    threat_score = Column(Integer, default=0, nullable=False)

    commands = relationship(
        "CommandLog",
        back_populates="session",
        cascade="all, delete-orphan"
    )


class CommandLog(Base):
    __tablename__ = "commands"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=False)
    command = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

    session = relationship("SessionAttack", back_populates="commands")


class WebEvent(Base):
    __tablename__ = "web_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    ip_source = Column(String, index=True, nullable=False)
    method = Column(String, nullable=False)
    path = Column(String, nullable=False)
    user_agent = Column(String, nullable=True)
    username = Column(String, nullable=True)
    password = Column(String, nullable=True)
    payload = Column(String, nullable=True)
    threat_score = Column(Integer, default=0, nullable=False)
    threat_label = Column(String, nullable=True)
    attack_type = Column(String, nullable=True)