"""SQLAlchemy database engine and declarative base."""
from pathlib import Path
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from config.settings import DATABASE_URL

class Base(DeclarativeBase):
    pass


def make_engine(url: str = DATABASE_URL):
    if url.startswith("sqlite:///"):
        db_path = url.removeprefix("sqlite:///")
        if db_path != ":memory:":
            Path(db_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    return create_engine(url, future=True, connect_args={"check_same_thread": False} if url.startswith("sqlite") else {})

engine = make_engine()
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)

def init_db(target_engine=None) -> None:
    from database.repository import Base as _  # register models
    active_engine = target_engine or engine
    Base.metadata.create_all(active_engine)
    if active_engine.dialect.name == "sqlite":
        inspector = inspect(active_engine)
        columns = {column["name"] for column in inspector.get_columns("observations")}
        with active_engine.begin() as connection:
            if "hostname_method" not in columns:
                connection.execute(text("ALTER TABLE observations ADD COLUMN hostname_method VARCHAR(40)"))
            if "hostname_status" not in columns:
                connection.execute(text("ALTER TABLE observations ADD COLUMN hostname_status VARCHAR(24) DEFAULT 'not_attempted'"))
