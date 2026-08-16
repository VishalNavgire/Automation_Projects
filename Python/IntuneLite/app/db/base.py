'''
In SQLAlchemy 2.0, every ORM class (like User or ManagedDevice) must inherit from a single parent class so that SQLAlchemy can register, track, 
and manage all database models in a central registry called metadata. base.py defines this single parent class (Base).

DeclarativeBase: This is SQLAlchemy 2.0’s core foundation class. It contains an internal dictionary called Base.metadata.tables.
When User and ManagedDevice inherit from Base, SQLAlchemy automatically reads their __tablename__ and column definitions and registers them inside Base.metadata.
This allows us to trigger table creation across the entire application with a single command: Base.metadata.create_all(bind=engine).

'''
# Define SQL database tables using SQLAlchemy 2.0 ORM models.
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base catalog class that registers all ORM models for table creation."""
    # pass