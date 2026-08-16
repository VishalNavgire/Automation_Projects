'''
app/db/session.py — Configures the SQLAlchemy database connection engine and the request session generator (get_db).

'''
from collections.abc import Generator

from app.core.config import settings
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

# Create SQLite Engine
'''
connect_args={"check_same_thread": False} is required strictly for SQLite in multi-threaded Python/FastAPI apps.

connect_args={"check_same_thread": False}: By default, SQLite restricts connections to the single thread that opened them. 
FastAPI uses multi-threading to handle asynchronous HTTP requests concurrently, so disabling this single-thread constraint allows different threads in FastAPI to query SQLite safely.
'''
engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False  # Set to True if you want to print raw SQL queries during debugging / Controls whether SQLAlchemy prints SQL statements to the console.
)

# Create SessionLocal Factory
'''
autocommit=False: Prevents automatic saving. Changes are explicitly committed via db.commit(), ensuring atomic transactions.
autoflush=False: Prevents SQLAlchemy from prematurely pushing memory changes to disk before explicitly requested.
'''
SessionLocal = sessionmaker(autocommit=False, 
                            autoflush=False, 
                            bind=engine)


'''
This function creates a database session and makes it available to your API endpoint.

get_db(): A generator function providing dependency injection for FastAPI. It instantiates db = SessionLocal(), yields the active database connection to the API endpoint, 
and guarantees db.close() runs in the finally: block after the response finishes.

Generator[Session, None, None]

Think of it as:
Generator[
    What it produces,
    What it can receive,
    What it returns when finished
]
"This 'get_db()' function is a generator that yields Session objects, doesn't expect values to be sent into it, and doesn't return a meaningful value when it finishes."
'''
def get_db() -> Generator[Session, None, None]:
    """Provides a transactional database session per HTTP request."""
    db = SessionLocal()
    try:
        yield db #Here is the database session. Use it. When you're finished, come back here and I'll clean it up."
    finally:
        db.close()