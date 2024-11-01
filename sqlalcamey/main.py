# main.py
from .database import get_session
from .repository import BenchmarksRepository

session = get_session()
repo = BenchmarksRepository(session)

# Perform operations...
