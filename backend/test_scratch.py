import sys
from pathlib import Path
backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

from datetime import datetime, timezone, timedelta
from app.models.scan import Scan
from app.db.session import local_session_factory

sess = local_session_factory()
print("1. Querying with session.query...")
scan = sess.query(Scan).filter(Scan.normalized_url == "https://direct-test.com/login").first()
print("2. Query finished. Result:", scan)
sess.close()
