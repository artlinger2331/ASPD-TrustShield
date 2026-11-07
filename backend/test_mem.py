import sys
print("Line 1 ok")
from pathlib import Path
print("Line 2 ok")
sys.path.insert(0, str(Path(__file__).parent))
print("Line 3 ok")
from app.db.base import Base
print("Line 4 ok")
from app.models.user import User
print("Line 5 ok")
from sqlalchemy import create_engine, select
print("Line 6 ok")
from sqlalchemy.orm import Session
print("Line 7 ok")
eng = create_engine("sqlite:///:memory:")
print("Line 8 ok")
Base.metadata.create_all(eng)
print("Line 9 ok")
s = Session(eng)
print("Line 10 ok")
u = User(email="subhra@gmail.com", hashed_password="hash", full_name="Subhra", role="user", is_active=True)
print("Line 11 ok")
s.add(u)
print("Line 12 ok")
s.commit()
print("Line 13 ok")
s.refresh(u)
print("Line 14 ok")
print("FOUND USER:", u.email, u.full_name, str(u.id))
