import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import asyncio
from app.db.base import Base
from app.models.user import User
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

eng = create_engine("sqlite:///:memory:")
Base.metadata.create_all(eng)
s = Session(eng)

class AsyncSessionFallback:
    def __init__(self, s):
        self._s = s
    async def execute(self, stmt):
        return self._s.execute(stmt)
    def add(self, x):
        self._s.add(x)
    async def commit(self):
        self._s.commit()
    async def refresh(self, x):
        self._s.refresh(x)
    async def close(self):
        self._s.close()
    async def rollback(self):
        self._s.rollback()

async def test():
    asess = AsyncSessionFallback(s)
    u = User(email="subhra@gmail.com", hashed_password="hash", full_name="Subhra", role="user", is_active=True)
    asess.add(u)
    await asess.commit()
    await asess.refresh(u)
    res = await asess.execute(select(User).where(User.email == "subhra@gmail.com"))
    found = res.scalar_one_or_none()
    print("SUCCESS: FOUND USER:", found.email, found.full_name, str(found.id))

asyncio.run(test())
