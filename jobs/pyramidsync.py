import asyncio
import logging
import os

import httpx
from pyairtable import Api
from pyairtable.formulas import match
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from db.main import get_session
from models.main import User

logger = logging.getLogger(__name__)


async def sync_users_to_airtable():
    """Push user data to Pyramid Scheme Airtable table"""
    table_id = os.getenv("AIRTABLE_PYRAMID_TABLE_ID")
    api_key = os.getenv("AIRTABLE_API_KEY")
    base_id = os.getenv("AIRTABLE_BASE_ID")
    if not all([table_id, api_key, base_id]):
        return

    api = Api(api_key)
    table = api.table(base_id, table_id)

    # Fetch all users with their projects
    async with get_session() as session:
        users = (await session.execute(
            select(User).options(selectinload(User.projects))
        )).scalars().all()

        async with httpx.AsyncClient(timeout=10) as client:
            for user in users:
                idv = "error"
                try:
                    resp = await client.get(
                        "https://auth.hackclub.com/api/external/check",
                        params={"email": user.email},
                    )
                    if resp.status_code == 200:
                        idv = resp.json().get("result", "error")
                except Exception:
                    pass

                record = {
                    "Email": user.email,
                    "Hours": round(sum(p.hackatime_total_hours for p in user.projects), 2),
                    "Projects Shipped": sum(1 for p in user.projects if p.shipped),
                    "IDV Status": idv,
                }

                try:
                    def upsert_record(r):
                        existing = table.first(formula=match({"Email": r["Email"]}))
                        if existing:
                            table.update(existing["id"], r)
                        else:
                            table.create(r)

                    await asyncio.to_thread(lambda r=record: upsert_record(r))
                except Exception:
                    logger.exception("Airtable sync failed for %s", user.email)
