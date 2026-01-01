import asyncio
import logging
import os

import httpx
from pyairtable import Api
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from db.main import get_session
from models.main import User

logger = logging.getLogger(__name__)


async def sync_users_to_airtable():
    """Push user data to Pyramid Scheme Airtable table"""
    table_id = os.getenv("AIRTABLE_PYRAMID_TABLE_ID")
    if not table_id:
        return

    api = Api(os.environ["AIRTABLE_API_KEY"])
    table = api.table(os.environ["AIRTABLE_BASE_ID"], table_id)

    # Fetch all users with their projects
    async with get_session() as session:
        users = (await session.execute(
            select(User).options(selectinload(User.projects))
        )).scalars().all()

        for user in users:
            idv = "error"
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.get(
                        "https://auth.hackclub.com/api/external/check",
                        params={"email": user.email},
                        timeout=10,
                    )
                    if resp.status_code == 200:
                        idv = resp.json().get("result", "error")
            except Exception:
                pass

            # Build the record for Airtable
            record = {
                "Email": user.email,
                "Username": user.username or "",
                "Hours": round(sum(p.hackatime_total_hours for p in user.projects), 2),
                "Projects Shipped": sum(1 for p in user.projects if p.shipped),
                "IDV Status": idv,
                "Referral Code": user.referral_code_used or "",
            }

            try:
                await asyncio.to_thread(lambda r=record: table.create(r))
            except Exception:
                logger.exception("Airtable sync failed for %s", user.email)