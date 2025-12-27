from datetime import datetime, timezone
from sqlalchemy import select, delete
from db.main import get_session
from models.main import User

async def cleanup_deleted_users() -> int:
    """Find users past their deletion date and permanently delete. Returns # of users deleted"""
    print("DEBUG: cleanup_deleted_users() called")

    async with get_session() as session:
        now = datetime.now(timezone.utc)
        print(f"DEBUG: Current time (UTC): {now}")

        query = select(User).where(
            User.marked_for_deletion == True,
            User.date_for_deletion <= now
        )

        print(f"DEBUG: Executing query...")
        result = await session.execute(query)
        users_to_delete = result.scalars().all()
        print(f"DEBUG: Found {len(users_to_delete)} users to delete")

        if not users_to_delete:
            print("DEBUG: No users to delete, returning 0")
            return 0

        deleted_count = 0
        for user in users_to_delete:
            print(f"DEBUG: Deleting user {user.id} (marked_for_deletion={user.marked_for_deletion}, date_for_deletion={user.date_for_deletion})")
            await session.delete(user) #sqlalchemy automatically cascades so we js have to delete this record
            deleted_count += 1
            print(f"DEBUG: deleted_count is now {deleted_count}")

        print(f"DEBUG: About to commit, deleted_count={deleted_count}")
        await session.commit()
        print(f"DEBUG: Commit done, returning {deleted_count}")
        return deleted_count