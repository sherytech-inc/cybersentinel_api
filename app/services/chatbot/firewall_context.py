from app.repositories.repositories import FirewallActionRepository

class FirewallContext:
    async def build_context(self, db, user_input: str) -> dict:
        repo = FirewallActionRepository(db)
        blocked = await repo.get_blocked_ips()
        return {"blocked_ips": blocked[:10]}
