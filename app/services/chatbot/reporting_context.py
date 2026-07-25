class ReportingContext:
    async def build_context(self, db, user_input: str) -> dict:
        try:
            result = (
                await db.table("report_snapshots")
                .select("*")
                .order("generated_at", desc=True)
                .limit(5)
                .execute()
            )
            reports = result.data or []
        except Exception:
            reports = []
        return {"recent_reports": reports}
