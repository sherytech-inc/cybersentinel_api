import re
from app.repositories.repositories import IPIntelligenceRepository

class IntelligenceContext:
    async def build_context(self, db, user_input: str) -> dict:
        repo = IPIntelligenceRepository(db)
        match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', user_input)
        if match:
            ip = match.group(0)
            data = await repo.get_by_ip(ip)
            if data:
                return {"ip_intelligence": data}
        return {"ip_intelligence": "No specific IP found in query or no data available."}
