from pydantic import BaseModel
from typing import Any
from datetime import datetime

class ChatRequest(BaseModel):
    session_id: str
    message: str

class ChatResponse(BaseModel):
    session_id: str
    intent: str
    response: str
    context_used: dict[str, Any]
    timestamp: datetime
