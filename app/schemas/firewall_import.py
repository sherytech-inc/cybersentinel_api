from typing import Literal, List
from pydantic import BaseModel, Field

class RejectedFirewallLine(BaseModel):
    line: int
    content: str
    reason: str

class FirewallImportResponse(BaseModel):
    format: Literal["ufw", "windows_firewall"]
    imported: int
    rejected: int
    rejected_details: List[RejectedFirewallLine]
    warnings: List[str] = Field(default_factory=list)

class FirewallImportErrorResponse(BaseModel):
    status: Literal[
        "empty_file",
        "unsupported_format",
        "no_parseable_entries",
        "file_too_large",
        "unavailable",
        "unsupported_encoding",
        "duplicate_import",
    ]
    message: str
