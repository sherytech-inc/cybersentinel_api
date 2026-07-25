from datetime import datetime
from typing import Optional

class AlertFilters:
    """Helper class to build repository filters and clean up parameters."""
    @staticmethod
    def sanitize_history_params(
        severity: Optional[str] = None,
        status: Optional[str] = None,
        ip: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> dict:
        """Parses and sanitizes input params for query filtering."""
        filters = {}
        if severity:
            filters["severity"] = severity.upper()
        if status:
            filters["status"] = status.upper()
        if ip:
            filters["source_ip"] = ip
            
        parsed_start = None
        parsed_end = None
        if start_date:
            try:
                parsed_start = datetime.fromisoformat(start_date)
            except ValueError:
                pass
        if end_date:
            try:
                parsed_end = datetime.fromisoformat(end_date)
            except ValueError:
                pass

        return {
            "filters": filters,
            "start_date": parsed_start,
            "end_date": parsed_end
        }
