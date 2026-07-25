import re

class QueryClassifier:
    def classify(self, user_input: str) -> str:
        text = user_input.lower()
        if re.search(r'\b(explain|alert|alerts|threat|threats)\b', text):
            return "EXPLAIN_ALERT"
        if re.search(r'\b(investigate|ip|address|score)\b', text):
            return "INVESTIGATE_IP"
        if re.search(r'\b(summary|overview|status)\b', text):
            return "THREAT_SUMMARY"
        if re.search(r'\b(report|generate)\b', text):
            return "REPORTING"
        return "GENERAL_CYBER"
