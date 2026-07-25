from app.services.chatbot.query_classifier import QueryClassifier

class RAGService:
    def is_generic_query(self, user_input: str) -> bool:
        intent = QueryClassifier().classify(user_input)
        return intent == "GENERAL_CYBER"
