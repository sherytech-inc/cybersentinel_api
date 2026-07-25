from dataclasses import dataclass

@dataclass(frozen=True)
class DecisionWeights:
    random_forest: float = 0.40
    isolation_forest: float = 0.30
    threat_intelligence: float = 0.30
