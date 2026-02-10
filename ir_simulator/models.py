from dataclasses import dataclass
from enum import Enum
from typing import List


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Incident:
    title: str
    severity: Severity
    evidence: List[str]
    explanation: str
    recommended_actions: List[str]

    from dataclasses import dataclass


@dataclass
class TimelineEvent:
    timestamp: int
    description: str
    significance: str
