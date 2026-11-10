"""irreversibility-guard — intercept an agent's irreversible tool actions.

Submission to the Drawerrr challenge "Prevent irreversible AI autonomous actions".
"""
from .classifier import (
    IRREVERSIBLE,
    REVERSIBLE,
    UNKNOWN,
    Classification,
    Classifier,
    ManifestEntry,
    default_classifier,
)
from .core import Action, Decision, Verdict
from .policy import Dial, Guard, Policy, Session

__all__ = [
    "Action", "Decision", "Verdict",
    "Classifier", "Classification", "ManifestEntry", "default_classifier",
    "REVERSIBLE", "IRREVERSIBLE", "UNKNOWN",
    "Guard", "Policy", "Session", "Dial",
]
__version__ = "0.1.0"
GUARD_REV = "0.1.0"
