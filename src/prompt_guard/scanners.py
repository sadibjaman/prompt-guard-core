import re
from abc import ABC, abstractmethod

from prompt_guard.models import DeveloperPromptRequest, GuardrailAssessment


class BaseScanner(ABC):
    """Abstract interface that all guardrail scanners must implement."""

    @abstractmethod
    def scan(self, request: DeveloperPromptRequest) -> GuardrailAssessment:
        """Scan a developer prompt request and return a structured assessment."""
        pass


class RegexSecretScanner(BaseScanner):
    """Rule-based scanner that detects leaked API keys and destructive commands."""

    # Class-level dictionaries mapping category names to compiled regex patterns
    SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
        # OpenAI-style keys like sk-proj-... or sk-abcde123123...
        "hardcoded_secret": re.compile(r"sk-[a-zA-Z0-9_-]{20,}"),
        # Matches AWS Access Key IDs (starts with AKIA followed by 16 alphanumeric chars)
        "aws_credentials": re.compile(r"AKIA[0-9A-Z]{16}"),
    }

    DESTRUCTIVE_PATTERNS: dict[str, re.Pattern[str]] = {
        # Matches rm -rf, DROP DATABASE, or DROP TABLE (case-insensitive)
        "destructive_command": re.compile(
            r"(rm\s+-rf\s+/|DROP\s+(DATABASE|TABLE))", re.IGNORECASE
        ),
    }

    def scan(self, request: DeveloperPromptRequest) -> GuardrailAssessment:

        flagged: list[str] = []
        risk_score: float = 0.0
        full_text: str = request.prompt_text
        is_safe: bool

        if request.context_code is not None:
            full_text = f"{full_text}\n{request.context_code}"

        for category, pattern in self.SECRET_PATTERNS.items():
            if pattern.search(full_text):
                flagged.append(category)
                risk_score = 1.0

        for category, pattern in self.DESTRUCTIVE_PATTERNS.items():
            if pattern.search(full_text):
                flagged.append(category)
                risk_score = max(risk_score, 0.8)

        is_safe: bool = len(flagged) == 0

        return GuardrailAssessment(
            is_safe=is_safe, risk_score=risk_score, flagged_categories=flagged
        )
