from datetime import datetime, timezone
from enum import Enum
from typing import Optional, List

from pydantic import BaseModel, Field, field_validator, validator


class ProgrammingLanguage(str, Enum): 
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    SQL = "sql"
    CPP = "cpp"


class DeveloperPromptRequest(BaseModel):
    user_id : str = Field(min_length=1)
    programming_language : ProgrammingLanguage
    prompt_text : str = Field(min_length=3, max_length=5000) #condition false --> ValidationError
    context_code: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("prompt_text", mode="before")
    @classmethod
    def clean_prompt_texts(cls, value: object) -> object:
        if isinstance(value, str):
            value = value.strip()
            if not value:
                raise ValueError("prompt_text cannot be empty or whitespace only")
        return value

    
class GuardrailAssessment(BaseModel):
    is_safe : bool
    risk_score : float = Field(ge=0.0, le=1.0)
    flagged_categories : List[str] = Field(default_factory=list) #what i understand is every new object gets a new empty list
    sanitized_prompt: str | None = None

