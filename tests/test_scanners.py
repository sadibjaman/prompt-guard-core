import pytest
from pydantic import ValidationError

from prompt_guard.models import (
        DeveloperPromptRequest, 
        GuardrailAssessment, 
        ProgrammingLanguage,
        )


from prompt_guard.scanners import RegexSecretScanner

def test_valid_prompt_request() -> None:
    req = DeveloperPromptRequest(
        user_id="user_123",
        programming_language=ProgrammingLanguage.PYTHON,
        prompt_text= "  How do I reverse a list in Python?   "
    )

    assert req.user_id == "user_123"

    assert req.prompt_text == "How do I reverse a list in Python?"


def test_empty_prompt_raises_validation_error() -> None:
    with pytest.raises(ValidationError):
        DeveloperPromptRequest(
            user_id = "user_123123",
            programming_language=ProgrammingLanguage.CPP,
            prompt_text="  "
        )

def test_invalid_risk_score_raises_validation_error() -> None:
    with pytest.raises(ValidationError):
        GuardrailAssessment(
            is_safe=False,
            risk_score=1.5,
            flagged_categories=[]
        )


def test_clean_prompt_passes_scanner() -> None:
    req = DeveloperPromptRequest(
        user_id = "user_123",
        programming_language=ProgrammingLanguage.CPP,
        prompt_text="What is a pointer in C++?",
    )

    scanner = RegexSecretScanner()
    assessment = scanner.scan(req)

    assert assessment.is_safe == True
    assert assessment.risk_score == 0.0
    assert assessment.flagged_categories == []


def test_openai_secret_detected_in_prompt() -> None:
    req = DeveloperPromptRequest(
            user_id = "user_123",
            programming_language=ProgrammingLanguage.CPP,
            prompt_text="How to check API key is fine or not?\n" \
                        "Here is my API Key. :V" \
                        "\nsk-abcdef1234567890abcdef123456 ",
        )

    scanner = RegexSecretScanner()
    assessment = scanner.scan(req)

    assert assessment.is_safe == False
    assert assessment.risk_score == 1.0
    assert assessment.flagged_categories == ["hardcoded_secret"]

def test_aws_credentials_detected() -> None:
    req = DeveloperPromptRequest(
                user_id = "user_123",
                programming_language=ProgrammingLanguage.CPP,
                prompt_text="Here is my AWS credential. XD\nAKIA1234567890ABCDEF",
            )
    
    scanner = RegexSecretScanner()
    assessment = scanner.scan(req)
    
    assert assessment.is_safe == False
    assert assessment.risk_score == 1.0
    assert assessment.flagged_categories == ["aws_credentials"]


def test_destructive_command_detected() -> None:
    req = DeveloperPromptRequest(
                user_id = "user_123",
                programming_language=ProgrammingLanguage.CPP,
                prompt_text="rm -rf / XD\nDROP DATABASE",
            )
    scanner = RegexSecretScanner()
    assessment = scanner.scan(req)
        
    assert assessment.is_safe == False
    assert assessment.risk_score == 0.8
    assert assessment.flagged_categories == ["destructive_command"]

def test_secret_detected_in_context_code() -> None:
    req = DeveloperPromptRequest(
        user_id = "user_123",
        programming_language=ProgrammingLanguage.CPP,
        prompt_text="What is a pointer in C++?",
        context_code="AKIA1234567890ABCDEF",
    )

    scanner = RegexSecretScanner()
    assessment = scanner.scan(req)
        
    assert assessment.is_safe == False
    assert assessment.risk_score == 1.0
    assert assessment.flagged_categories == ["aws_credentials"]r