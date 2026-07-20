import re

INJECTION_PATTERNS = [
    (re.compile(r'\bignore\s+previous\s+instructions\b', re.IGNORECASE), "System Instruction Override"),
    (re.compile(r'\bsystem\s*:\s*override\b', re.IGNORECASE), "System Override Delimiter"),
    (re.compile(r'\byou\s+are\s+now\s+(?:an?\s+)?unrestricted\b', re.IGNORECASE), "Jailbreak Persona Injection"),
    (re.compile(r'\bforget\s+all\s+(?:safety\s+)?rules\b', re.IGNORECASE), "Safety Boundary Erasure"),
    (re.compile(r'</?system(?:_prompt)?>', re.IGNORECASE), "System Tag XML Escape"),
    (re.compile(r'<\|(?:im_start|im_end|endoftext)\|>', re.IGNORECASE), "Special Token Context Escape"),
    (re.compile(r'```system', re.IGNORECASE), "Markdown Context Hijack"),
    (re.compile(r'\bdeveloper\s+mode\s+enabled\b', re.IGNORECASE), "Developer Mode Jailbreak")
]

def scan_and_sanitize_prompt_injection(text: str) -> dict:
    """Performs Layer 2 indirect prompt injection detection and text sanitization."""
    if not text:
        return {"risk_score": 0.0, "triggers": [], "sanitized_text": ""}

    triggers = []
    risk_score = 0.0
    sanitized_text = text

    for pattern, label in INJECTION_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            risk_score += 35.0
            triggers.append({
                "vector": label,
                "count": len(matches),
                "matched_sample": matches[0][:40]
            })
            # Sanitize match inline by replacing with [REDACTED_INJECTION_VECTOR]
            sanitized_text = pattern.sub("[REDACTED_PROMPT_INJECTION]", sanitized_text)

    # Normalize unicode to prevent homoglyph evasion
    import unicodedata
    normalized_text = unicodedata.normalize("NFKD", sanitized_text)

    return {
        "risk_score": min(risk_score, 100.0),
        "triggers": triggers,
        "sanitized_text": normalized_text
    }
