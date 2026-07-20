import ast
import re
import unicodedata

# Dangerous Python functions & module imports for AST inspection
DISALLOWED_AST_NODES = {
    "eval", "exec", "__import__", "compile", 
    "subprocess", "os.system", "os.popen", "shutil.rmtree",
    "socket", "pty", "ctypes"
}

# Regex compiled patterns for data leaks and obfuscation
CREDENTIAL_PATTERNS = {
    "openai_key": (re.compile(r'\bsk-(?:proj-)?[a-zA-Z0-9_-]{40,60}\b'), "OpenAI API Key Leak"),
    "aws_key": (re.compile(r'\b(AKIA|ASCA|AGPA|AIDA)[A-Z0-9]{16}\b'), "AWS Access Key ID Leak"),
    "google_key": (re.compile(r'\bAIzaSy[a-zA-Z0-9_-]{33}\b'), "Google Cloud API Key Leak"),
    "base64_dropper": (re.compile(r'base64\.b64decode\s*\('), "Base64 Execution Dropper"),
    "rot13_obfuscation": (re.compile(r"codecs\.decode\s*\([^)]*['\"]rot13['\"]"), "ROT13 Code Obfuscation")
}

# Zero-width / invisible steganography characters
ZERO_WIDTH_CHARS = {'\u200b', '\u200c', '\u200d', '\ufeff', '\u200e', '\u200f'}

def analyze_rules_and_ast(code_str: str, text_metadata: str) -> dict:
    """Performs Layer 1 deterministic static analysis on code body and text fields."""
    findings = []
    severity_score = 0.0

    # 1. Steganography & Zero-Width Character Detection
    found_zero_width = [c for c in text_metadata + code_str if c in ZERO_WIDTH_CHARS]
    if found_zero_width:
        severity_score += 40.0
        findings.append({
            "rule": "Steganographic Zero-Width Space Injection",
            "severity": "HIGH",
            "details": f"Detected {len(found_zero_width)} hidden zero-width unicode characters designed to bypass pattern filters."
        })

    # 2. Regex Pattern & Credential Leaks
    combined_content = f"{text_metadata}\n{code_str}"
    for rule_id, (pattern, rule_name) in CREDENTIAL_PATTERNS.items():
        matches = pattern.findall(combined_content)
        if matches:
            severity_score += 35.0
            findings.append({
                "rule": rule_name,
                "severity": "HIGH",
                "details": f"Matched pattern '{rule_name}' with {len(matches)} occurrences."
            })

    # 3. Python AST Parsing for Dangerous Operations
    if code_str and code_str.strip():
        try:
            tree = ast.parse(code_str)
            for node in ast.walk(tree):
                # Check call nodes (e.g. eval(), exec(), os.system())
                if isinstance(node, ast.Call):
                    func_name = ""
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        func_name = f"{getattr(node.func.value, 'id', '')}.{node.func.attr}"

                    for disallowed in DISALLOWED_AST_NODES:
                        if disallowed in func_name:
                            severity_score += 45.0
                            findings.append({
                                "rule": f"Dangerous Call: {func_name}",
                                "severity": "CRITICAL",
                                "details": f"AST parser identified unauthorized function invocation '{func_name}'."
                            })

                # Check import nodes (e.g. import subprocess, import socket)
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in DISALLOWED_AST_NODES:
                            severity_score += 30.0
                            findings.append({
                                "rule": f"Disallowed Module Import: {alias.name}",
                                "severity": "MEDIUM",
                                "details": f"Skill attempts to import system execution module '{alias.name}'."
                            })
                elif isinstance(node, ast.ImportFrom):
                    if node.module in DISALLOWED_AST_NODES:
                        severity_score += 30.0
                        findings.append({
                            "rule": f"Disallowed Module Import: {node.module}",
                            "severity": "MEDIUM",
                            "details": f"Skill attempts to import from system module '{node.module}'."
                        })
        except SyntaxError as e:
            # Code does not compile cleanly
            findings.append({
                "rule": "Syntax Analysis Failure",
                "severity": "LOW",
                "details": f"Code body contains invalid Python syntax: {e.msg}"
            })
        except Exception as e:
            pass

    return {
        "severity_score": min(severity_score, 100.0),
        "findings": findings
    }
