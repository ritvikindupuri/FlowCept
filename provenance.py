import hmac
import hashlib

# Pre-registered trusted author public key fingerprints
TRUSTED_AUTHORS = {
    "official-agent-registry": "key_sig_trusted_master_001",
    "verified-enterprise-dev": "key_sig_enterprise_002"
}

def verify_skill_provenance(skill_name: str, code_body: str, author_id: str, signature: str) -> dict:
    """Performs Layer 3 Cryptographic Provenance & Supply Chain verification."""
    if not author_id or not signature:
        return {
            "verified": False,
            "status": "UNSIGNED",
            "risk_score": 15.0,
            "details": "Skill definition lacks a cryptographic author signature (Unsigned Supply Chain Origin)."
        }

    if author_id not in TRUSTED_AUTHORS:
        return {
            "verified": False,
            "status": "UNTRUSTED_AUTHOR",
            "risk_score": 25.0,
            "details": f"Author ID '{author_id}' is not in the trusted registry database."
        }

    # Verify HMAC-SHA256 signature against key
    secret_key = TRUSTED_AUTHORS[author_id].encode('utf-8')
    payload = f"{skill_name}:{code_body}".encode('utf-8')
    expected_sig = hmac.new(secret_key, payload, hashlib.sha256).hexdigest()

    if hmac.compare_digest(signature, expected_sig):
        return {
            "verified": True,
            "status": "VERIFIED_VALID",
            "risk_score": 0.0,
            "details": f"Cryptographic signature verified for trusted author '{author_id}'."
        }
    else:
        return {
            "verified": False,
            "status": "SIGNATURE_MISMATCH",
            "risk_score": 85.0,
            "details": "CRITICAL: Cryptographic signature mismatch. The skill content has been tampered with post-signing!"
        }
