import logging

logger = logging.getLogger("mitre_mapper")

MITRE_ATTACK_MATRIX = {
    "T1609": {
        "technique_id": "T1609",
        "name": "Execution: Container Administration Command",
        "tactic": "Execution",
        "description": "Attacker invoked interactive shell (docker exec, /bin/sh, nc) inside running container.",
        "severity": "CRITICAL"
    },
    "T1611": {
        "technique_id": "T1611",
        "name": "Privilege Escalation: Escape to Host",
        "tactic": "Privilege Escalation",
        "description": "Attacker attempted container escape via root mount tampering, nsenter, or docker.sock access.",
        "severity": "CRITICAL"
    },
    "T1496": {
        "technique_id": "T1496",
        "name": "Impact: Resource Hijacking (Cryptomining)",
        "tactic": "Impact",
        "description": "Unauthorized compute consumption by xmrig/cpuminer process spiking CPU > 85%.",
        "severity": "HIGH"
    },
    "T1041": {
        "technique_id": "T1041",
        "name": "Exfiltration: Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Unapproved outbound TCP connection transferring environment secrets to external IP.",
        "severity": "HIGH"
    },
    "T1543": {
        "technique_id": "T1543",
        "name": "Persistence: File Integrity Tampering",
        "tactic": "Persistence",
        "description": "Unauthorized executable dropped into volatile /tmp directory with SUID permissions.",
        "severity": "MEDIUM"
    }
}

def map_threat_to_mitre(threat_type: str) -> dict:
    """Maps container threat signatures to MITRE ATT&CK for Containers techniques."""
    t_lower = threat_type.lower()
    if "shell" in t_lower or "rule-101" in t_lower:
        return MITRE_ATTACK_MATRIX["T1609"]
    elif "privilege" in t_lower or "escalation" in t_lower or "rule-103" in t_lower:
        return MITRE_ATTACK_MATRIX["T1611"]
    elif "miner" in t_lower or "crypto" in t_lower or "rule-102" in t_lower:
        return MITRE_ATTACK_MATRIX["T1496"]
    elif "exfil" in t_lower or "outbound" in t_lower or "rule-104" in t_lower:
        return MITRE_ATTACK_MATRIX["T1041"]
    else:
        return MITRE_ATTACK_MATRIX["T1543"]
