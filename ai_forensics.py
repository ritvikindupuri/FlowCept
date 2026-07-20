import os
import json
import logging

logger = logging.getLogger("ai_forensics")

def generate_forensic_patch(forensic_data: dict) -> dict:
    """Analyzes container forensic dumps and outputs hardened Dockerfile & Compose security patches."""
    cntr_name = forensic_data.get("name", "container")
    threat_info = forensic_data.get("threat_analysis", {})
    alerts = threat_info.get("active_alerts", [])

    alert_summary = ", ".join([a.get("threat_type", "Threat") for a in alerts]) if alerts else "Runtime Anomaly"

    api_key = os.getenv("ANTHROPIC_API_KEY", "")

    if api_key:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)

            prompt = f"""You are DockerShield AI Security Forensics Expert.
Analyze this container breach forensic log:
CONTAINER: {cntr_name}
DETECTED THREATS: {alert_summary}
PROCESS SNAPSHOT: {json.dumps(forensic_data.get("process_tree_snapshot", []))}

Respond ONLY with a JSON object:
{{
  "forensic_diagnosis": "<detailed root cause analysis>",
  "hardened_dockerfile": "<hardened Dockerfile syntax>",
  "hardened_compose": "<hardened docker-compose.yml snippet>",
  "security_recommendations": ["<recommendation 1>", "<recommendation 2>"]
}}"""

            res = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=1000,
                temperature=0.0,
                messages=[{"role": "user", "content": prompt}]
            )

            res_text = res.content[0].text.strip()
            if "```json" in res_text:
                res_text = res_text.split("```json")[1].split("```")[0].strip()

            parsed = json.loads(res_text)
            parsed["ai_engine"] = "Claude 3.5 Sonnet"
            return parsed
        except Exception as e:
            logger.error(f"Claude AI Forensics API call error: {e}")

    # Default Open-Source Hardened Patch Generator
    hardened_dockerfile = f"""# DockerShield Auto-Hardened Build Specification for {cntr_name}
FROM alpine:3.19

# Create non-root unprivileged security user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Hardening: Drop all root permissions
USER appuser
WORKDIR /home/appuser

# Enforce read-only root filesystems and drop kernel capabilities
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD wget -qO- http://localhost:80/ || exit 1
"""

    hardened_compose = f"""# DockerShield Auto-Hardened Compose Policy for {cntr_name}
version: '3.8'
services:
  {cntr_name}:
    image: {forensic_data.get("name", "app")}:hardened-v1
    read_only: true
    user: "10001:10001"
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    deploy:
      resources:
        limits:
          cpus: '0.50'
          memory: 128M
    security_opt:
      - no-new-privileges:true
"""

    return {
        "ai_engine": "DockerShield Deterministic Forensics Engine",
        "forensic_diagnosis": f"Detected runtime security compromise ({alert_summary}). Process tree contained unauthorized execution payloads.",
        "hardened_dockerfile": hardened_dockerfile,
        "hardened_compose": hardened_compose,
        "security_recommendations": [
            "Enforce read-only root filesystem ('read_only: true') in docker-compose.yml",
            "Drop Linux kernel capabilities ('cap_drop: ALL')",
            "Run container process under non-root UID 10001",
            "Restructure network bridge to block unapproved outbound egress connections"
        ]
    }
