import time

# Pre-defined dangerous skill execution composition sequences
HAZARD_CHAINS = [
    {
        "name": "Chained Data Exfiltration Sequence",
        "pattern": ["file_read", "compress", "http_post"],
        "severity": "CRITICAL",
        "score": 85.0,
        "description": "Benign FileRead followed by Data Compression and Outbound HTTP Transfer indicates multi-stage data exfiltration."
    },
    {
        "name": "Staged Payload Dropper Sequence",
        "pattern": ["download_file", "chmod_exec", "spawn_process"],
        "severity": "CRITICAL",
        "score": 90.0,
        "description": "Download followed by permission modification and process execution indicates dropper activity."
    },
    {
        "name": "Privilege Escalation & Log Erasure",
        "pattern": ["discovery", "privilege_escalate", "delete_logs"],
        "severity": "HIGH",
        "score": 80.0,
        "description": "Reconnaissance followed by privilege escalation and log cleanup indicates hostile intrusion."
    }
]

# Global store for active agent session graphs
SESSION_GRAPHS = {}

def record_skill_invocation(session_id: str, skill_id: str, skill_type: str) -> dict:
    """Records a skill invocation in the session graph and evaluates composition risks."""
    if session_id not in SESSION_GRAPHS:
        SESSION_GRAPHS[session_id] = {
            "sequence": [],
            "nodes": set(),
            "edges": []
        }

    graph = SESSION_GRAPHS[session_id]
    
    # Record node
    graph["nodes"].add(skill_id)
    
    # Record edge if there is a previous skill
    if graph["sequence"]:
        prev_skill = graph["sequence"][-1]["skill_id"]
        graph["edges"].append((prev_skill, skill_id))

    graph["sequence"].append({
        "skill_id": skill_id,
        "skill_type": skill_type.lower(),
        "timestamp": time.time()
    })

    # Evaluate composition chains
    recent_types = [item["skill_type"] for item in graph["sequence"][-5:]]
    
    chain_alerts = []
    total_composition_risk = 0.0

    for chain in HAZARD_CHAINS:
        pattern = chain["pattern"]
        # Check if the sequence pattern matches recent invocations
        for i in range(len(recent_types) - len(pattern) + 1):
            sub_seq = recent_types[i:i + len(pattern)]
            if sub_seq == pattern:
                total_composition_risk += chain["score"]
                chain_alerts.append({
                    "chain_name": chain["name"],
                    "severity": chain["severity"],
                    "description": chain["description"],
                    "matched_sequence": sub_seq
                })

    return {
        "composition_risk_score": min(total_composition_risk, 100.0),
        "chain_alerts": chain_alerts,
        "session_node_count": len(graph["nodes"]),
        "session_sequence_length": len(graph["sequence"]),
        "graph_edges": graph["edges"]
    }
