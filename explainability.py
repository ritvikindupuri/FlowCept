def evaluate_skill_definition(
    skill_name: str,
    description: str,
    code_body: str,
    author_id: str,
    signature: str,
    session_id: str,
    skill_type: str,
    layer1_res: dict,
    layer2_res: dict,
    layer3_res: dict,
    layer4_res: dict,
    claude_res: dict = None
) -> dict:
    """Aggregates all defense layer signals and produces an explainable classification verdict."""
    
    # Calculate weighted threat score
    l1_score = layer1_res.get("severity_score", 0.0)
    l2_score = layer2_res.get("risk_score", 0.0)
    l3_score = layer3_res.get("risk_score", 0.0)
    l4_score = layer4_res.get("composition_risk_score", 0.0)

    claude_score = 0.0
    if claude_res and claude_res.get("enabled"):
        claude_score = claude_res.get("claude_threat_score", 0.0)

    # Max-based risk aggregation with weighted scaling
    overall_score = max(l1_score, l2_score, l3_score, l4_score, claude_score)
    
    # Add minor secondary weight if multiple layers trigger
    triggered_layers = sum(1 for s in [l1_score, l2_score, l3_score, l4_score, claude_score] if s > 20.0)
    if triggered_layers > 1:
        overall_score = min(overall_score + (triggered_layers * 5.0), 100.0)

    overall_score = round(overall_score, 2)

    # Classification Status
    if overall_score >= 65.0:
        verdict = "MALICIOUS"
    elif overall_score >= 25.0:
        verdict = "SUSPICIOUS"
    else:
        verdict = "BENIGN"

    # Build Structured Reasoning Trace
    reasoning_trace = []
    
    if l1_score > 0:
        for finding in layer1_res.get("findings", []):
            reasoning_trace.append(f"[Layer 1 - Rule/AST Engine] {finding['rule']} ({finding['severity']}): {finding['details']}")

    if l2_score > 0:
        for trigger in layer2_res.get("triggers", []):
            reasoning_trace.append(f"[Layer 2 - Prompt Injection / Open-Source ML] {trigger['vector']}: Matched '{trigger['matched_sample']}'")

    if l3_score > 0:
        reasoning_trace.append(f"[Layer 3 - Supply Chain Provenance] {layer3_res['status']}: {layer3_res['details']}")

    if l4_score > 0:
        for alert in layer4_res.get("chain_alerts", []):
            reasoning_trace.append(f"[Layer 4 - Composition Graph] {alert['chain_name']} ({alert['severity']}): {alert['description']}")

    if claude_res and claude_res.get("enabled"):
        reasoning_trace.append(f"[Tier 3 - Anthropic Claude Deep Reasoning] {claude_res.get('claude_verdict', 'EVALUATED')}: {claude_res.get('deep_intent_analysis', '')}")

    if not reasoning_trace:
        reasoning_trace.append("All security defense layers passed without triggering alerts.")

    # Build Counterfactual Remediation
    remediation_steps = []
    if l1_score > 0:
        remediation_steps.append("Remove unauthorized AST calls (e.g. eval, subprocess, socket) and clean hidden zero-width unicode characters.")
    if l2_score > 0:
        remediation_steps.append("Sanitize description text to remove prompt injection phrases like 'ignore previous instructions' or XML tag escapes.")
    if l3_score > 0:
        remediation_steps.append("Sign the skill package using a registered cryptographic key from a trusted author registry.")
    if l4_score > 0:
        remediation_steps.append("Avoid chaining file access, compression, and outbound HTTP transfer skills within short execution windows.")
    if claude_res and claude_res.get("constitutional_remediation"):
        remediation_steps.append(f"[Claude Remediation] {claude_res['constitutional_remediation']}")

    if not remediation_steps:
        remediation_steps.append("No remediation required. Skill complies with security policies.")

    return {
        "skill_name": skill_name,
        "verdict": verdict,
        "overall_threat_score": overall_score,
        "triggered_layer_count": triggered_layers,
        "sanitized_description": layer2_res.get("sanitized_text", description),
        "reasoning_trace": reasoning_trace,
        "remediation_steps": remediation_steps,
        "layer_breakdown": {
            "layer1_rules_ast": l1_score,
            "layer2_prompt_injection": l2_score,
            "layer3_provenance": l3_score,
            "layer4_graph_composition": l4_score,
            "tier3_claude_reasoning": claude_score
        },
        "claude_details": claude_res or {}
    }
