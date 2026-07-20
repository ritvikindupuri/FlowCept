import os
import json
import logging
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
import uvicorn

import docker_monitor
import threat_engine
import healing_engine
import ai_forensics

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app")

app = FastAPI(title="DockerShield - Self-Healing Infrastructure Security")

class AttackSimulationModel(BaseModel):
    container_id: str
    attack_type: str

class SelfHealModel(BaseModel):
    container_id: str

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DockerShield — Self-Healing Infrastructure Security</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Newsreader:ital,opsz,wght@0,6..72,400;0,6..72,500;1,6..72,400&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-base: #fbf9f5;
            --bg-surface: #ffffff;
            --bg-card: #f4f0ea;
            --text-main: #1e1e1e;
            --text-muted: #6e6a66;
            --border: #e6e0d8;
            --accent-coral: #da7756;
            --accent-coral-hover: #c86545;
            --accent-coral-light: #fdf2ee;
            --safe-green: #15803d;
            --safe-bg: #f0fdf4;
            --safe-border: #bbf7d0;
            --warning-amber: #b45309;
            --warning-bg: #fffbeb;
            --warning-border: #fef3c7;
            --unsafe-red: #b91c1c;
            --unsafe-bg: #fef2f2;
            --unsafe-border: #fecaca;
            --heal-blue: #1d4ed8;
            --heal-bg: #eff6ff;
            --heal-border: #bfdbfe;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            background-color: var(--bg-base);
            color: var(--text-main);
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            -webkit-font-smoothing: antialiased;
        }

        header {
            background: var(--bg-base);
            border-bottom: 1px solid var(--border);
            padding: 0.9rem 2.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .brand { display: flex; align-items: center; gap: 0.85rem; }
        .logo-mark {
            width: 34px; height: 34px;
            display: flex; align-items: center; justify-content: center;
        }
        h1 {
            font-family: 'Newsreader', serif;
            font-size: 1.45rem; font-weight: 500;
            color: var(--text-main); letter-spacing: -0.01em;
        }
        .tagline { font-size: 0.82rem; color: var(--text-muted); font-weight: 500; }

        main { flex: 1; display: flex; overflow: hidden; }

        .column { display: flex; flex-direction: column; overflow: hidden; }
        .col-left { flex: 1.15; border-right: 1px solid var(--border); background: var(--bg-surface); }
        .col-right { flex: 0.85; background: var(--bg-base); }

        .section-header {
            padding: 1rem 2rem;
            border-bottom: 1px solid var(--border);
            display: flex; justify-content: space-between; align-items: center;
            background: var(--bg-base);
        }
        .section-title {
            font-size: 0.78rem; font-weight: 700; text-transform: uppercase;
            letter-spacing: 0.08em; color: var(--text-muted);
        }

        /* Controls Bar */
        .controls-bar {
            padding: 0.85rem 2rem;
            background: var(--bg-card);
            border-bottom: 1px solid var(--border);
            display: flex; gap: 0.6rem; align-items: center; flex-wrap: wrap;
        }

        .sim-btn {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 0.45rem 0.95rem; font-size: 0.78rem; font-weight: 600;
            border-radius: 20px; cursor: pointer; transition: all 0.15s ease;
        }
        .sim-btn:hover {
            border-color: var(--accent-coral);
            color: var(--accent-coral);
            background: var(--accent-coral-light);
        }

        .btn-heal {
            background: var(--accent-coral);
            color: white; border: none;
            padding: 0.5rem 1.25rem; font-size: 0.82rem; font-weight: 700;
            border-radius: 6px; cursor: pointer; transition: background 0.15s ease;
            margin-left: auto;
        }
        .btn-heal:hover { background: var(--accent-coral-hover); }

        /* Container Inventory Grid */
        .inventory-body {
            padding: 1.75rem 2rem;
            display: flex; flex-direction: column; gap: 1.25rem;
            overflow-y: auto; flex: 1;
        }

        .container-card {
            background: var(--bg-base);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 1.25rem;
            display: flex; flex-direction: column; gap: 0.85rem;
            transition: all 0.2s ease;
        }
        .container-card.compromised {
            border-color: var(--unsafe-border);
            background: var(--unsafe-bg);
        }
        .container-card.healed {
            border-color: var(--heal-border);
            background: var(--heal-bg);
        }

        .cntr-header {
            display: flex; justify-content: space-between; align-items: center;
        }
        .cntr-name { font-weight: 700; font-size: 0.95rem; color: var(--text-main); }
        .cntr-id { font-family: monospace; font-size: 0.75rem; color: var(--text-muted); }

        .status-badge {
            font-size: 0.72rem; font-weight: 700; padding: 0.25rem 0.65rem;
            border-radius: 12px; text-transform: uppercase; letter-spacing: 0.05em;
        }
        .status-badge.healthy { background: var(--safe-bg); color: var(--safe-green); border: 1px solid var(--safe-border); }
        .status-badge.compromised { background: var(--unsafe-bg); color: var(--unsafe-red); border: 1px solid var(--unsafe-border); animation: pulse-red 1.5s infinite; }
        .status-badge.healed { background: var(--heal-bg); color: var(--heal-blue); border: 1px solid var(--heal-border); }

        @keyframes pulse-red { 0% { opacity: 0.7; } 50% { opacity: 1; } 100% { opacity: 0.7; } }

        .metrics-row {
            display: flex; gap: 1.5rem; font-size: 0.8rem; color: var(--text-muted);
        }
        .metric-item { display: flex; flex-direction: column; gap: 0.15rem; }
        .metric-val { font-weight: 700; color: var(--text-main); font-size: 0.88rem; }

        .process-list {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 0.65rem 0.85rem;
            font-family: monospace; font-size: 0.75rem; color: #334155;
            display: flex; flex-direction: column; gap: 0.25rem;
        }

        /* Right Hero & Logs */
        .system-hero {
            padding: 2rem;
            border-bottom: 1px solid var(--border);
            background: var(--bg-surface);
            display: flex; justify-content: space-between; align-items: center;
        }

        .hero-status {
            font-family: 'Newsreader', serif;
            font-size: 1.7rem; font-weight: 500;
        }

        .timeline-body {
            padding: 2rem; overflow-y: auto; flex: 1;
            display: flex; flex-direction: column; gap: 1.5rem;
        }

        .timeline-block { display: flex; flex-direction: column; gap: 0.65rem; }
        .block-title {
            font-size: 0.78rem; font-weight: 700; text-transform: uppercase;
            letter-spacing: 0.05em; color: var(--text-muted);
        }

        .step-card {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 0.85rem 1.15rem;
            font-size: 0.85rem; line-height: 1.5;
            display: flex; flex-direction: column; gap: 0.3rem;
        }

        .step-stage { font-size: 0.7rem; font-weight: 700; color: var(--accent-coral); text-transform: uppercase; }

        /* Modal Overlay for AI Forensics */
        .modal-overlay {
            position: fixed; top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(25, 25, 25, 0.4);
            backdrop-filter: blur(4px); display: none;
            align-items: center; justify-content: center; z-index: 1000;
        }
        .modal-box {
            background: var(--bg-surface);
            border: 1px solid var(--border); border-radius: 12px;
            width: 90%; max-width: 650px; max-height: 80vh;
            display: flex; flex-direction: column;
            box-shadow: 0 20px 40px rgba(0,0,0,0.15); overflow: hidden;
        }
        .modal-header {
            padding: 1.25rem 1.75rem; border-bottom: 1px solid var(--border);
            display: flex; justify-content: space-between; align-items: center;
            background: var(--bg-base);
        }
        .modal-body {
            padding: 1.75rem; overflow-y: auto; display: flex; flex-direction: column; gap: 1.25rem;
        }
        .code-box {
            background: var(--bg-base); border: 1px solid var(--border);
            border-radius: 6px; padding: 1rem;
            font-family: monospace; font-size: 0.8rem;
            white-space: pre-wrap; word-break: break-all;
        }
    </style>
</head>
<body>

    <header>
        <div class="brand">
            <div class="logo-mark">
                <svg width="32" height="32" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M50 8 L85 24 V50 C85 70 70 86 50 92 C30 86 15 70 15 50 V24 L50 8 Z" fill="#da7756"/>
                    <path d="M50 20 L72 32 V50 C72 64 61 76 50 81 C39 76 28 64 28 50 V32 L50 20 Z" fill="#ffffff" fill-opacity="0.25"/>
                    <circle cx="50" cy="50" r="14" fill="#ffffff"/>
                    <circle cx="50" cy="50" r="7" fill="#da7756"/>
                </svg>
            </div>
            <h1>DockerShield</h1>
        </div>
        <div class="tagline">
            Self-Healing Docker Cybersecurity & Automated Remediation Platform
        </div>
    </header>

    <main>
        <!-- Left Column: Active Container Inventory & Threat Simulators -->
        <div class="column col-left">
            <div class="section-header">
                <span class="section-title">Active Container Workloads</span>
            </div>

            <!-- Attack Simulator Buttons -->
            <div class="controls-bar">
                <span style="font-size:0.75rem; color:var(--text-muted); font-weight:600;">Attack Simulator:</span>
                <button class="sim-btn" onclick="triggerAttack('cntr-nginx-prod-01', 'reverse_shell')">Reverse Shell</button>
                <button class="sim-btn" onclick="triggerAttack('cntr-nginx-prod-01', 'cryptominer')">CryptoMiner</button>
                <button class="sim-btn" onclick="triggerAttack('cntr-nginx-prod-01', 'exfiltration')">Data Exfil</button>
                <button class="sim-btn" onclick="triggerAttack('cntr-nginx-prod-01', 'privilege_escalation')">PrivEsc</button>

                <button class="btn-heal" onclick="runSelfHealing('cntr-nginx-prod-01')">Auto-Heal Infrastructure</button>
            </div>

            <!-- Container Inventory List -->
            <div class="inventory-body" id="inventory-container">
                <!-- Dynamically Rendered Container Cards -->
            </div>
        </div>

        <!-- Right Column: System Posture & Self-Healing Audit Timeline -->
        <div class="column col-right">
            <div class="section-header">
                <span class="section-title">Self-Healing Security Posture</span>
            </div>

            <!-- System Posture Hero -->
            <div class="system-hero">
                <div>
                    <div class="hero-status" id="system-status-text" style="color:var(--safe-green);">INFRASTRUCTURE HEALTHY</div>
                    <span style="font-size:0.75rem; color:var(--text-muted); font-weight:500;">Continuous Automated Remediation Protocol Active</span>
                </div>
            </div>

            <!-- Self-Healing Timeline & Forensics -->
            <div class="timeline-body">
                <div class="timeline-block">
                    <span class="block-title">Automated Self-Healing Remediation Log</span>
                    <div id="timeline-container" style="display:flex; flex-direction:column; gap:0.75rem;">
                        <div class="step-card" style="color:var(--text-muted);">
                            No security incidents detected. Self-healing daemon standing by in sub-100ms inspection loop.
                        </div>
                    </div>
                </div>

                <div class="timeline-block">
                    <span class="block-title">AI Forensic Diagnostics & Patch Generation</span>
                    <div id="forensics-container">
                        <button class="sim-btn" style="width:100%; border-radius:8px; padding:0.75rem;" onclick="openForensicsModal('cntr-nginx-prod-01')">
                            🔍 View AI Forensic Diagnosis & Hardened Dockerfile Patch
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <!-- AI Forensics Modal -->
    <div class="modal-overlay" id="modal-overlay" onclick="closeModal(event)">
        <div class="modal-box" onclick="event.stopPropagation()">
            <div class="modal-header">
                <h2 style="font-family:'Newsreader',serif; font-size:1.3rem;">AI Security Patch & Forensic Diagnosis</h2>
                <button style="background:none; border:none; font-size:1.4rem; cursor:pointer;" onclick="closeModal()">×</button>
            </div>
            <div class="modal-body" id="modal-body">
                <p>Click "Auto-Heal Infrastructure" or trigger an attack to view full AI forensic telemetry.</p>
            </div>
        </div>
    </div>

    <script>
        let latestForensicsData = null;

        async function fetchContainers() {
            const resp = await fetch('/api/containers');
            const containers = await resp.json();
            renderContainers(containers);
        }

        function renderContainers(containers) {
            const container = document.getElementById('inventory-container');
            container.innerHTML = '';

            let hasCompromised = false;
            let hasHealed = false;

            containers.forEach(c => {
                let statusClass = 'healthy';
                let badgeLabel = c.health;

                if (c.health === 'COMPROMISED') {
                    statusClass = 'compromised';
                    hasCompromised = true;
                } else if (c.health.includes('SELF-HEALED')) {
                    statusClass = 'healed';
                    hasHealed = true;
                }

                const card = document.createElement('div');
                card.className = `container-card ${statusClass}`;
                card.innerHTML = `
                    <div class="cntr-header">
                        <div>
                            <span class="cntr-name">${c.name}</span>
                            <span class="cntr-id"> (${c.container_id})</span>
                        </div>
                        <span class="status-badge ${statusClass}">${badgeLabel}</span>
                    </div>

                    <div class="metrics-row">
                        <div class="metric-item">
                            <span>Image</span>
                            <span class="metric-val">${c.image}</span>
                        </div>
                        <div class="metric-item">
                            <span>CPU Usage</span>
                            <span class="metric-val">${c.cpu_usage_pct}%</span>
                        </div>
                        <div class="metric-item">
                            <span>Memory</span>
                            <span class="metric-val">${c.memory_mb} MB</span>
                        </div>
                        <div class="metric-item">
                            <span>Network</span>
                            <span class="metric-val">${c.network_status}</span>
                        </div>
                    </div>

                    <div class="process-list">
                        <span style="font-weight:700; color:var(--text-muted);">ACTIVE PROCESS TREE:</span>
                        ${c.processes.map(p => `<div>⚡ ${p}</div>`).join('')}
                    </div>
                `;
                container.appendChild(card);
            });

            // Update Hero Status
            const heroStatus = document.getElementById('system-status-text');
            if (hasCompromised) {
                heroStatus.innerText = 'ATTACK DETECTED — HEALING REQUIRED';
                heroStatus.style.color = 'var(--unsafe-red)';
            } else if (hasHealed) {
                heroStatus.innerText = 'INFRASTRUCTURE SELF-HEALED & RESTORED';
                heroStatus.style.color = 'var(--heal-blue)';
            } else {
                heroStatus.innerText = 'INFRASTRUCTURE HEALTHY';
                heroStatus.style.color = 'var(--safe-green)';
            }
        }

        async function triggerAttack(containerId, attackType) {
            await fetch('/api/simulate-attack', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ container_id: containerId, attack_type: attackType })
            });
            await fetchContainers();
        }

        async function runSelfHealing(containerId) {
            const resp = await fetch('/api/self-heal', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ container_id: containerId })
            });

            const record = await resp.json();
            renderTimeline(record);
            await fetchContainers();
        }

        function renderTimeline(record) {
            const container = document.getElementById('timeline-container');
            container.innerHTML = '';

            if (record.steps) {
                record.steps.forEach(st => {
                    const stepCard = document.createElement('div');
                    stepCard.className = 'step-card';
                    stepCard.innerHTML = `
                        <div class="step-stage">Stage ${st.stage}: ${st.action} (${st.timestamp})</div>
                        <div>${st.details}</div>
                    `;
                    container.appendChild(stepCard);
                });
            }
        }

        async function openForensicsModal(containerId) {
            const resp = await fetch(`/api/forensics/${containerId}`);
            const patch = await resp.json();

            const body = document.getElementById('modal-body');
            body.innerHTML = `
                <p><strong>AI Security Engine:</strong> ${patch.ai_engine}</p>
                <p><strong>Forensic Root Cause Diagnosis:</strong></p>
                <div class="code-box" style="color:var(--text-main);">${patch.forensic_diagnosis}</div>

                <p><strong>Auto-Generated Hardened Dockerfile Patch:</strong></p>
                <div class="code-box">${patch.hardened_dockerfile}</div>

                <p><strong>Auto-Generated Hardened docker-compose.yml Policy:</strong></p>
                <div class="code-box">${patch.hardened_compose}</div>
            `;
            document.getElementById('modal-overlay').style.display = 'flex';
        }

        function closeModal() {
            document.getElementById('modal-overlay').style.display = 'none';
        }

        // Initial Load & Auto Refresh
        fetchContainers();
        setInterval(fetchContainers, 3000);
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    return DASHBOARD_HTML

@app.get("/api/containers")
async def get_containers():
    containers = docker_monitor.get_active_containers()
    for c in containers:
        threat_info = threat_engine.analyze_container_threats(c)
        if threat_info["threat_status"] == "COMPROMISED" and c["health"] != "HEALTHY (SELF-HEALED)":
            c["health"] = "COMPROMISED"
    return containers

@app.post("/api/simulate-attack")
async def simulate_attack(req: AttackSimulationModel):
    res = threat_engine.inject_simulated_attack(req.container_id, req.attack_type, docker_monitor.SYSTEM_CONTAINERS)
    return res

@app.post("/api/self-heal")
async def self_heal(req: SelfHealModel):
    cntr_info = docker_monitor.inspect_container(req.container_id)
    threat_analysis = threat_engine.analyze_container_threats(cntr_info)
    record = healing_engine.execute_self_healing(req.container_id, threat_analysis)
    return record

@app.get("/api/healing-logs")
async def get_healing_logs():
    return healing_engine.HEALING_AUDIT_LOGS

@app.get("/api/forensics/{container_id}")
async def get_forensics(container_id: str):
    cntr_info = docker_monitor.inspect_container(container_id)
    threat_analysis = threat_engine.analyze_container_threats(cntr_info)
    forensic_payload = {
        "container_id": container_id,
        "name": cntr_info.get("name", "nginx-app"),
        "threat_analysis": threat_analysis,
        "process_tree_snapshot": cntr_info.get("processes", [])
    }
    patch = ai_forensics.generate_forensic_patch(forensic_payload)
    return patch

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8500)
