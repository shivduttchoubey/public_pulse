# Public Pulse — PoC
### *Decentralizing IT Trust: From Institutional Assurance to Algorithmic Proof*

> "Don't trust the badge. Trust the math."

---

## What is this?

A working Proof-of-Concept of the **Public Pulse Framework** — a three-layer system that allows non-technical users to verify the security of IT infrastructure they depend on, **without ever seeing raw infrastructure data**.

This implements the vision from the paper: moving from *"Trust Me, I'm Certified"* to cryptographically verifiable, continuous, user-triggered audits.

---

## Architecture

```
┌─────────────────┐     Trust Claims      ┌──────────────────────┐
│                 │ ─────────────────────► │                      │
│  USER DASHBOARD │                        │  MIDDLEWARE ENGINE   │
│  (Port 3000)    │ ◄───────────────────── │  (Port 3002)         │
│                 │   ZKP Proof Certificate│                      │
└─────────────────┘                        └──────────┬───────────┘
                                                      │ Policy Queries
                                                      │ (Pass/Fail only)
                                                      ▼
                                           ┌──────────────────────┐
                                           │  IT INFRASTRUCTURE   │
                                           │  SIMULATION          │
                                           │  (Port 3001)         │
                                           │                      │
                                           │  ⚠ NEVER exposed     │
                                           │    to the user       │
                                           └──────────────────────┘
```

### Layer 1: IT Infrastructure Simulation (`/infra-sim`)
- Simulates a real production environment with databases, network config, access control
- Contains **intentional misconfigurations** (expiring SSL cert, overdue access reviews) to demo real findings
- Has 15 Rego-inspired policy checks built in
- **Never directly accessible to the user**

### Layer 2: Middleware Assessment Engine (`/middleware`)
- The ZKP trust bridge
- Translates user-facing "Trust Claims" into technical policy checks
- Queries the infra and returns **only pass/fail + evidence** — no raw data
- Generates verifiable Proof Certificates with commitment hashes

### Layer 3: User Dashboard (`/frontend`)
- Clean, non-technical interface
- 8 Trust Claims (mapped to 15 underlying policy checks)
- Real-time verification with animated ZKP proof display
- **Works in demo mode** (no backend required — open `index.html` directly in a browser)

---

## Quick Start

### Option A: Demo Mode (No Installation)
Just open `frontend/public/index.html` in your browser. The app will run in demo mode with realistic pre-generated proofs.

### Option B: Full Stack (Node.js Required)

**Prerequisites:** Node.js 18+

```bash
# 1. Install dependencies
cd infra-sim && npm install && cd ..
cd middleware && npm install && cd ..

# 2. Start everything
node start.js
```

Then open **http://localhost:3000** in your browser.

---

## Trust Claims Available

| Claim | Policies Checked |
|-------|-----------------|
| 🔐 My data is encrypted | Encryption at rest + in transit |
| 🛡️ My account cannot be broken into | MFA, session timeout, brute force protection |
| 🗑️ My data will be deleted when I ask | GDPR Art. 17, deletion audit trail |
| 💾 My data is regularly backed up | Backup recency verification |
| 📋 This system meets official standards | ISO 27001, HIPAA, SSL validity |
| 🌐 My data is not exposed to the internet | DB isolation, VPN admin access, IDS |
| 👥 Only authorized people can access my data | Access review currency |
| 🔍 Full infrastructure audit | All 15 checks — equivalent to a week-long expert audit |

---

## Key Design Principles

1. **Zero Raw Data Exposure**: The user dashboard never receives IP addresses, credentials, config files, or any raw infrastructure data. Only human-readable evidence statements.

2. **ZKP-Inspired Commitments**: Each check produces a cryptographic commitment hash. The aggregated proof chain hash proves all checks ran against live infrastructure.

3. **Policy-as-Code**: Standards (ISO 27001 Control A.9.4.2, HIPAA) are encoded as executable Rego-like scripts, not paper checklists.

4. **Continuous Verification**: Proofs are time-limited (5 minutes). Each button press is a fresh audit — not a stale certificate.

5. **Intentional Flaws**: The infra simulation includes real findings (expiring SSL, overdue access review) to demonstrate the system catches real issues.

---

## File Structure

```
public-pulse/
├── start.js                  # Launch all services
├── package.json
│
├── infra-sim/
│   ├── index.js              # Infrastructure simulation + policy engine
│   └── package.json
│
├── middleware/
│   ├── index.js              # Assessment engine + proof generator
│   └── package.json
│
└── frontend/
    └── public/
        └── index.html        # User dashboard (self-contained)
```

---

## Extending the PoC

**Add a new Trust Claim** (in `middleware/index.js`):
```js
"my-logs-are-retained": {
  id: "my-logs-are-retained",
  label: "My access logs are kept for 12 months",
  description: "Confirms audit logs are stored and retained per policy",
  icon: "📝",
  category: "Auditability",
  policies: ["log-retention-policy", "log-integrity-check"],
  interpretation: { allPass: "...", anyFail: "...", anyWarn: "..." }
}
```

**Add a new Policy Check** (in `infra-sim/index.js`):
```js
"log-retention-policy": () => ({
  pass: infraState.logging.retention_days >= 365,
  evidence: `Logs retained for ${infraState.logging.retention_days} days`,
  severity: "medium"
})
```

---

*Built as a PoC for the paper: "Decentralizing IT Trust: A Framework for User-Led, Privacy-Preserving Infrastructure Auditing via Data Obfuscation and Zero-Knowledge Logic"*
