/**
 * PUBLIC PULSE — Simulated IT Infrastructure
 * 
 * This simulates a real-world IT infrastructure with:
 * - Database config (with intentional misconfigurations)
 * - Access control policies
 * - Encryption status
 * - Data retention policies
 * - Audit logs
 * 
 * The USER never sees this file directly.
 * The MIDDLEWARE queries it and returns only ZKP-style proofs.
 */

const express = require('express');
const app = express();
app.use(express.json());

// ============================================================
// SIMULATED INFRASTRUCTURE STATE
// (Hidden from users — middleware never exposes this directly)
// ============================================================
const infraState = {
  database: {
    host: "db-prod-01.internal",          // HIDDEN
    port: 5432,                            // HIDDEN
    name: "health_vault_prod",             // HIDDEN
    encryption_at_rest: true,
    encryption_in_transit: true,
    tls_version: "TLS 1.3",
    backup_enabled: true,
    backup_frequency_hours: 6,
    last_backup: new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString(), // 3 hrs ago
    public_access: false,                  // GOOD
    password_complexity: "high",
    connection_logging: true,
  },
  access_control: {
    mfa_required: true,
    session_timeout_minutes: 30,
    failed_login_lockout: true,
    lockout_threshold: 5,
    role_based_access: true,
    principle_of_least_privilege: true,
    privileged_accounts_count: 3,         // HIDDEN
    last_access_review: new Date(Date.now() - 25 * 24 * 60 * 60 * 1000).toISOString(), // 25 days ago — BORDERLINE
  },
  data_retention: {
    deletion_on_account_close: true,
    deletion_delay_days: 30,
    deletion_audit_log: true,
    gdpr_compliant: true,
    right_to_erasure: true,
    data_minimization: true,
  },
  network: {
    firewall_active: true,
    intrusion_detection: true,
    ddos_protection: true,
    open_ports: [443, 80],                 // HIDDEN
    vpn_required_for_admin: true,
    last_pentest: new Date(Date.now() - 45 * 24 * 60 * 60 * 1000).toISOString(), // 45 days ago
  },
  compliance: {
    iso_27001: true,
    hipaa: true,
    soc2_type2: true,
    gdpr: true,
    last_audit_date: new Date(Date.now() - 180 * 24 * 60 * 60 * 1000).toISOString(), // 6 months ago — STALE
    next_audit_date: new Date(Date.now() + 185 * 24 * 60 * 60 * 1000).toISOString(),
  },
  vulnerabilities: {
    // Intentional misconfigurations for demo
    admin_panel_exposed: false,
    default_credentials_changed: true,
    software_patching_current: true,
    unencrypted_backup_exists: false,
    excessive_permissions: false,
    logging_gaps: false,
    ssl_cert_expiry_days: 12,             // WARN: expiring soon
  }
};

// ============================================================
// POLICY RULES (Rego-inspired)
// Each returns { pass: bool, evidence: string, severity: string }
// ============================================================
const policies = {
  "encryption-at-rest": () => ({
    pass: infraState.database.encryption_at_rest,
    evidence: infraState.database.encryption_at_rest
      ? "AES-256 encryption verified on primary data store"
      : "CRITICAL: Data at rest is NOT encrypted",
    severity: "critical"
  }),

  "encryption-in-transit": () => ({
    pass: infraState.database.encryption_in_transit,
    evidence: `Transport security: ${infraState.database.tls_version} confirmed active`,
    severity: "critical"
  }),

  "no-public-database-access": () => ({
    pass: !infraState.database.public_access,
    evidence: infraState.database.public_access
      ? "CRITICAL: Database is publicly accessible on the internet"
      : "Database is isolated — no public internet exposure detected",
    severity: "critical"
  }),

  "mfa-enforced": () => ({
    pass: infraState.access_control.mfa_required,
    evidence: infraState.access_control.mfa_required
      ? "Multi-Factor Authentication is mandatory for all user sessions"
      : "WARNING: MFA is not enforced — accounts vulnerable to credential theft",
    severity: "high"
  }),

  "session-timeout": () => ({
    pass: infraState.access_control.session_timeout_minutes <= 60,
    evidence: `Sessions automatically expire after ${infraState.access_control.session_timeout_minutes} minutes of inactivity`,
    severity: "medium"
  }),

  "data-deletion-on-close": () => ({
    pass: infraState.data_retention.deletion_on_account_close,
    evidence: infraState.data_retention.deletion_on_account_close
      ? `Account deletion triggers full data purge within ${infraState.data_retention.deletion_delay_days} days per GDPR Article 17`
      : "FAIL: No deletion policy found for closed accounts",
    severity: "high"
  }),

  "gdpr-right-to-erasure": () => ({
    pass: infraState.data_retention.right_to_erasure && infraState.data_retention.deletion_audit_log,
    evidence: "Right to Erasure (GDPR Art. 17) is implemented with full audit trail logging",
    severity: "high"
  }),

  "backup-recency": () => {
    const lastBackup = new Date(infraState.database.last_backup);
    const hoursSince = (Date.now() - lastBackup) / (1000 * 60 * 60);
    const pass = hoursSince < infraState.database.backup_frequency_hours * 1.5;
    return {
      pass,
      evidence: pass
        ? `Last verified backup: ${Math.round(hoursSince)} hours ago (within ${infraState.database.backup_frequency_hours}h schedule)`
        : `WARNING: Last backup was ${Math.round(hoursSince)} hours ago — exceeds scheduled frequency`,
      severity: "medium"
    };
  },

  "ssl-certificate-valid": () => {
    const days = infraState.vulnerabilities.ssl_cert_expiry_days;
    const pass = days > 30;
    const warn = days > 0 && days <= 30;
    return {
      pass,
      warn,
      evidence: pass
        ? `SSL certificate is valid with ${days} days remaining`
        : warn
          ? `WARNING: SSL certificate expires in ${days} days — renewal required urgently`
          : "CRITICAL: SSL certificate has expired",
      severity: warn ? "medium" : "critical"
    };
  },

  "intrusion-detection-active": () => ({
    pass: infraState.network.intrusion_detection && infraState.network.firewall_active,
    evidence: "Active firewall and IDS (Intrusion Detection System) confirmed operational",
    severity: "high"
  }),

  "access-review-current": () => {
    const lastReview = new Date(infraState.access_control.last_access_review);
    const daysSince = (Date.now() - lastReview) / (1000 * 60 * 60 * 24);
    const pass = daysSince < 30;
    return {
      pass,
      evidence: pass
        ? `Access permissions reviewed ${Math.round(daysSince)} days ago (within 30-day policy)`
        : `WARNING: Last access review was ${Math.round(daysSince)} days ago — exceeds 30-day policy`,
      severity: "medium"
    };
  },

  "iso27001-compliance": () => ({
    pass: infraState.compliance.iso_27001,
    evidence: "ISO 27001 Information Security Management System controls are active",
    severity: "high"
  }),

  "hipaa-compliance": () => ({
    pass: infraState.compliance.hipaa,
    evidence: "HIPAA Security Rule safeguards verified across administrative, physical, and technical domains",
    severity: "critical"
  }),

  "login-brute-force-protection": () => ({
    pass: infraState.access_control.failed_login_lockout,
    evidence: `Account lockout after ${infraState.access_control.lockout_threshold} failed attempts — brute force protection active`,
    severity: "high"
  }),

  "admin-vpn-required": () => ({
    pass: infraState.network.vpn_required_for_admin,
    evidence: "Administrative access requires VPN — direct internet admin access is blocked",
    severity: "high"
  }),
};

// ============================================================
// API ENDPOINTS (called by Middleware only)
// ============================================================

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'operational', timestamp: new Date().toISOString() });
});

// Run a specific policy check — returns ONLY pass/fail + evidence (no raw infra data)
app.post('/audit/policy', (req, res) => {
  const { policyId } = req.body;
  
  if (!policies[policyId]) {
    return res.status(404).json({ error: 'Policy not found' });
  }

  // Simulate processing delay (ZKP circuit computation)
  setTimeout(() => {
    const result = policies[policyId]();
    
    // Generate a fake ZKP commitment hash (in real world, this would be a real ZKP)
    const commitment = generateCommitment(policyId, result.pass);
    
    res.json({
      policyId,
      result: result.pass ? (result.warn ? 'warn' : 'pass') : 'fail',
      evidence: result.evidence,
      severity: result.severity,
      zkp_commitment: commitment,
      timestamp: new Date().toISOString(),
      // NEVER return: actual IP, credentials, config files, raw server data
    });
  }, Math.random() * 800 + 200); // 200-1000ms realistic delay
});

// List available policies
app.get('/audit/policies', (req, res) => {
  res.json({
    policies: Object.keys(policies).map(id => ({
      id,
      name: formatPolicyName(id)
    }))
  });
});

// Run all policies (full audit)
app.post('/audit/full', async (req, res) => {
  const results = {};
  for (const [id, fn] of Object.entries(policies)) {
    const result = fn();
    results[id] = {
      result: result.pass ? (result.warn ? 'warn' : 'pass') : 'fail',
      evidence: result.evidence,
      severity: result.severity,
      zkp_commitment: generateCommitment(id, result.pass),
      timestamp: new Date().toISOString(),
    };
  }
  res.json({ results, auditId: generateAuditId(), timestamp: new Date().toISOString() });
});

// ============================================================
// HELPERS
// ============================================================
function generateCommitment(policyId, passed) {
  // Simulated ZKP commitment — in production this would be a real cryptographic proof
  const seed = `${policyId}-${passed}-${Date.now()}`;
  let hash = 0;
  for (let i = 0; i < seed.length; i++) {
    hash = ((hash << 5) - hash) + seed.charCodeAt(i);
    hash |= 0;
  }
  return `zkp_${Math.abs(hash).toString(16).padStart(8, '0')}_${Math.random().toString(36).slice(2, 10)}`;
}

function generateAuditId() {
  return `AUDIT-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2,6).toUpperCase()}`;
}

function formatPolicyName(id) {
  return id.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
}

const PORT = 3001;
app.listen(PORT, () => {
  console.log(`[INFRA-SIM] Infrastructure simulation running on port ${PORT}`);
  console.log(`[INFRA-SIM] ${Object.keys(policies).length} policy checks loaded`);
});

module.exports = app;
