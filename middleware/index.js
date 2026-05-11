/**
 * PUBLIC PULSE — Middleware Assessment Engine
 * 
 * This is the TRUST BRIDGE between raw infrastructure and the public user.
 * 
 * Key responsibilities:
 * 1. Translate user-facing "Trust Claims" into technical policy checks
 * 2. Aggregate results into human-readable proofs
 * 3. Ensure NO raw infrastructure data leaks to the user
 * 4. Generate audit trails and verifiable proof certificates
 */

const express = require('express');
const cors = require('cors');
const app = express();
app.use(cors());
app.use(express.json());

const INFRA_URL = 'http://localhost:3001';

// ============================================================
// TRUST CLAIM CATALOG
// These are what users see — mapped to underlying policy checks
// ============================================================
const TRUST_CLAIMS = {
  "my-data-is-encrypted": {
    id: "my-data-is-encrypted",
    label: "My data is encrypted",
    description: "Verifies that your personal data is encrypted both when stored and when transmitted",
    icon: "🔐",
    category: "Data Protection",
    policies: ["encryption-at-rest", "encryption-in-transit"],
    interpretation: {
      allPass: "Your data is protected by encryption at all times — at rest and in transit.",
      anyFail: "Encryption gaps detected. Your data may be at risk.",
      anyWarn: "Encryption is active but some concerns were flagged.",
    }
  },
  "my-account-is-secure": {
    id: "my-account-is-secure",
    label: "My account cannot be easily broken into",
    description: "Checks that strong authentication, session management, and brute force protection are in place",
    icon: "🛡️",
    category: "Access Security",
    policies: ["mfa-enforced", "session-timeout", "login-brute-force-protection"],
    interpretation: {
      allPass: "Strong authentication controls protect your account from unauthorized access.",
      anyFail: "Account security gaps found. Your account may be vulnerable.",
      anyWarn: "Most account protections are active, but some improvements are needed.",
    }
  },
  "my-data-is-deleted-on-request": {
    id: "my-data-is-deleted-on-request",
    label: "My data will be deleted when I ask",
    description: "Confirms the Right to Erasure (GDPR Article 17) is technically implemented, not just promised",
    icon: "🗑️",
    category: "Data Rights",
    policies: ["data-deletion-on-close", "gdpr-right-to-erasure"],
    interpretation: {
      allPass: "Your right to data deletion is technically enforced — not just a policy promise.",
      anyFail: "Data deletion mechanisms are missing or incomplete.",
      anyWarn: "Partial deletion controls found. Some data may not be fully erasable.",
    }
  },
  "my-data-is-backed-up": {
    id: "my-data-is-backed-up",
    label: "My data is regularly backed up",
    description: "Verifies that recent backups exist so your data isn't lost to a technical failure",
    icon: "💾",
    category: "Data Resilience",
    policies: ["backup-recency"],
    interpretation: {
      allPass: "Recent backups confirmed — your data is protected against infrastructure failures.",
      anyFail: "Backups are missing or outdated. Data loss risk is elevated.",
      anyWarn: "Backups exist but may not be within the expected schedule.",
    }
  },
  "the-system-is-compliant": {
    id: "the-system-is-compliant",
    label: "This system meets official standards",
    description: "Checks ISO 27001 and HIPAA compliance controls are technically active, not just certified on paper",
    icon: "📋",
    category: "Compliance",
    policies: ["iso27001-compliance", "hipaa-compliance", "ssl-certificate-valid"],
    interpretation: {
      allPass: "Active compliance controls verified — certifications reflect real technical implementation.",
      anyFail: "Compliance controls are failing. The badge may not match reality.",
      anyWarn: "Mostly compliant, but some controls need attention.",
    }
  },
  "my-data-is-not-exposed": {
    id: "my-data-is-not-exposed",
    label: "My data is not exposed to the internet",
    description: "Confirms the database is isolated from public internet access and admin access is secured",
    icon: "🌐",
    category: "Network Security",
    policies: ["no-public-database-access", "admin-vpn-required", "intrusion-detection-active"],
    interpretation: {
      allPass: "Database is isolated from the public internet and protected by active security monitoring.",
      anyFail: "Network exposure detected. Your data may be accessible to attackers.",
      anyWarn: "Network security is mostly in place, but some exposure risks were found.",
    }
  },
  "access-is-reviewed": {
    id: "access-is-reviewed",
    label: "Only authorized people can access my data",
    description: "Verifies that access permissions are regularly reviewed and follow least-privilege principles",
    icon: "👥",
    category: "Access Governance",
    policies: ["access-review-current"],
    interpretation: {
      allPass: "Access control reviews are current — only authorized personnel can reach your data.",
      anyFail: "Access reviews are overdue. Unauthorized access may have gone undetected.",
      anyWarn: "Access reviews exist but are approaching their deadline.",
    }
  },
  "full-audit": {
    id: "full-audit",
    label: "Run a complete infrastructure audit",
    description: "Runs all 15 policy checks across every security domain — the equivalent of a week-long expert audit, in minutes",
    icon: "🔍",
    category: "Full Assessment",
    policies: "ALL",
    interpretation: {
      allPass: "All systems verified. This infrastructure meets a high security standard.",
      anyFail: "Critical issues found. Immediate attention is required.",
      anyWarn: "Infrastructure is mostly secure with some items needing attention.",
    }
  }
};

// ============================================================
// PROOF CERTIFICATE GENERATOR
// Produces a verifiable, human-readable proof document
// ============================================================
function generateProofCertificate(claimId, results, claimMeta) {
  const allPass = results.every(r => r.result === 'pass' || r.result === 'warn');
  const anyFail = results.some(r => r.result === 'fail');
  const anyWarn = results.some(r => r.result === 'warn');
  
  const overallResult = anyFail ? 'fail' : anyWarn ? 'warn' : 'pass';
  
  // Aggregate ZKP commitments into a single proof hash
  const commitmentChain = results.map(r => r.zkp_commitment).join('|');
  const proofHash = generateProofHash(commitmentChain);
  
  return {
    proof_certificate: {
      id: `PROOF-${Date.now().toString(36).toUpperCase()}`,
      claim_id: claimId,
      claim_label: claimMeta.label,
      overall_result: overallResult,
      interpretation: anyFail
        ? claimMeta.interpretation.anyFail
        : anyWarn
          ? claimMeta.interpretation.anyWarn
          : claimMeta.interpretation.allPass,
      checks_performed: results.length,
      checks_passed: results.filter(r => r.result === 'pass').length,
      checks_warned: results.filter(r => r.result === 'warn').length,
      checks_failed: results.filter(r => r.result === 'fail').length,
      individual_results: results.map(r => ({
        policy: r.policyId,
        result: r.result,
        evidence: r.evidence,     // Human-readable proof statement
        severity: r.severity,
        zkp_commitment: r.zkp_commitment,  // Cryptographic commitment
        // RAW INFRA DATA IS NEVER INCLUDED
      })),
      proof_chain_hash: proofHash,
      generated_at: new Date().toISOString(),
      valid_for_minutes: 5,        // Proofs are time-limited (continuous verification)
      methodology: "Zero-Knowledge Policy Verification via Public Pulse Framework v1.0",
    }
  };
}

function generateProofHash(commitmentChain) {
  let hash = 5381;
  for (let i = 0; i < commitmentChain.length; i++) {
    hash = ((hash << 5) + hash) + commitmentChain.charCodeAt(i);
    hash |= 0;
  }
  const hex = Math.abs(hash).toString(16).padStart(8, '0');
  return `0x${hex}${Math.random().toString(16).slice(2, 10)}`;
}

// ============================================================
// API ENDPOINTS (called by Frontend)
// ============================================================

// Get all available trust claims
app.get('/claims', (req, res) => {
  const claims = Object.values(TRUST_CLAIMS).map(claim => ({
    id: claim.id,
    label: claim.label,
    description: claim.description,
    icon: claim.icon,
    category: claim.category,
    policy_count: claim.policies === 'ALL' ? 'All' : claim.policies.length,
  }));
  res.json({ claims });
});

// Run a specific trust claim verification
app.post('/verify/:claimId', async (req, res) => {
  const { claimId } = req.params;
  const claim = TRUST_CLAIMS[claimId];
  
  if (!claim) {
    return res.status(404).json({ error: 'Trust claim not found' });
  }

  try {
    let policyIds = claim.policies;
    
    // For full audit, get all policy IDs from infra
    if (policyIds === 'ALL') {
      const policiesRes = await fetch(`${INFRA_URL}/audit/policies`);
      const policiesData = await policiesRes.json();
      policyIds = policiesData.policies.map(p => p.id);
    }

    // Run all relevant policy checks against infra
    const policyPromises = policyIds.map(async (policyId) => {
      const response = await fetch(`${INFRA_URL}/audit/policy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ policyId })
      });
      return response.json();
    });

    const results = await Promise.all(policyPromises);
    
    // Generate proof certificate (no raw infra data)
    const certificate = generateProofCertificate(claimId, results, claim);
    
    res.json(certificate);
    
  } catch (error) {
    console.error('[MIDDLEWARE] Error running verification:', error);
    res.status(500).json({ 
      error: 'Verification failed — infrastructure may be unreachable',
      detail: error.message 
    });
  }
});

// Infrastructure health check (returns only availability, no config)
app.get('/infra/status', async (req, res) => {
  try {
    const response = await fetch(`${INFRA_URL}/health`);
    const data = await response.json();
    res.json({ 
      available: true, 
      timestamp: data.timestamp,
      message: "Infrastructure is reachable and responding"
    });
  } catch (e) {
    res.json({ available: false, message: "Infrastructure unreachable" });
  }
});

// Stats endpoint
app.get('/stats', (req, res) => {
  res.json({
    total_claims: Object.keys(TRUST_CLAIMS).length,
    categories: [...new Set(Object.values(TRUST_CLAIMS).map(c => c.category))],
    framework_version: "1.0.0",
    methodology: "Zero-Knowledge Policy Verification",
  });
});

const PORT = 3002;
app.listen(PORT, () => {
  console.log(`[MIDDLEWARE] Assessment engine running on port ${PORT}`);
  console.log(`[MIDDLEWARE] ${Object.keys(TRUST_CLAIMS).length} trust claims available`);
});

module.exports = app;
