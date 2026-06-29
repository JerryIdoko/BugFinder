import { Config } from '../orchestrator/orchestrator.js';
import { Vulnerability } from '../detector/vulnerability-detector.js';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';
import chalk from 'chalk';

function sanitizeTitle(s: string): string {
  return s
    .replace(/[^a-zA-Z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '')
    .toLowerCase()
    .substring(0, 60);
}

function buildImmunefiTitle(vuln: Vulnerability): string {
  const type = vuln.type || 'Vulnerability';
  const file = vuln.location.file.split('/').pop() || vuln.location.file;
  const func = vuln.location.function || 'unknown';
  const location = `${file}:${func}`;
  const impactPhrase = summarizeImpact(vuln);
  return `[${type}] in ${location} leads to ${impactPhrase}`;
}

function summarizeImpact(vuln: Vulnerability): string {
  const sev = vuln.severity?.toLowerCase() || 'medium';
  const impact = vuln.impact || '';
  if (impact.length > 10) {
    const trimmed = impact.replace(/^[^a-zA-Z]+/, '').substring(0, 80).replace(/\s+\S*$/, '');
    return trimmed;
  }
  const map: Record<string, string> = {
    critical: 'total loss of protocol funds',
    high: 'significant loss of user funds',
    medium: 'temporary asset freeze or manipulation',
    low: 'minor security best-practice violation',
  };
  return map[sev] || 'security impact';
}

function immunefiSeverity(vuln: Vulnerability): { label: string; criteria: string } {
  const sev = vuln.severity?.toLowerCase() || 'low';
  const map: Record<string, { label: string; criteria: string }> = {
    critical: {
      label: 'Critical',
      criteria: 'Permanent freezing or theft of protocol funds, total loss of user assets, or permanent network shutdown.',
    },
    high: {
      label: 'High',
      criteria: 'Temporary freezing of funds, significant loss of yield, or manipulation of critical contract state that impacts core functionality.',
    },
    medium: {
      label: 'Medium',
      criteria: 'Temporary denial-of-service, smart contract griefing, or manipulation of non-critical state with limited economic impact.',
    },
    low: {
      label: 'Low',
      criteria: 'Best-practice violations, gas inefficiencies, lack of events, or informational findings with no direct economic risk.',
    },
  };
  return map[sev] || map.low;
}

export class Reporter {
  private config: Config;
  private findingsDir: string;

  constructor(config: Config, targetPath?: string) {
    this.config = config;
    if (targetPath) {
      const scanName = this.createScanName(targetPath);
      this.findingsDir = path.join(config.output.findings_dir, scanName);
    } else {
      this.findingsDir = config.output.findings_dir;
    }
  }

  private createScanName(targetPath: string): string {
    const baseName = path.basename(targetPath);
    const hash = crypto.createHash('sha256')
      .update(path.resolve(targetPath))
      .digest('hex')
      .substring(0, 8);
    return `${baseName}-${hash}`;
  }

  async report(vulnerabilities: Vulnerability[]): Promise<void> {
    await fs.mkdir(this.findingsDir, { recursive: true });
    const manifest: any[] = [];

    for (const vuln of vulnerabilities) {
      await this.reportVulnerability(vuln);
      manifest.push({
        id: vuln.id,
        type: vuln.type,
        severity: vuln.severity,
        immunefiTitle: buildImmunefiTitle(vuln),
        verificationStatus: vuln.verificationStatus || 'unverified',
        confidence: vuln.confidence || 'unknown',
        needsManualReview: vuln.needsManualReview || false,
        hasPOC: !!vuln.poc,
        pocValidated: vuln.poc?.validated || false,
        location: `${vuln.location.file}:${vuln.location.line}`,
        attackerControlled: vuln.attackerControlled?.isControlled || false,
        blindspot: vuln.blindspotCategory && vuln.blindspotCategory !== 'none',
        timestamp: new Date().toISOString(),
      });
    }

    const manifestPath = path.join(this.findingsDir, 'MANIFEST.json');
    await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2));
    console.log(chalk.gray(`    Manifest saved: ${manifest.length} findings tracked`));
  }

  private async reportVulnerability(vuln: Vulnerability): Promise<void> {
    const title = buildImmunefiTitle(vuln);
    const slug = sanitizeTitle(title);

    let prefix = '';
    if (vuln.verificationStatus === 'contradicted') {
      prefix = 'contradicted-';
    } else if (vuln.verificationStatus === 'uncertain' || vuln.needsManualReview) {
      prefix = 'uncertain-';
    } else if (vuln.blindspotCategory && vuln.blindspotCategory !== 'none') {
      prefix = 'blindspot-';
    } else if (vuln.attackerControlled?.isControlled) {
      prefix = 'verified-';
    }

    const dirName = `${prefix}${slug}`;
    const bugDir = path.join(this.findingsDir, dirName);
    await fs.mkdir(bugDir, { recursive: true });

    const analysisPath = path.join(bugDir, 'analysis.md');
    const analysis = this.generateAnalysis(vuln, title);
    await fs.writeFile(analysisPath, analysis);

    if (vuln.poc) {
      const ext = this.getExtension(vuln.poc.language);
      const pocPath = path.join(bugDir, `poc.${ext}`);
      await fs.writeFile(pocPath, vuln.poc.code);

      const setupPath = path.join(bugDir, 'SETUP.md');
      let setup = `# Proof of Concept Setup\n\n`;
      if (vuln.poc.prerequisitesHandled) {
        setup += `## Prerequisites Analysis\n\n`;
        if (vuln.poc.prerequisitesHandled.exploitationDependencies) {
          setup += `**Exploitation Dependencies**: ${vuln.poc.prerequisitesHandled.exploitationDependencies}\n\n`;
        }
        if (vuln.poc.prerequisitesHandled.reachability) {
          setup += `**Reachability**: ${vuln.poc.prerequisitesHandled.reachability}\n\n`;
        }
        if (vuln.poc.prerequisitesHandled.attackChain) {
          setup += `**Attack Chain**: ${vuln.poc.prerequisitesHandled.attackChain}\n\n`;
        }
      }
      setup += `## Setup Instructions\n\n${vuln.poc.setupInstructions}\n\n`;
      if (vuln.poc.testSteps && vuln.poc.testSteps.length > 0) {
        setup += `## Test Steps\n\n`;
        vuln.poc.testSteps.forEach((step, i) => {
          setup += `${i + 1}. ${step}\n`;
        });
        setup += `\n`;
      }
      setup += `## Expected Impact\n\n${vuln.poc.expectedImpact}\n\n`;
      setup += `## POC Validation Status\n\n`;
      if (vuln.poc.validated === true) {
        setup += `✅ **VALIDATED** - POC has been tested and confirmed working\n\n`;
      } else if (vuln.poc.validated === false) {
        setup += `⚠️ **UNVALIDATED** - POC failed validation testing\n\n`;
        setup += `**Possible reasons**:\n`;
        setup += `- POC code needs adjustment\n`;
        setup += `- Environment/dependency mismatch\n`;
        setup += `- Bug exists but POC demonstration is incorrect\n`;
        setup += `- Bug may be a false positive (manual review required)\n\n`;
        setup += `**Action Required**: Manual testing and verification needed\n\n`;
      } else {
        setup += `⚪ **NOT TESTED** - Validation was skipped\n\n`;
      }
      await fs.writeFile(setupPath, setup);
    }

    const evidencePath = path.join(bugDir, 'evidence.json');
    await fs.writeFile(evidencePath, JSON.stringify(vuln.evidenceChain, null, 2));

    const severityColor = ['critical', 'high'].includes(vuln.severity?.toLowerCase() || '') ? chalk.red : chalk.green;
    let marker = '';
    if (vuln.verificationStatus === 'contradicted') {
      marker = '[CONTRADICTED] ';
    } else if (vuln.verificationStatus === 'uncertain' || vuln.needsManualReview) {
      marker = '[UNCERTAIN] ';
    } else if (vuln.blindspotCategory && vuln.blindspotCategory !== 'none') {
      marker = '[BLINDSPOT] ';
    } else if (vuln.attackerControlled?.isControlled) {
      marker = '[VERIFIED] ';
    }
    console.log(severityColor(`  ${marker}${vuln.id}: ${title} (${vuln.severity})`));
  }

  private generateAnalysis(vuln: Vulnerability, immunefiTitle: string): string {
    const sev = immunefiSeverity(vuln);

    // Verification status banner
    let statusBanner = '';
    if (vuln.verificationStatus === 'contradicted' || vuln.verificationStatus === 'uncertain' || vuln.needsManualReview) {
      statusBanner = `> **VERIFICATION STATUS**: ${vuln.verificationStatus?.toUpperCase() || 'NEEDS REVIEW'}\n`;
      statusBanner += `> **Confidence**: ${vuln.confidence?.toUpperCase() || 'UNKNOWN'}\n`;
      if (vuln.contradictions && vuln.contradictions.length > 0) {
        statusBanner += `> **Issues Found**:\n`;
        for (const c of vuln.contradictions) {
          statusBanner += `> - ${c}\n`;
        }
      }
      statusBanner += `> **Action Required**: Manual review recommended before reporting\n\n`;
    }

    // Build the code snippet section
    let codeSnippets = '';
    if (vuln.evidenceChain && vuln.evidenceChain.length > 0) {
      for (const ev of vuln.evidenceChain) {
        codeSnippets += `### Relevant Code at \`${ev.location}\`\n\`\`\`\n${ev.code}\n\`\`\`\n\n**Reasoning**: ${ev.reasoning}\n\n`;
      }
    }

    // Build data flow
    let dataFlowSection = '';
    if (vuln.attackerControlled?.dataFlow && vuln.attackerControlled.dataFlow.length > 0) {
      dataFlowSection += `**Data Flow Path**:\n\`\`\`\n${vuln.attackerControlled.dataFlow.map((s, i) => `${i + 1}. ${s}`).join('\n')}\n\`\`\`\n\n`;
    }

    // Build exploitation dependencies
    let depsSection = '';
    if (vuln.exploitationDependencies?.required && vuln.exploitationDependencies.required.length > 0) {
      depsSection += `**Required Prerequisites**:\n`;
      for (const dep of vuln.exploitationDependencies.required) {
        depsSection += `- [${dep.feasibility.toUpperCase()}] **${dep.type}**: ${dep.description}\n`;
      }
      depsSection += `\n`;
    }
    if (vuln.exploitationDependencies?.notes) {
      depsSection += `**Notes**: ${vuln.exploitationDependencies.notes}\n\n`;
    }

    // Build recommendation
    let recommendation = vuln.attackVector
      ? `**Root Cause**: ${vuln.description}\n\n**Attack Vector**: \`${vuln.attackVector}\`\n\n`
      : `**Root Cause**: ${vuln.description}\n\n`;
    if (vuln.evidenceChain && vuln.evidenceChain.length > 0) {
      recommendation += `**Recommended Fix**:\n`;
      recommendation += `- Address the issue at \`${vuln.location.file}:${vuln.location.line}\` in function \`${vuln.location.function}\`\n`;
      recommendation += `- Implement proper validation and access controls at the identified trust boundary\n`;
      recommendation += `- Apply defense-in-depth: add reentrancy guards, input sanitization, and explicit authorization checks\n`;
      if (vuln.evidenceChain[0]?.reasoning) {
        recommendation += `- ${vuln.evidenceChain[0].reasoning}\n`;
      }
    }

    // Build PoC section
    let pocSection = '';
    if (vuln.poc) {
      const ext = this.getExtension(vuln.poc.language);
      pocSection = `## 5. Proof of Concept (PoC)\n\n`;
      pocSection += `\`\`\`${vuln.poc.language}\n${vuln.poc.code}\n\`\`\`\n\n`;
      pocSection += `See \`SETUP.md\` in this directory for execution instructions.\n`;
      if (vuln.poc.validated === true) {
        pocSection += `\n> ✅ **POC VALIDATED** — This proof of concept has been tested and confirmed working.\n`;
      } else if (vuln.poc.validated === false) {
        pocSection += `\n> ⚠️ **POC UNVALIDATED** — This proof of concept requires manual verification.\n`;
      }
    } else {
      pocSection = `## 5. Proof of Concept (PoC)\n\nA proof of concept was not generated for this finding. See \`evidence.json\` for the evidence chain supporting this vulnerability.\n`;
    }

    // Full Recursive Analysis section (preserved as reference appendix)
    let recursiveSection = '';
    if (vuln.recursive) {
      recursiveSection = `\n---\n### Recursive Analysis Appendix\n\n`;
      recursiveSection += `**Call Chains** (depth: ${vuln.recursive.depth}):\n`;
      if (vuln.recursive.callChains?.length > 0) {
        for (const chain of vuln.recursive.callChains) {
          recursiveSection += `- \`${chain.path.join(' → ')}\` ${chain.tainted ? '(tainted)' : ''}\n`;
        }
      } else {
        recursiveSection += `No call chains found.\n`;
      }
      recursiveSection += `\n**Vulnerability Chains**:\n`;
      if (vuln.recursive.vulnerabilityChains?.length > 0) {
        for (const vc of vuln.recursive.vulnerabilityChains) {
          recursiveSection += `- \`${vc.attackPath}\` — exploitability: ${(vc.combinedExploitability * 100).toFixed(0)}%\n`;
        }
      } else {
        recursiveSection += `No vulnerability chains found.\n`;
      }
    }

    // Recursive exploitability proof appendix
    let exploitabilitySection = '';
    const proof = (vuln as any).recursiveExploitabilityProof;
    if (proof) {
      const passRate = ((proof.validationsPassed / proof.validationsTotal) * 100).toFixed(0);
      exploitabilitySection = `\n---\n### Recursive Exploitability Proof\n\n`;
      exploitabilitySection += `**Validation Score**: ${proof.validationsPassed}/${proof.validationsTotal} (${passRate}%)\n\n`;
      for (const step of proof.proofSteps) {
        exploitabilitySection += `- ${step}\n`;
      }
      exploitabilitySection += `\n`;
    }

    // ─── Immunefi 5-Section Template ──────────────────────────────

    return `# ${immunefiTitle}

${statusBanner}
## 1. Brief / Intro

${vuln.description}

On live mainnet deployment, a malicious actor exploiting this vulnerability would face **${vuln.exploitationDependencies?.directlyExploitable !== false ? 'minimal' : 'specific'} preconditions** and the consequence is **${summarizeImpact(vuln)}**. The affected component is \`${vuln.location.file}:${vuln.location.function}\` (line ${vuln.location.line}).

## 2. Vulnerability Details

### Classification

| Field | Value |
|-------|-------|
| **Type** | ${vuln.type} |
| **Location** | \`${vuln.location.file}:${vuln.location.line}\` |
| **Function** | \`${vuln.location.function}\` |
| **Severity** | **${sev.label}** |
| **Immunefi Criteria** | ${sev.criteria} |

### Step-by-Step Walkthrough

${vuln.attackVector}

${dataFlowSection}
### Code Path Analysis

${codeSnippets}
${depsSection}
## 3. Impact

**Severity**: **${sev.label}**

**Immunefi Classification**: ${sev.criteria}

**Assets at Risk**:

${this.formatAssetsAtRisk(vuln)}

**Attacker Control**: ${vuln.attackerControlled?.isControlled ? '✅ The attacker has verified control over the exploit path.' : '⚠️ Attacker control is unconfirmed or partial.'}

${vuln.impact}

### Exploitability Assessment

| Factor | Assessment |
|--------|-----------|
| **Directly Exploitable** | ${vuln.exploitationDependencies?.directlyExploitable ? 'Yes' : 'No / Conditional'} |
| **Complexity** | ${(vuln.exploitationDependencies?.complexity || 'medium').toUpperCase()} |
| **Attacker Control** | ${vuln.attackerControlled?.isControlled ? 'Verified' : 'Unverified'} |

${vuln.reachability ? `
### Reachability

- **Currently reachable**: ${vuln.reachability.isReachable ? 'Yes' : 'No'}
- **Reason**: ${vuln.reachability.reason || 'N/A'}
${vuln.reachability.couldBecomeReachable ? `- **Could become reachable**: Yes (latent bug)` : ''}
` : ''}
${exploitabilitySection}
## 4. Recommendation

${recommendation}

### Remediation Checklist

- [ ] Fix the vulnerability at \`${vuln.location.file}:${vuln.location.line}\`
- [ ] Add/verify input validation for all user-controlled parameters
- [ ] Apply the principle of least privilege on the affected function
- [ ] Add event emissions for critical state changes
- [ ] Run integration tests covering the exploit path
- [ ] Consider a bug bounty retest after the fix is deployed

${pocSection}
${recursiveSection}
---

*Report generated by Sandyaa — Immunefi-Compliant Format*
`;
  }

  private formatAssetsAtRisk(vuln: Vulnerability): string {
    const sev = vuln.severity?.toLowerCase() || 'medium';
    const impactText = vuln.impact || '';

    const hasFunds = /fund|token|ether|eth|usd|balance|treasury|pool|liquidity/i.test(impactText);
    const hasUserFunds = /user|depositor|lender|staker/i.test(impactText);
    const hasGovernance = /govern|vote|proposal|admin|owner/i.test(impactText);
    const hasDoS = /dos|denial|grief|freeze|lock/i.test(impactText);

    const assets: string[] = [];
    if (sev === 'critical' || sev === 'high') {
      if (hasFunds) {
        assets.push(hasUserFunds
          ? '**User deposits / protocol TVL** — permanent or temporary loss of user funds held in the contract'
          : '**Protocol treasury / pool funds** — direct loss of assets managed by the contract');
      }
      if (hasGovernance) {
        assets.push('**Governance control** — potential takeover of administrative functions');
      }
    }
    if (hasDoS) {
      assets.push('**Contract availability** — risk of denial-of-service or state corruption');
    }
    if (assets.length === 0) {
      if (sev === 'critical') {
        assets.push('**All protocol funds** — total loss of value');
      } else if (sev === 'high') {
        assets.push('**Significant portion of user/protocol funds** — partial loss');
      } else if (sev === 'medium') {
        assets.push('**Contract functionality** — temporary disruption or griefing');
      } else {
        assets.push('**No direct assets at risk** — informational finding');
      }
    }
    return assets.map(a => `- ${a}`).join('\n');
  }

  private getExtension(language: string): string {
    const exts: { [key: string]: string } = {
      python: 'py',
      javascript: 'js',
      bash: 'sh',
      ruby: 'rb',
      html: 'html',
      sql: 'sql',
      http: 'http',
      curl: 'sh',
      text: 'txt',
      solidity: 'sol',
      rust: 'rs',
    };
    return exts[language] || 'txt';
  }

  async generateSummary(totalBugs: number, totalFiles: number, duration: string): Promise<void> {
    await fs.mkdir(this.findingsDir, { recursive: true });

    const summaryPath = path.join(this.findingsDir, 'SUMMARY.md');
    const entries = await fs.readdir(this.findingsDir, { withFileTypes: true });

    // Read manifest for structured data
    let manifest: any[] = [];
    try {
      const manifestPath = path.join(this.findingsDir, 'MANIFEST.json');
      const manifestContent = await fs.readFile(manifestPath, 'utf-8');
      manifest = JSON.parse(manifestContent);
    } catch {
      // Fallback: scan directories
    }

    const bugDirs = entries.filter(e => e.isDirectory());
    const bugsBySeverity: Record<string, number> = {};
    const bugsByType: Record<string, number> = {};

    if (manifest.length > 0) {
      for (const m of manifest) {
        const sev = (m.severity || 'low').toLowerCase();
        bugsBySeverity[sev] = (bugsBySeverity[sev] || 0) + 1;
        const type = m.type || 'unknown';
        bugsByType[type] = (bugsByType[type] || 0) + 1;
      }
    } else {
      for (const dir of bugDirs) {
        try {
          const analysisPath = path.join(this.findingsDir, dir.name, 'analysis.md');
          const content = await fs.readFile(analysisPath, 'utf-8');
          const sevMatch = content.match(/\*\*Severity\*\*:\s*\*\*(Critical|High|Medium|Low)\*\*/i);
          if (sevMatch) {
            const sev = sevMatch[1].toLowerCase();
            bugsBySeverity[sev] = (bugsBySeverity[sev] || 0) + 1;
          }
          const typeMatch = content.match(/\*\*Type\*\*\s*\|\s*([^\n]+)/);
          if (typeMatch) {
            const type = typeMatch[1].trim();
            bugsByType[type] = (bugsByType[type] || 0) + 1;
          }
        } catch {
          // skip
        }
      }
    }

    const sevOrder = ['critical', 'high', 'medium', 'low'];
    const summary = `# Security Analysis Summary — Immunefi Report

## Overview

| Metric | Value |
|--------|-------|
| **Files Analyzed** | ${totalFiles} |
| **Findings Reported** | ${totalBugs} |
| **Analysis Duration** | ${duration} min |
| **Generated** | ${new Date().toISOString()} |

## Breakdown by Severity

| Severity | Count | Immunefi Criteria |
|----------|-------|-------------------|
${sevOrder.map(s => {
  const c = bugsBySeverity[s] || 0;
  const criteria: Record<string, string> = {
    critical: 'Permanent freezing/theft of funds',
    high: 'Temporary freezing of funds',
    medium: 'DoS or griefing',
    low: 'Best-practice violation',
  };
  return `| **${s.charAt(0).toUpperCase() + s.slice(1)}** | ${c} | ${criteria[s] || ''} |`;
}).join('\n')}

## Findings

| # | Finding | Severity | Status |
|---|---------|----------|--------|
${manifest.length > 0
  ? manifest.map((m, i) =>
      `| ${i + 1} | [${m.immunefiTitle || m.type}](./${sanitizeTitle(m.immunefiTitle || m.type)}/analysis.md) | **${(m.severity || 'N/A').toUpperCase()}** | ${m.verificationStatus || 'unverified'} |`
    ).join('\n')
  : bugDirs.map((d, i) =>
      `| ${i + 1} | [\`${d.name}\`](./${d.name}/analysis.md) | — | — |`
    ).join('\n')}

---

*Generated by Sandyaa — Immunefi-Compliant Format*
`;

    await fs.writeFile(summaryPath, summary);
    console.log(chalk.cyan('\nImmunefi summary report:'), summaryPath);
  }
}
