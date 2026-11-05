import { ThreatReport } from '../types/threat';
import {
  exportThreatAsMarkdown,
  exportThreatAsStixBundle,
} from './threatLogic';

export interface GitHubFileEntry {
  path: string;
  content: string;
  description: string;
}

export interface RepoCreationOptions {
  repoName: string;
  description: string;
  isPrivate: boolean;
  includeAppSource: boolean;
  includeSecOpsRules: boolean;
  includeThreatIntel: boolean;
}

/**
 * Sanitizes and validates a GitHub repository name.
 */
export function sanitizeGitHubRepoName(rawName: string): string {
  return rawName
    .trim()
    .replace(/[^a-zA-Z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 100);
}

export function validateRepoCreationOptions(
  options: RepoCreationOptions
): { valid: boolean; error?: string } {
  const cleaned = sanitizeGitHubRepoName(options.repoName);
  if (!cleaned || cleaned.length < 2) {
    return {
      valid: false,
      error: 'Please enter a valid GitHub repository name (at least 2 characters).',
    };
  }
  if (
    !options.includeAppSource &&
    !options.includeSecOpsRules &&
    !options.includeThreatIntel
  ) {
    return {
      valid: false,
      error: 'Select at least one content package (Application Source, SecOps Rules, or Threat Intelligence) to commit.',
    };
  }
  return { valid: true };
}

/**
 * Builds the SecOps Detection Rules, UDM Queries, STIX 2.1 Bundle, and README files
 * to be committed to a newly created GitHub repository.
 */
export function buildGitHubRepoFiles(
  threats: ThreatReport[],
  options: RepoCreationOptions
): GitHubFileEntry[] {
  const files: GitHubFileEntry[] = [];
  const safeRepoName = sanitizeGitHubRepoName(options.repoName) || 'chronicle-pulse-secops';

  // 1. Repository README.md
  const readmeContent = `# ${safeRepoName}

${options.description || 'Real-Time Threat Intelligence & Google SecOps (Chronicle) Threat Hunting Workbench & Detection Repository.'}

## Repository Structure

${options.includeAppSource ? '- \`src/\` & \`server.ts\` — Full-stack React 19 + Express + TypeScript Real-Time Threat Intelligence Workbench\n' : ''}${options.includeSecOpsRules ? '- \`secops-rules/\` — Production YARA-L 2.0 detection rules for Google SecOps (Chronicle)\n- \`secops-queries/\` — Unified Data Model (UDM) IoC Sweep & Behavioral Threat Hunting queries\n' : ''}${options.includeThreatIntel ? '- \`threat-intel/stix21-bundle.json\` — STIX 2.1 structured threat intelligence bundle\n- \`threat-intel/ADVISORIES.md\` — Full Threat Intelligence & MITRE ATT&CK Kill Chain reports\n' : ''}

## Active Threat Intelligence Summary (${threats.length} Advisories)

| ID | Threat / Advisory Title | Severity | Actor | Malware | YARA-L 2.0 Rule |
| :--- | :--- | :--- | :--- | :--- | :--- |
${threats
  .slice(0, 25)
  .map(
    (t) =>
      `| \`${t.id}\` | ${t.title.replace(/\|/g, '-')} | **${t.severity}** | ${t.threatActor} | ${t.malwareFamily} | \`${t.secops.ruleName}.yaral\` |`
  )
  .join('\n')}

## Quick Start (Local Development)

\`\`\`bash
npm install
npm run dev
\`\`\`
`;

  files.push({
    path: 'README.md',
    content: readmeContent,
    description: 'Repository overview, index of active threat advisories, and setup instructions',
  });

  // 2. Google SecOps YARA-L 2.0 Rules & UDM Hunting Queries
  if (options.includeSecOpsRules) {
    for (const threat of threats.slice(0, 15)) {
      const ruleSlug = threat.secops.ruleName || threat.id;
      files.push({
        path: `secops-rules/${ruleSlug}.yaral`,
        content: threat.secops.yaralRule,
        description: `YARA-L 2.0 detection rule for ${threat.title}`,
      });

      const udmCombined = `// ============================================================================
// Google SecOps (Chronicle) UDM Hunting Queries
// Advisory: ${threat.title}
// Severity: ${threat.severity} | Actor: ${threat.threatActor} | Malware: ${threat.malwareFamily}
// CVE References: ${threat.cveIds.join(', ') || 'N/A'}
// ============================================================================

// --- 1. UDM Multi-Surface IoC Sweep Query ---
${threat.secops.udmIocQuery}

// --- 2. UDM Behavioral / Execution Pattern Hunt Query ---
${threat.secops.udmBehavioralQuery}
`;
      files.push({
        path: `secops-queries/${ruleSlug}_hunt.udm`,
        content: udmCombined,
        description: `UDM IoC Sweep & Behavioral Hunt queries for ${threat.malwareFamily}`,
      });
    }
  }

  // 3. STIX 2.1 JSON Bundle & Markdown Advisories
  if (options.includeThreatIntel) {
    files.push({
      path: 'threat-intel/stix21-bundle.json',
      content: exportThreatAsStixBundle(threats.slice(0, 15)),
      description: 'STIX 2.1 machine-readable bundle of indicators, malware, and attack patterns',
    });

    const combinedMarkdown = threats
      .slice(0, 12)
      .map((t) => exportThreatAsMarkdown(t))
      .join('\n\n---\n\n');

    files.push({
      path: 'threat-intel/ADVISORIES.md',
      content: combinedMarkdown,
      description: 'Comprehensive Markdown documentation with Kill Chains, MITRE mappings, and IoCs',
    });
  }

  return files;
}
