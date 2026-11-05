import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildGitHubRepoFiles,
  sanitizeGitHubRepoName,
  validateRepoCreationOptions,
} from './githubSyncLogic';
import { BASELINE_THREATS } from '../data/baselineThreats';

test('sanitizeGitHubRepoName normalizes spaces and special characters cleanly', () => {
  assert.equal(
    sanitizeGitHubRepoName('  Chronicle Pulse SecOps 2026! '),
    'Chronicle-Pulse-SecOps-2026'
  );
  assert.equal(sanitizeGitHubRepoName('___my_repo--name___'), '___my_repo--name___');
});

test('validateRepoCreationOptions rejects empty repo names or unselected content packages', () => {
  const badName = validateRepoCreationOptions({
    repoName: ' ',
    description: 'Test',
    isPrivate: false,
    includeAppSource: true,
    includeSecOpsRules: true,
    includeThreatIntel: true,
  });
  assert.equal(badName.valid, false);

  const noContent = validateRepoCreationOptions({
    repoName: 'secops-repo',
    description: 'Test',
    isPrivate: false,
    includeAppSource: false,
    includeSecOpsRules: false,
    includeThreatIntel: false,
  });
  assert.equal(noContent.valid, false);

  const validConfig = validateRepoCreationOptions({
    repoName: 'chronicle-pulse-secops',
    description: 'SecOps repo',
    isPrivate: true,
    includeAppSource: true,
    includeSecOpsRules: true,
    includeThreatIntel: true,
  });
  assert.equal(validConfig.valid, true);
});

test('buildGitHubRepoFiles generates README, YARA-L 2.0 rules, UDM queries, and STIX 2.1 bundle', () => {
  const files = buildGitHubRepoFiles(BASELINE_THREATS.slice(0, 3), {
    repoName: 'chronicle-pulse-secops',
    description: 'SecOps Threat Hunting Repository',
    isPrivate: false,
    includeAppSource: true,
    includeSecOpsRules: true,
    includeThreatIntel: true,
  });

  assert.ok(files.some((f) => f.path === 'README.md'));
  assert.ok(files.some((f) => f.path.startsWith('secops-rules/') && f.path.endsWith('.yaral')));
  assert.ok(files.some((f) => f.path.startsWith('secops-queries/') && f.path.endsWith('.udm')));
  assert.ok(files.some((f) => f.path === 'threat-intel/stix21-bundle.json'));
  assert.ok(files.some((f) => f.path === 'threat-intel/ADVISORIES.md'));
});
