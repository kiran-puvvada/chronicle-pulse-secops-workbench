import test from 'node:test';
import assert from 'node:assert/strict';
import {
  computeDashboardMetrics,
  enrichRawFeedItem,
  exportIocsAsCsv,
  exportThreatAsMarkdown,
  exportThreatAsStixBundle,
  filterThreats,
  generateSecOpsQueries,
} from './threatLogic';
import { BASELINE_THREATS } from '../data/baselineThreats';
import { FilterState } from '../types/threat';

const defaultFilters: FilterState = {
  searchQuery: '',
  timeframePreset: 'all',
  month: 'All',
  year: 'All',
  industry: 'All',
  region: 'All',
  malwareCategory: 'All',
  threatType: 'All',
  severity: 'All',
  source: 'All',
};

test('generateSecOpsQueries builds valid UDM IoC, UDM Behavioral, and YARA-L 2.0 rules', () => {
  const sample = BASELINE_THREATS[0];
  const secops = generateSecOpsQueries(sample);

  assert.ok(secops.ruleName.length > 0, 'Rule name should be generated');
  assert.ok(
    secops.udmIocQuery.includes('target.ip in ("172.104.91.214"'),
    'UDM IoC query should include target.ip'
  );
  assert.ok(
    secops.udmIocQuery.includes('network.dns.questions.name in ("wan-firmware-check-global.net")'),
    'UDM IoC query should include DNS question name'
  );
  assert.ok(
    secops.udmIocQuery.includes('target.file.sha256 in'),
    'UDM IoC query should include SHA256 hashes'
  );
  assert.ok(
    secops.udmBehavioralQuery.includes('metadata.event_type in ("PROCESS_LAUNCH"'),
    'UDM behavioral query should hunt PROCESS_LAUNCH events'
  );
  assert.ok(
    secops.yaralRule.includes(`rule ${secops.ruleName} {`),
    'YARA-L 2.0 rule header should match ruleName'
  );
  assert.ok(
    secops.yaralRule.includes('meta:') &&
      secops.yaralRule.includes('events:') &&
      secops.yaralRule.includes('match:') &&
      secops.yaralRule.includes('outcome:') &&
      secops.yaralRule.includes('condition:'),
    'YARA-L 2.0 rule must contain all 5 required sections'
  );
});

test('enrichRawFeedItem parses raw RSS / CISA KEV items into structured ThreatReport', () => {
  const raw = {
    title: 'Critical LockBit Ransomware Exploits CVE-2026-9911 in Healthcare & Banking Networks in India',
    description:
      'Researchers observed active exploitation of CVE-2026-9911 connecting to 198.51.100.44 and dropping LockBit encryptors across APAC hospitals.',
    link: 'https://thehackernews.com/2026/11/lockbit-cve-2026-9911.html',
    pubDate: new Date().toISOString(),
    source: 'The Hacker News',
  };

  const enriched = enrichRawFeedItem(raw);

  assert.equal(enriched.severity, 'Critical');
  assert.ok(enriched.cveIds.includes('CVE-2026-9911'));
  assert.equal(enriched.malwareCategory, 'Ransomware');
  assert.equal(enriched.malwareFamily, 'LockBit');
  assert.ok(enriched.targetIndustries.includes('Healthcare'));
  assert.ok(enriched.targetIndustries.includes('Finance/BFSI'));
  assert.ok(enriched.targetRegions.includes('APAC'));
  assert.equal(enriched.killChain.length, 7, 'Must generate all 7 Kill Chain stages');
  assert.ok(
    enriched.iocs.network.some((n) => n.value === '198.51.100.44'),
    'Should extract inline IPv4 indicator from description'
  );
  assert.ok(enriched.secops.yaralRule.includes('CVE-2026-9911'));
});

test('filterThreats filters across Industry, Region, Malware, Actor, Year, and Instant Search', () => {
  // Filter by Industry: Healthcare
  const healthcareOnly = filterThreats(BASELINE_THREATS, {
    ...defaultFilters,
    industry: 'Healthcare',
  });
  assert.ok(healthcareOnly.length >= 2);
  assert.ok(healthcareOnly.every((t) => t.targetIndustries.includes('Healthcare')));

  // Filter by Malware Category / Family: LockBit
  const lockbitOnly = filterThreats(BASELINE_THREATS, {
    ...defaultFilters,
    malwareCategory: 'LockBit',
  });
  assert.equal(lockbitOnly.length, 1);
  assert.equal(lockbitOnly[0].id, 'ti-2026-002');

  // Filter by Threat Actor: Volt Typhoon
  const voltOnly = filterThreats(BASELINE_THREATS, {
    ...defaultFilters,
    threatType: 'Volt Typhoon',
  });
  assert.equal(voltOnly.length, 1);
  assert.equal(voltOnly[0].threatActor, 'Volt Typhoon');

  // Filter by Instant Search on MITRE ID or CVE
  const mitreSearch = filterThreats(BASELINE_THREATS, {
    ...defaultFilters,
    searchQuery: 'T1195.001',
  });
  assert.equal(mitreSearch.length, 1);
  assert.equal(mitreSearch[0].threatActor, 'Lazarus');

  // Filter by Year: 2024
  const year2024 = filterThreats(BASELINE_THREATS, {
    ...defaultFilters,
    year: '2024',
  });
  assert.equal(year2024.length, 1);
  assert.equal(year2024[0].id, 'ti-2024-008');
});

test('computeDashboardMetrics calculates accurate KPI counts and chart series', () => {
  const metrics = computeDashboardMetrics(BASELINE_THREATS, BASELINE_THREATS);

  assert.equal(metrics.totalActiveThreats, BASELINE_THREATS.length);
  assert.ok(metrics.liveFeedsSyncedToday >= 3);
  assert.ok(metrics.totalExtractedIocs > 30);
  assert.ok(metrics.industryBreakdown.length > 0);
  assert.ok(metrics.categoryDistribution.length > 0);
});

test('export formatters generate valid Markdown, STIX 2.1 JSON Bundle, and CSV IoCs', () => {
  const sample = BASELINE_THREATS[0];

  const md = exportThreatAsMarkdown(sample);
  assert.ok(md.includes('# Threat Intelligence & SecOps Hunting Report'));
  assert.ok(md.includes(sample.secops.yaralRule));

  const stixJson = exportThreatAsStixBundle(sample);
  const parsedStix = JSON.parse(stixJson);
  assert.equal(parsedStix.type, 'bundle');
  assert.equal(parsedStix.spec_version, '2.1');
  assert.ok(Array.isArray(parsedStix.objects));
  assert.ok(parsedStix.objects.some((o: { type: string }) => o.type === 'indicator'));
  assert.ok(parsedStix.objects.some((o: { type: string }) => o.type === 'report'));

  const csv = exportIocsAsCsv(sample);
  assert.ok(csv.startsWith('Category,Indicator_Type,Indicator_Value'));
  assert.ok(csv.includes('172.104.91.214'));
});
