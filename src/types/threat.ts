export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low';

export type TimeframePreset = 'all' | 'today' | '24h' | '7d' | '30d';

export interface KillChainStage {
  stage:
    | 'Initial Access'
    | 'Execution'
    | 'Persistence'
    | 'Privilege Escalation'
    | 'Defense Evasion'
    | 'Lateral Movement'
    | 'Exfiltration & Impact';
  title: string;
  description: string;
  commandOrArtifact?: string;
  mitreId?: string;
}

export interface MitreMapping {
  tactic: string;
  techniqueId: string;
  techniqueName: string;
  description: string;
}

export interface HashIndicator {
  algorithm: 'MD5' | 'SHA-1' | 'SHA-256';
  value: string;
  fileName: string;
}

export interface NetworkIndicator {
  type: 'IPv4' | 'Domain' | 'URL';
  value: string;
  context: string;
  portOrProtocol?: string;
}

export interface HostArtifact {
  type:
    | 'Registry Key'
    | 'Mutex'
    | 'File Path'
    | 'Scheduled Task'
    | 'Command Line'
    | 'Named Pipe';
  value: string;
  description: string;
}

export interface ThreatIoCs {
  hashes: HashIndicator[];
  network: NetworkIndicator[];
  hostArtifacts: HostArtifact[];
}

export interface SecOpsHuntingPack {
  udmIocQuery: string;
  udmBehavioralQuery: string;
  yaralRule: string;
  ruleName: string;
}

export interface ThreatReport {
  id: string;
  title: string;
  summary: string;
  executiveSummary: string;
  source: string;
  sourceUrl: string;
  publishedAt: string; // ISO timestamp
  isLive: boolean;
  isNew?: boolean;
  aiEnriched?: boolean;
  enrichedAt?: string;
  severity: SeverityLevel;
  cvssScore?: number;
  cveIds: string[];
  threatActor: string;
  threatType: string;
  malwareFamily: string;
  malwareCategory: string;
  targetIndustries: string[];
  targetRegions: string[];
  killChain: KillChainStage[];
  mitreAttack: MitreMapping[];
  iocs: ThreatIoCs;
  secops: SecOpsHuntingPack;
}

export interface FilterState {
  searchQuery: string;
  timeframePreset: TimeframePreset;
  month: string; // 'All' | '01' .. '12'
  year: string; // 'All' | '2024' | '2025' | '2026'
  industry: string;
  region: string;
  malwareCategory: string;
  threatType: string;
  severity: string;
  source: string;
}

export interface FeedSourceConfig {
  id: string;
  name: string;
  url: string;
  type: 'rss' | 'json';
  enabled: boolean;
  lastCount: number;
  status: 'active' | 'synced' | 'fallback';
}

export interface DashboardMetrics {
  totalActiveThreats: number;
  liveFeedsSyncedToday: number;
  criticalZeroDayCount: number;
  topTargetedIndustry: string;
  topIndustryCount: number;
  mostActiveMalware: string;
  topMalwareCount: number;
  totalExtractedIocs: number;
  volumeByTime: { label: string; critical: number; high: number; medium: number; total: number }[];
  industryBreakdown: { industry: string; count: number; percentage: number }[];
  categoryDistribution: { category: string; count: number; type: 'Malware' | 'Vulnerability' | 'Actor' }[];
}
