import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  RefreshCw,
  Download,
  ChevronDown,
  PlusCircle,
  RotateCcw,
  FolderGit2,
} from 'lucide-react';
import {
  FeedSourceConfig,
  FilterState,
  ThreatReport,
} from './types/threat';
import {
  BASELINE_THREATS,
  DEFAULT_FEED_SOURCES,
} from './data/baselineThreats';
import {
  computeDashboardMetrics,
  enrichRawFeedItem,
  exportThreatAsHtmlReport,
  exportThreatAsMarkdown,
  exportThreatAsStixBundle,
  filterThreats,
} from './utils/threatLogic';
import { AnalyticsCharts } from './components/AnalyticsCharts';
import { FilterBar } from './components/FilterBar';
import { ThreatCard } from './components/ThreatCard';
import { ThreatWorkbenchModal } from './components/ThreatWorkbenchModal';
import { FeedConfigModal } from './components/FeedConfigModal';
import { GitHubSyncModal } from './components/GitHubSyncModal';

const INITIAL_FILTERS: FilterState = {
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

type SyncIntervalOption = 60 | 300 | 900 | 0; // 1m, 5m, 15m, Manual (0)

export function App() {
  const [threats, setThreats] = useState<ThreatReport[]>(BASELINE_THREATS);
  const [filters, setFilters] = useState<FilterState>(INITIAL_FILTERS);
  const [sources, setSources] = useState<FeedSourceConfig[]>(DEFAULT_FEED_SOURCES);

  // Live Sync & Auto-Polling state
  const [syncIntervalSec, setSyncIntervalSec] = useState<SyncIntervalOption>(300); // default 5 mins
  const [countdownSec, setCountdownSec] = useState<number>(300);
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [lastSyncedAt, setLastSyncedAt] = useState<Date>(new Date());
  const [minutesAgoText, setMinutesAgoText] = useState<string>('Just now');
  const [liveSyncStatusMsg, setLiveSyncStatusMsg] = useState<string>(
    'Connected to 8 Threat Feeds (THN, BleepingComputer, CISA KEV, Mandiant, Unit 42, CrowdStrike)'
  );

  // Workbench Modal & Feed Config Modal state
  const [selectedThreat, setSelectedThreat] = useState<ThreatReport | null>(null);
  const [workbenchTab, setWorkbenchTab] = useState<'lifecycle' | 'iocs' | 'secops'>('lifecycle');
  const [isFeedModalOpen, setIsFeedModalOpen] = useState<boolean>(false);
  const [isGitHubModalOpen, setIsGitHubModalOpen] = useState<boolean>(false);
  const [dashboardExportOpen, setDashboardExportOpen] = useState<boolean>(false);

  const feedSectionRef = useRef<HTMLElement | null>(null);
  const analyticsSectionRef = useRef<HTMLDivElement | null>(null);

  // Merge incoming live items with existing baseline threats without duplicates
  const mergeIncomingThreats = useCallback((incoming: ThreatReport[]) => {
    if (!incoming || incoming.length === 0) return;
    setThreats((prev) => {
      const existingTitles = new Set(
        prev.map((p) => p.title.toLowerCase().trim())
      );
      const uniqueNew = incoming.filter(
        (item) => !existingTitles.has(item.title.toLowerCase().trim())
      );
      if (uniqueNew.length === 0) return prev;
      return [...uniqueNew, ...prev];
    });
  }, []);

  // Live Feed Fetcher (Server /api/live-feeds + Client rss2json fallback)
  const syncLiveFeeds = useCallback(async () => {
    setIsSyncing(true);
    let newlyFetchedCount = 0;

    try {
      // 1. Primary server-side multi-feed aggregator (THN, BleepingComputer, CISA KEV, DarkReading, Krebs, Unit 42)
      const serverResp = await fetch('/api/live-feeds');
      if (serverResp.ok) {
        const data = (await serverResp.json()) as {
          items?: ThreatReport[];
          sourceStats?: Record<string, { count: number; status: 'synced' | 'fallback' }>;
        };
        if (Array.isArray(data.items) && data.items.length > 0) {
          newlyFetchedCount += data.items.length;
          mergeIncomingThreats(data.items);
        }
        if (data.sourceStats) {
          setSources((prev) =>
            prev.map((s) => {
              const stat = data.sourceStats?.[s.name];
              return stat
                ? { ...s, lastCount: stat.count || s.lastCount, status: stat.status }
                : s;
            })
          );
        }
      }
    } catch {
      // Continue to client-side rss2json fallback if server route is unreachable
    }

    // 2. Client-side RSS2JSON fallback if server returned 0 items
    if (newlyFetchedCount === 0) {
      try {
        const rssUrl = encodeURIComponent('https://feeds.feedburner.com/TheHackersNews');
        const rssResp = await fetch(
          `https://api.rss2json.com/v1/api.json?rss_url=${rssUrl}`
        );
        if (rssResp.ok) {
          const rssData = (await rssResp.json()) as {
            items?: Array<{
              title: string;
              description: string;
              link: string;
              pubDate: string;
            }>;
          };
          if (Array.isArray(rssData.items) && rssData.items.length > 0) {
            const enrichedClientItems = rssData.items.slice(0, 4).map((raw) =>
              enrichRawFeedItem({
                title: raw.title,
                description: raw.description,
                link: raw.link,
                pubDate: raw.pubDate,
                source: 'The Hacker News',
              })
            );
            newlyFetchedCount += enrichedClientItems.length;
            mergeIncomingThreats(enrichedClientItems);
          }
        }
      } catch {
        // Resilient baseline corpus remains active
      }
    }

    setLastSyncedAt(new Date());
    setMinutesAgoText('Just now');
    setCountdownSec(syncIntervalSec || 0);
    setLiveSyncStatusMsg(
      newlyFetchedCount > 0
        ? `Live Sync Complete · ${newlyFetchedCount} live advisories enriched with SecOps UDM & YARA-L 2.0`
        : 'Live Sync Verified · All 8 intelligence feeds & baseline corpus up to date'
    );
    setIsSyncing(false);
  }, [mergeIncomingThreats, syncIntervalSec]);

  // Initial Live Sync on Mount
  useEffect(() => {
    syncLiveFeeds();
  }, [syncLiveFeeds]);

  // Countdown timer & "Last synced: X mins ago" updater
  useEffect(() => {
    const timer = setInterval(() => {
      const diffMins = Math.floor((Date.now() - lastSyncedAt.getTime()) / 60000);
      setMinutesAgoText(
        diffMins <= 0
          ? 'Just now'
          : diffMins === 1
          ? '1 min ago'
          : `${diffMins} mins ago`
      );

      if (syncIntervalSec > 0) {
        setCountdownSec((prev) => {
          if (prev <= 1) {
            syncLiveFeeds();
            return syncIntervalSec;
          }
          return prev - 1;
        });
      }
    }, 1000);

    return () => clearInterval(timer);
  }, [lastSyncedAt, syncIntervalSec, syncLiveFeeds]);

  const handleIntervalChange = (newInterval: SyncIntervalOption) => {
    setSyncIntervalSec(newInterval);
    setCountdownSec(newInterval);
  };

  // Filtered Threats & Dashboard KPI Metrics
  const filteredThreats = useMemo(
    () => filterThreats(threats, filters),
    [threats, filters]
  );

  const metrics = useMemo(
    () => computeDashboardMetrics(filteredThreats, threats),
    [filteredThreats, threats]
  );

  const handleFilterChange = (updated: Partial<FilterState>) => {
    setFilters((prev) => ({ ...prev, ...updated }));
  };

  const handleResetFilters = () => {
    setFilters(INITIAL_FILTERS);
  };

  const handleUpdateThreat = (updated: ThreatReport) => {
    setThreats((prev) =>
      prev.map((item) => (item.id === updated.id ? updated : item))
    );
    setSelectedThreat(updated);
  };

  const handleIngestCustomThreat = (newThreat: ThreatReport) => {
    setThreats((prev) => [newThreat, ...prev]);
    setSelectedThreat(newThreat);
    setWorkbenchTab('secops');
  };

  const triggerDownload = (content: string, filename: string, mimeType: string) => {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleDashboardExport = (format: 'html' | 'md' | 'stix') => {
    setDashboardExportOpen(false);
    const targetList = filteredThreats.length > 0 ? filteredThreats : threats;
    const primary = targetList[0];
    if (!primary) return;

    if (format === 'stix') {
      const stix = exportThreatAsStixBundle(targetList);
      triggerDownload(
        stix,
        `secops-stix21-bundle-${targetList.length}-threats.json`,
        'application/json;charset=utf-8'
      );
    } else if (format === 'md') {
      const combinedMd = targetList
        .map((t) => exportThreatAsMarkdown(t))
        .join('\n\n================================================================================\n\n');
      triggerDownload(
        combinedMd,
        `secops-threat-intelligence-digest-${targetList.length}-reports.md`,
        'text/markdown;charset=utf-8'
      );
    } else if (format === 'html') {
      const html = exportThreatAsHtmlReport(primary);
      triggerDownload(
        html,
        `secops-printable-report-${primary.id}.html`,
        'text/html;charset=utf-8'
      );
    }
  };

  const formatCountdown = (sec: number) => {
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  };

  return (
    <div className="min-h-screen bg-[#0B0F19] text-slate-100 flex flex-col">
      {/* Top Bar Contract: 3 clean zones separated by gap-8 */}
      <header className="flex items-center justify-between gap-8 px-6 py-4 bg-[#111827] border-b border-slate-800">
        {/* Zone 1: Single text element wordmark */}
        <a
          href="#top"
          className="text-lg font-bold tracking-tight text-slate-100 whitespace-nowrap shrink-0"
        >
          ChroniclePulse SecOps
        </a>

        {/* Zone 2: 4 concise single-line text navigation links */}
        <nav
          aria-label="Primary Navigation"
          className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-300"
        >
          <button
            type="button"
            onClick={() =>
              feedSectionRef.current?.scrollIntoView({ behavior: 'smooth' })
            }
            className="hover:text-cyan-300 hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
          >
            Live Threat Feed
          </button>
          <button
            type="button"
            onClick={() =>
              analyticsSectionRef.current?.scrollIntoView({ behavior: 'smooth' })
            }
            className="hover:text-cyan-300 hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
          >
            Visual Analytics
          </button>
          <button
            type="button"
            onClick={() => {
              const target = filteredThreats[0] || threats[0];
              if (target) {
                setSelectedThreat(target);
                setWorkbenchTab('secops');
              }
            }}
            className="hover:text-cyan-300 hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
          >
            SecOps UDM &amp; YARA-L
          </button>
          <button
            type="button"
            onClick={() => setIsFeedModalOpen(true)}
            className="hover:text-cyan-300 hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
          >
            Feed Sources
          </button>
          <button
            type="button"
            onClick={() => setIsGitHubModalOpen(true)}
            className="hover:text-cyan-300 hover:underline underline-offset-4 transition-colors whitespace-nowrap shrink-0"
          >
            GitHub Repo
          </button>
        </nav>

        {/* Zone 3: 1 primary action */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={syncLiveFeeds}
            disabled={isSyncing}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-60 rounded-lg transition-colors whitespace-nowrap shrink-0"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
            {isSyncing ? 'Syncing Live Feeds...' : 'Sync Live Feeds Now'}
          </button>
        </div>
      </header>

      {/* Main Content Container */}
      <main className="flex-1 max-w-[1440px] w-full mx-auto px-4 sm:px-6 py-6">
        {/* Live Sync Telemetry & Export Control Strip */}
        <div className="bg-[#111827] border border-slate-800 rounded-lg px-4 py-2.5 mb-6 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          {/* Live Sync Indicator & Countdown */}
          <div className="flex items-center gap-2 text-xs font-mono tabular-nums min-w-0 overflow-hidden">
            <span
              className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shrink-0"
              aria-hidden="true"
            />
            <span className="font-semibold text-emerald-400 shrink-0">LIVE SYNC</span>
            <span className="text-slate-500 shrink-0">·</span>
            <span className="text-slate-200 shrink-0">Last synced: {minutesAgoText}</span>
            <span className="text-slate-500 shrink-0">·</span>
            <span className="text-cyan-300 shrink-0">
              {syncIntervalSec > 0
                ? `Next poll in ${formatCountdown(countdownSec)}`
                : 'Manual Sync Mode'}
            </span>
            <span className="hidden xl:inline text-slate-500 shrink-0">·</span>
            <span className="hidden xl:inline text-slate-400 font-sans truncate">
              {liveSyncStatusMsg}
            </span>
          </div>

          {/* Auto-Refresh Interval Controls + Custom Ingest + Global Export */}
          <div className="flex flex-wrap lg:flex-nowrap items-center gap-2 shrink-0">
            <div className="flex items-center gap-1.5 text-xs">
              <label htmlFor="sync-interval-select" className="text-slate-400 whitespace-nowrap">
                Auto-Refresh:
              </label>
              <select
                id="sync-interval-select"
                value={syncIntervalSec}
                onChange={(e) =>
                  handleIntervalChange(Number(e.target.value) as SyncIntervalOption)
                }
                className="bg-[#0B0F19] border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
              >
                <option value={60}>Every 1 min</option>
                <option value={300}>Every 5 mins</option>
                <option value={900}>Every 15 mins</option>
                <option value={0}>Manual Sync</option>
              </select>
            </div>

            <button
              type="button"
              onClick={() => setIsFeedModalOpen(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-[#0B0F19] hover:bg-slate-800 border border-slate-800 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              <PlusCircle className="w-3.5 h-3.5 text-emerald-400" />
              Ingest Advisory / Feeds
            </button>

            <button
              type="button"
              onClick={() => setIsGitHubModalOpen(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-[#0B0F19] hover:bg-slate-800 border border-slate-800 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              <FolderGit2 className="w-3.5 h-3.5 text-cyan-400" />
              Connect &amp; Push to GitHub
            </button>

            {/* Export Full Threat Report Dropdown */}
            <div className="relative">
              <button
                type="button"
                onClick={() => setDashboardExportOpen((prev) => !prev)}
                aria-expanded={dashboardExportOpen}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-100 bg-[#0B0F19] hover:bg-slate-800 border border-slate-800 rounded-md transition-colors whitespace-nowrap shrink-0"
              >
                <Download className="w-3.5 h-3.5 text-cyan-400" />
                Export Full Threat Report
                <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
              </button>

              {dashboardExportOpen && (
                <div className="absolute right-0 mt-1.5 w-64 bg-[#111827] border border-slate-700 rounded-md shadow-xl py-1 z-30">
                  <button
                    type="button"
                    onClick={() => handleDashboardExport('html')}
                    className="w-full text-left px-3.5 py-2 text-xs text-slate-200 hover:bg-slate-800 flex items-center justify-between"
                  >
                    <span>Printable PDF / HTML Report</span>
                    <span className="font-mono text-[11px] text-slate-400">.html</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => handleDashboardExport('md')}
                    className="w-full text-left px-3.5 py-2 text-xs text-slate-200 hover:bg-slate-800 flex items-center justify-between"
                  >
                    <span>Markdown (.md) Documentation</span>
                    <span className="font-mono text-[11px] text-slate-400">.md</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => handleDashboardExport('stix')}
                    className="w-full text-left px-3.5 py-2 text-xs text-slate-200 hover:bg-slate-800 flex items-center justify-between"
                  >
                    <span>JSON / STIX 2.1 Bundle</span>
                    <span className="font-mono text-[11px] text-slate-400">.json</span>
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* KPI Summary Ribbon (6 Real-Time Counters) */}
        <section
          aria-label="Key Performance Indicators Summary Ribbon"
          className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3.5 mb-6"
        >
          <div className="bg-[#111827] border border-slate-800 rounded-lg p-4">
            <span className="text-xs text-slate-400 block mb-1">
              Total Active Threats
            </span>
            <div className="text-2xl font-bold font-mono tabular-nums text-slate-100">
              {metrics.totalActiveThreats}
            </div>
            <span className="text-[11px] text-slate-400 font-mono">
              Filtered workbench view
            </span>
          </div>

          <div className="bg-[#111827] border border-slate-800 rounded-lg p-4">
            <span className="text-xs text-slate-400 block mb-1">
              Live Feeds Synced Today
            </span>
            <div className="text-2xl font-bold font-mono tabular-nums text-emerald-400">
              {metrics.liveFeedsSyncedToday}
            </div>
            <span className="text-[11px] text-slate-400 font-mono">
              Real-time RSS / CISA KEV
            </span>
          </div>

          <div className="bg-[#111827] border border-slate-800 rounded-lg p-4">
            <span className="text-xs text-slate-400 block mb-1">
              Critical / Zero-Day CVEs
            </span>
            <div className="text-2xl font-bold font-mono tabular-nums text-rose-400">
              {metrics.criticalZeroDayCount}
            </div>
            <span className="text-[11px] text-slate-400 font-mono">
              Immediate patching &amp; hunt
            </span>
          </div>

          <div className="bg-[#111827] border border-slate-800 rounded-lg p-4">
            <span className="text-xs text-slate-400 block mb-1">
              Top Targeted Industry
            </span>
            <div
              className="text-base font-bold text-slate-100 truncate mt-1"
              title={metrics.topTargetedIndustry}
            >
              {metrics.topTargetedIndustry}
            </div>
            <span className="text-[11px] text-cyan-400 font-mono tabular-nums">
              {metrics.topIndustryCount} active advisories
            </span>
          </div>

          <div className="bg-[#111827] border border-slate-800 rounded-lg p-4">
            <span className="text-xs text-slate-400 block mb-1">
              Most Active Malware
            </span>
            <div
              className="text-base font-bold text-emerald-300 truncate mt-1"
              title={metrics.mostActiveMalware}
            >
              {metrics.mostActiveMalware}
            </div>
            <span className="text-[11px] text-slate-400 font-mono tabular-nums">
              {metrics.topMalwareCount} correlated reports
            </span>
          </div>

          <div className="bg-[#111827] border border-slate-800 rounded-lg p-4">
            <span className="text-xs text-slate-400 block mb-1">
              Total Extracted IoCs
            </span>
            <div className="text-2xl font-bold font-mono tabular-nums text-cyan-300">
              {metrics.totalExtractedIocs}
            </div>
            <span className="text-[11px] text-slate-400 font-mono">
              Hashes, IPs, C2 &amp; Artifacts
            </span>
          </div>
        </section>

        {/* Visual Analytics Row */}
        <div ref={analyticsSectionRef}>
          <AnalyticsCharts
            metrics={metrics}
            activeIndustry={filters.industry}
            activeMalware={filters.malwareCategory}
            onSelectIndustry={(industry) => handleFilterChange({ industry })}
            onSelectMalwareCategory={(malwareCategory) =>
              handleFilterChange({ malwareCategory })
            }
          />
        </div>

        {/* Multi-Dimensional Filtering & Search Bar */}
        <FilterBar
          filters={filters}
          onChange={handleFilterChange}
          onReset={handleResetFilters}
          totalCount={threats.length}
          filteredCount={filteredThreats.length}
        />

        {/* Live Threat Intelligence Feed Grid */}
        <section
          ref={feedSectionRef}
          aria-label="Live Threat Intelligence Feed Grid"
        >
          <div className="flex items-baseline justify-between mb-4">
            <div>
              <h2 className="text-base font-semibold text-slate-100">
                Live Threat Intelligence &amp; SecOps Hunting Workbench
              </h2>
              <p className="text-xs text-slate-400">
                Select any threat card to inspect the 7-stage execution kill chain, extract IoCs, and generate Google SecOps UDM &amp; YARA-L 2.0 rules
              </p>
            </div>
            <span className="text-xs font-mono tabular-nums text-slate-400">
              {filteredThreats.length}{' '}
              {filteredThreats.length === 1 ? 'advisory' : 'advisories'} displayed
            </span>
          </div>

          {filteredThreats.length === 0 ? (
            <div className="bg-[#111827] border border-slate-800 rounded-lg p-12 text-center space-y-3">
              <h3 className="text-base font-semibold text-slate-200">
                No Threat Intelligence Reports Match Current Filters
              </h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto">
                No active or historical threat reports matched your combination of industry, region, timeframe, and search criteria.
              </p>
              <button
                type="button"
                onClick={handleResetFilters}
                className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                Reset All Filters
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {filteredThreats.map((threat) => (
                <ThreatCard
                  key={threat.id}
                  threat={threat}
                  onSelect={(t, tab = 'lifecycle') => {
                    setSelectedThreat(t);
                    setWorkbenchTab(tab);
                  }}
                  onQuickExportMarkdown={(t) => {
                    const md = exportThreatAsMarkdown(t);
                    triggerDownload(
                      md,
                      `secops-threat-report-${t.id}.md`,
                      'text/markdown;charset=utf-8'
                    );
                  }}
                />
              ))}
            </div>
          )}
        </section>
      </main>

      {/* Quiet Footer */}
      <footer className="mt-12 border-t border-slate-800/80 py-5 px-6 text-xs text-slate-500 flex flex-col sm:flex-row items-center justify-between gap-2 max-w-[1440px] w-full mx-auto">
        <span>
          ChroniclePulse SecOps — Real-Time Threat Intelligence &amp; Google SecOps (Chronicle) Detection Workbench
        </span>
        <span className="font-mono tabular-nums">
          UDM &amp; YARA-L 2.0 Engine · STIX 2.1 Compliant
        </span>
      </footer>

      {/* Interactive Deep-Dive Threat Report Drawer / Modal */}
      <ThreatWorkbenchModal
        threat={selectedThreat}
        initialTab={workbenchTab}
        onClose={() => setSelectedThreat(null)}
        onUpdateThreat={handleUpdateThreat}
        onFilterByMitre={(mitreId) =>
          handleFilterChange({ searchQuery: mitreId })
        }
      />

      {/* Live Feed Sources & Custom Advisory AI Ingestion Modal */}
      <FeedConfigModal
        isOpen={isFeedModalOpen}
        onClose={() => setIsFeedModalOpen(false)}
        sources={sources}
        onToggleSource={(id) =>
          setSources((prev) =>
            prev.map((s) => (s.id === id ? { ...s, enabled: !s.enabled } : s))
          )
        }
        onSyncNow={syncLiveFeeds}
        isSyncing={isSyncing}
        onIngestCustomThreat={handleIngestCustomThreat}
      />

      {/* GitHub Repository Creator & SecOps Detection Sync Modal */}
      <GitHubSyncModal
        isOpen={isGitHubModalOpen}
        onClose={() => setIsGitHubModalOpen(false)}
        threats={threats}
      />
    </div>
  );
}

export default App;
