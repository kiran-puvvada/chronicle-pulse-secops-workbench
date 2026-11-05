import React from 'react';
import { Search, RotateCcw, SlidersHorizontal } from 'lucide-react';
import { FilterState, TimeframePreset } from '../types/threat';

interface FilterBarProps {
  filters: FilterState;
  onChange: (updated: Partial<FilterState>) => void;
  onReset: () => void;
  totalCount: number;
  filteredCount: number;
}

const TIMEFRAME_PRESETS: { id: TimeframePreset; label: string }[] = [
  { id: 'all', label: 'All Time' },
  { id: 'today', label: 'Live / Today' },
  { id: '24h', label: 'Last 24 Hours' },
  { id: '7d', label: 'Last 7 Days' },
  { id: '30d', label: 'Last 30 Days' },
];

const MONTHS = [
  { value: 'All', label: 'All Months' },
  { value: '01', label: 'Jan' },
  { value: '02', label: 'Feb' },
  { value: '03', label: 'Mar' },
  { value: '04', label: 'Apr' },
  { value: '05', label: 'May' },
  { value: '06', label: 'Jun' },
  { value: '07', label: 'Jul' },
  { value: '08', label: 'Aug' },
  { value: '09', label: 'Sep' },
  { value: '10', label: 'Oct' },
  { value: '11', label: 'Nov' },
  { value: '12', label: 'Dec' },
];

const YEARS = ['All', '2026', '2025', '2024'];

const INDUSTRIES = [
  'All',
  'Finance/BFSI',
  'Healthcare',
  'Technology/SaaS',
  'Government',
  'Critical Infrastructure/Energy',
  'Telecom',
  'Retail',
  'Manufacturing',
];

const REGIONS = [
  'All',
  'Global',
  'APAC',
  'North America',
  'Europe',
  'Middle East',
  'LATAM',
];

const MALWARE_OPTIONS = [
  { value: 'All', label: 'All Malware & Exploits' },
  { value: 'Ransomware', label: 'Ransomware (All)' },
  { value: 'LockBit', label: 'Ransomware: LockBit' },
  { value: 'BlackCat', label: 'Ransomware: BlackCat / ALPHV' },
  { value: 'Akira', label: 'Ransomware: Akira' },
  { value: 'RansomHub', label: 'Ransomware: RansomHub' },
  { value: 'InfoStealers', label: 'InfoStealers (All)' },
  { value: 'Lumma Stealer', label: 'InfoStealer: Lumma' },
  { value: 'RedLine', label: 'InfoStealer: RedLine' },
  { value: 'Vidar', label: 'InfoStealer: Vidar' },
  { value: 'RATs', label: 'RATs (AsyncRAT / Cobalt Strike)' },
  { value: 'Botnets', label: 'Botnets (KV-Botnet / Mirai)' },
  { value: 'Loaders', label: 'Loaders (BeaverTail / Latrodectus)' },
  { value: 'Wipers', label: 'Wipers (AcidPour / Destructive)' },
];

const THREAT_TYPES_ACTORS = [
  { value: 'All', label: 'All Actors & Threat Types' },
  { value: 'APT Groups', label: 'APT Groups (All State-Nexus)' },
  { value: 'Volt Typhoon', label: 'APT: Volt Typhoon' },
  { value: 'APT29', label: 'APT: APT29 (Midnight Blizzard)' },
  { value: 'Lazarus', label: 'APT: Lazarus Group' },
  { value: 'APT41', label: 'APT: APT41' },
  { value: 'Zero-Day Exploits', label: 'Zero-Day Exploits / CISA KEV' },
  { value: 'Supply Chain Attacks', label: 'Supply Chain Attacks' },
  { value: 'Phishing/BEC', label: 'Phishing / BEC / ClickFix' },
  { value: 'Cloud/Identity Attacks', label: 'Cloud / Identity Attacks' },
];

export const FilterBar: React.FC<FilterBarProps> = ({
  filters,
  onChange,
  onReset,
  totalCount,
  filteredCount,
}) => {
  const hasActiveFilters =
    filters.searchQuery.trim() !== '' ||
    filters.timeframePreset !== 'all' ||
    filters.month !== 'All' ||
    filters.year !== 'All' ||
    filters.industry !== 'All' ||
    filters.region !== 'All' ||
    filters.malwareCategory !== 'All' ||
    filters.threatType !== 'All' ||
    filters.severity !== 'All' ||
    filters.source !== 'All';

  return (
    <section
      aria-label="Multi-Dimensional Threat Intelligence Filters"
      className="bg-[#111827] border border-slate-800 rounded-lg p-4 mb-6 space-y-3.5"
    >
      {/* Top Row: Instant Search + Timeframe Presets + Reset */}
      <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3">
        {/* Instant Search Input */}
        <div className="relative flex-1 min-w-[260px]">
          <label htmlFor="threat-instant-search" className="sr-only">
            Search threats by title, CVE ID, Threat Actor, Malware, IoC, or MITRE ID
          </label>
          <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            id="threat-instant-search"
            type="search"
            value={filters.searchQuery}
            onChange={(e) => onChange({ searchQuery: e.target.value })}
            placeholder="Instant search across CVE IDs (e.g. CVE-2026-21409), Threat Actors, Malware, IoCs, or MITRE IDs (T1190)..."
            className="w-full bg-[#0B0F19] border border-slate-800 focus:border-cyan-500 focus:outline-none rounded-md pl-10 pr-4 py-2 text-xs text-slate-100 placeholder:text-slate-500 font-mono"
          />
        </div>

        {/* Timeframe Quick Presets */}
        <div
          role="group"
          aria-label="Timeframe Presets"
          className="flex items-center gap-1 bg-[#0B0F19] border border-slate-800 p-1 rounded-md overflow-x-auto"
        >
          {TIMEFRAME_PRESETS.map((preset) => {
            const active = filters.timeframePreset === preset.id;
            return (
              <button
                key={preset.id}
                type="button"
                onClick={() =>
                  onChange({
                    timeframePreset: preset.id,
                    ...(preset.id !== 'all' ? { month: 'All', year: 'All' } : {}),
                  })
                }
                className={`px-2.5 py-1.5 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                  active
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {preset.label}
              </button>
            );
          })}
        </div>

        {/* Filter Status & Reset */}
        <div className="flex items-center justify-between lg:justify-end gap-3 shrink-0">
          <span className="text-xs text-slate-400 font-mono tabular-nums whitespace-nowrap">
            Showing <strong className="text-slate-100">{filteredCount}</strong> of {totalCount}
          </span>
          {hasActiveFilters && (
            <button
              type="button"
              onClick={onReset}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-rose-300 bg-rose-950/40 border border-rose-800/60 rounded-md hover:bg-rose-900/50 transition-colors whitespace-nowrap shrink-0"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Reset Filters
            </button>
          )}
        </div>
      </div>

      {/* Bottom Row: 7 Multi-Dimensional Dropdown Selectors */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-7 gap-2.5 pt-2 border-t border-slate-800/70">
        {/* Industry */}
        <div>
          <label
            htmlFor="filter-industry"
            className="block text-[11px] font-medium text-slate-400 mb-1"
          >
            Target Industry
          </label>
          <select
            id="filter-industry"
            value={filters.industry}
            onChange={(e) => onChange({ industry: e.target.value })}
            className="w-full bg-[#0B0F19] border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
          >
            {INDUSTRIES.map((ind) => (
              <option key={ind} value={ind}>
                {ind === 'All' ? 'All Industries' : ind}
              </option>
            ))}
          </select>
        </div>

        {/* Region */}
        <div>
          <label
            htmlFor="filter-region"
            className="block text-[11px] font-medium text-slate-400 mb-1"
          >
            Target Region
          </label>
          <select
            id="filter-region"
            value={filters.region}
            onChange={(e) => onChange({ region: e.target.value })}
            className="w-full bg-[#0B0F19] border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
          >
            {REGIONS.map((reg) => (
              <option key={reg} value={reg}>
                {reg === 'All' ? 'All Regions' : reg}
              </option>
            ))}
          </select>
        </div>

        {/* Malware Category / Family */}
        <div>
          <label
            htmlFor="filter-malware"
            className="block text-[11px] font-medium text-slate-400 mb-1"
          >
            Malware Family
          </label>
          <select
            id="filter-malware"
            value={filters.malwareCategory}
            onChange={(e) => onChange({ malwareCategory: e.target.value })}
            className="w-full bg-[#0B0F19] border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
          >
            {MALWARE_OPTIONS.map((m) => (
              <option key={m.value} value={m.value}>
                {m.label}
              </option>
            ))}
          </select>
        </div>

        {/* Threat Actor / Type */}
        <div>
          <label
            htmlFor="filter-actor"
            className="block text-[11px] font-medium text-slate-400 mb-1"
          >
            Threat Type / Actor
          </label>
          <select
            id="filter-actor"
            value={filters.threatType}
            onChange={(e) => onChange({ threatType: e.target.value })}
            className="w-full bg-[#0B0F19] border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
          >
            {THREAT_TYPES_ACTORS.map((a) => (
              <option key={a.value} value={a.value}>
                {a.label}
              </option>
            ))}
          </select>
        </div>

        {/* Severity */}
        <div>
          <label
            htmlFor="filter-severity"
            className="block text-[11px] font-medium text-slate-400 mb-1"
          >
            Severity Level
          </label>
          <select
            id="filter-severity"
            value={filters.severity}
            onChange={(e) => onChange({ severity: e.target.value })}
            className="w-full bg-[#0B0F19] border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
          >
            <option value="All">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>

        {/* Month Selector */}
        <div>
          <label
            htmlFor="filter-month"
            className="block text-[11px] font-medium text-slate-400 mb-1"
          >
            Month (Jan–Dec)
          </label>
          <select
            id="filter-month"
            value={filters.month}
            onChange={(e) =>
              onChange({ month: e.target.value, timeframePreset: 'all' })
            }
            className="w-full bg-[#0B0F19] border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none font-mono"
          >
            {MONTHS.map((m) => (
              <option key={m.value} value={m.value}>
                {m.label}
              </option>
            ))}
          </select>
        </div>

        {/* Year Selector */}
        <div>
          <label
            htmlFor="filter-year"
            className="block text-[11px] font-medium text-slate-400 mb-1"
          >
            Year (2024–2026)
          </label>
          <select
            id="filter-year"
            value={filters.year}
            onChange={(e) =>
              onChange({ year: e.target.value, timeframePreset: 'all' })
            }
            className="w-full bg-[#0B0F19] border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none font-mono"
          >
            {YEARS.map((yr) => (
              <option key={yr} value={yr}>
                {yr === 'All' ? 'All Years' : yr}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Quick Filter Shortcuts for Rapid SOC Pivoting */}
      <div className="flex items-center gap-2 pt-1 overflow-x-auto text-xs">
        <span className="inline-flex items-center gap-1 text-slate-400 shrink-0">
          <SlidersHorizontal className="w-3.5 h-3.5" />
          Quick Hunts:
        </span>
        {[
          { label: 'Volt Typhoon LOTL', patch: { searchQuery: 'Volt Typhoon' } },
          { label: 'LockBit / RansomHub ESXi', patch: { malwareCategory: 'Ransomware' } },
          { label: 'CISA KEV Zero-Days', patch: { threatType: 'Zero-Day Exploits' } },
          { label: 'APAC Financial Sector', patch: { region: 'APAC', industry: 'Finance/BFSI' } },
          { label: 'Supply Chain CI/CD', patch: { threatType: 'Supply Chain Attacks' } },
        ].map((q) => (
          <button
            key={q.label}
            type="button"
            onClick={() => onChange({ ...q.patch })}
            className="px-2.5 py-1 text-xs font-mono text-slate-300 bg-[#0B0F19] hover:bg-slate-800 border border-slate-800 rounded transition-colors whitespace-nowrap shrink-0"
          >
            {q.label}
          </button>
        ))}
      </div>
    </section>
  );
};
