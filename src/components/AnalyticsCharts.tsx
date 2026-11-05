import React from 'react';
import { DashboardMetrics } from '../types/threat';

interface AnalyticsChartsProps {
  metrics: DashboardMetrics;
  activeIndustry: string;
  activeMalware: string;
  onSelectIndustry: (industry: string) => void;
  onSelectMalwareCategory: (category: string) => void;
}

export const AnalyticsCharts: React.FC<AnalyticsChartsProps> = ({
  metrics,
  activeIndustry,
  activeMalware,
  onSelectIndustry,
  onSelectMalwareCategory,
}) => {
  const maxVolume = Math.max(
    1,
    ...metrics.volumeByTime.map((v) => v.total)
  );
  const maxCategoryCount = Math.max(
    1,
    ...metrics.categoryDistribution.map((c) => c.count)
  );

  return (
    <section
      aria-label="Threat Intelligence Visual Analytics"
      className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6"
    >
      {/* Chart 1: Threat Volume by Time */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-5 flex flex-col justify-between">
        <div className="flex items-baseline justify-between mb-4">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">
              Threat Volume &amp; Severity Trend
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Temporal distribution across filtered advisories
            </p>
          </div>
          <div className="flex items-center gap-3 text-[11px] text-slate-400 font-mono tabular-nums">
            <span className="text-rose-400">Critical</span>
            <span>·</span>
            <span className="text-amber-400">High</span>
            <span>·</span>
            <span className="text-cyan-400">Med</span>
          </div>
        </div>

        {metrics.volumeByTime.length === 0 ? (
          <div className="h-44 flex items-center justify-center text-xs text-slate-500">
            No threat volume in current filter window
          </div>
        ) : (
          <div className="h-44 flex items-end gap-2.5 pt-4 pb-1 border-b border-slate-800/80">
            {metrics.volumeByTime.map((bucket) => {
              const totalHeightPct = Math.max(14, Math.round((bucket.total / maxVolume) * 100));
              const critPct = bucket.total > 0 ? (bucket.critical / bucket.total) * 100 : 0;
              const highPct = bucket.total > 0 ? (bucket.high / bucket.total) * 100 : 0;
              const medPct = Math.max(0, 100 - critPct - highPct);

              return (
                <div
                  key={bucket.label}
                  className="flex-1 flex flex-col items-center justify-end h-full group"
                >
                  <span className="text-[11px] font-mono tabular-nums text-slate-300 mb-1.5 opacity-85 group-hover:text-cyan-300">
                    {bucket.total}
                  </span>
                  <div
                    className="w-full max-w-[34px] rounded-t overflow-hidden flex flex-col justify-end bg-slate-900 border border-slate-800/90 transition-opacity group-hover:opacity-95"
                    style={{ height: `${totalHeightPct}%` }}
                    title={`${bucket.label}: ${bucket.total} total (${bucket.critical} Critical, ${bucket.high} High, ${bucket.medium} Medium)`}
                  >
                    {medPct > 0 && (
                      <div
                        style={{ height: `${medPct}%` }}
                        className="w-full bg-cyan-500/75"
                      />
                    )}
                    {highPct > 0 && (
                      <div
                        style={{ height: `${highPct}%` }}
                        className="w-full bg-amber-500/85"
                      />
                    )}
                    {critPct > 0 && (
                      <div
                        style={{ height: `${critPct}%` }}
                        className="w-full bg-rose-500"
                      />
                    )}
                  </div>
                  <span className="text-[11px] font-mono tabular-nums text-slate-400 mt-2 truncate max-w-full">
                    {bucket.label}
                  </span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Chart 2: Targeted Industries Breakdown */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-5 flex flex-col justify-between">
        <div className="flex items-baseline justify-between mb-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">
              Targeted Industries Breakdown
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Click any sector bar to isolate sector threats
            </p>
          </div>
          {activeIndustry !== 'All' && (
            <button
              type="button"
              onClick={() => onSelectIndustry('All')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium whitespace-nowrap shrink-0"
            >
              Reset Sector
            </button>
          )}
        </div>

        {metrics.industryBreakdown.length === 0 ? (
          <div className="h-44 flex items-center justify-center text-xs text-slate-500">
            No industry telemetry matching filters
          </div>
        ) : (
          <div className="space-y-2.5 my-auto">
            {metrics.industryBreakdown.map((item) => {
              const isSelected = activeIndustry === item.industry;
              return (
                <button
                  key={item.industry}
                  type="button"
                  onClick={() =>
                    onSelectIndustry(isSelected ? 'All' : item.industry)
                  }
                  className={`w-full text-left group rounded px-1.5 py-1 transition-colors ${
                    isSelected
                      ? 'bg-cyan-950/50 border border-cyan-500/40'
                      : 'hover:bg-slate-800/50'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span
                      className={`font-medium truncate ${
                        isSelected
                          ? 'text-cyan-300'
                          : 'text-slate-200 group-hover:text-white'
                      }`}
                    >
                      {item.industry}
                    </span>
                    <span className="font-mono tabular-nums text-slate-400 ml-2 shrink-0">
                      {item.count} ({item.percentage}%)
                    </span>
                  </div>
                  <div className="w-full h-1.5 bg-slate-900 rounded-sm overflow-hidden">
                    <div
                      className={`h-full transition-transform origin-left ${
                        isSelected ? 'bg-cyan-400' : 'bg-emerald-500/85 group-hover:bg-cyan-400'
                      }`}
                      style={{ width: `${Math.max(8, item.percentage * 1.8)}%`, maxWidth: '100%' }}
                    />
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* Chart 3: Malware vs. Vulnerability Distribution */}
      <div className="bg-[#111827] border border-slate-800 rounded-lg p-5 flex flex-col justify-between">
        <div className="flex items-baseline justify-between mb-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">
              Malware vs. Vulnerability Distribution
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Payload families &amp; zero-day exploit classes
            </p>
          </div>
          {activeMalware !== 'All' && (
            <button
              type="button"
              onClick={() => onSelectMalwareCategory('All')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium whitespace-nowrap shrink-0"
            >
              Reset Class
            </button>
          )}
        </div>

        {metrics.categoryDistribution.length === 0 ? (
          <div className="h-44 flex items-center justify-center text-xs text-slate-500">
            No malware/exploit telemetry in current view
          </div>
        ) : (
          <div className="space-y-2.5 my-auto">
            {metrics.categoryDistribution.slice(0, 6).map((cat) => {
              const isSelected = activeMalware === cat.category;
              const widthPct = Math.max(
                10,
                Math.round((cat.count / maxCategoryCount) * 100)
              );
              const barColor =
                cat.category === 'Ransomware' || cat.category === 'Wipers'
                  ? 'bg-rose-500/90'
                  : cat.type === 'Vulnerability'
                  ? 'bg-amber-500/90'
                  : 'bg-cyan-500/85';

              return (
                <button
                  key={cat.category}
                  type="button"
                  onClick={() =>
                    onSelectMalwareCategory(isSelected ? 'All' : cat.category)
                  }
                  className={`w-full text-left group rounded px-1.5 py-1 transition-colors ${
                    isSelected
                      ? 'bg-cyan-950/50 border border-cyan-500/40'
                      : 'hover:bg-slate-800/50'
                  }`}
                >
                  <div className="flex items-center justify-between text-xs mb-1">
                    <span className="font-medium text-slate-200 group-hover:text-white truncate">
                      {cat.category}
                    </span>
                    <span className="font-mono tabular-nums text-slate-400 ml-2 shrink-0">
                      {cat.count} {cat.count === 1 ? 'report' : 'reports'} · {cat.type}
                    </span>
                  </div>
                  <div className="w-full h-1.5 bg-slate-900 rounded-sm overflow-hidden">
                    <div
                      className={`h-full ${barColor}`}
                      style={{ width: `${widthPct}%` }}
                    />
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </section>
  );
};
