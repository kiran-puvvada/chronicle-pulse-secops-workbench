import React from 'react';
import { ExternalLink, Terminal, FileDown } from 'lucide-react';
import { ThreatReport } from '../types/threat';

interface ThreatCardProps {
  threat: ThreatReport;
  onSelect: (threat: ThreatReport, initialTab?: 'lifecycle' | 'iocs' | 'secops') => void;
  onQuickExportMarkdown: (threat: ThreatReport) => void;
}

export const ThreatCard: React.FC<ThreatCardProps> = ({
  threat,
  onSelect,
  onQuickExportMarkdown,
}) => {
  const totalIocs =
    threat.iocs.hashes.length +
    threat.iocs.network.length +
    threat.iocs.hostArtifacts.length;

  const severityStyles =
    threat.severity === 'Critical'
      ? 'text-rose-400 font-semibold'
      : threat.severity === 'High'
      ? 'text-amber-400 font-semibold'
      : threat.severity === 'Medium'
      ? 'text-cyan-400 font-medium'
      : 'text-slate-400 font-medium';

  const formattedDate = new Date(threat.publishedAt).toLocaleString('en-US', {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });

  return (
    <article className="bg-[#111827] border border-slate-800 hover:border-slate-700 rounded-lg p-5 flex flex-col justify-between transition-colors">
      <div>
        {/* Quiet 1-line metadata kicker (unboxed text with typographic separators per design rules) */}
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400 font-mono tabular-nums mb-2.5">
          <div className="flex flex-wrap items-center gap-1.5">
            {threat.isLive && (
              <>
                <span className="text-emerald-400 font-semibold tracking-wide">
                  LIVE FEED
                </span>
                <span aria-hidden="true">·</span>
              </>
            )}
            <span className={severityStyles}>
              {threat.severity.toUpperCase()}
              {threat.cvssScore ? ` (${threat.cvssScore})` : ''}
            </span>
            <span aria-hidden="true">·</span>
            <span className="text-slate-300">{threat.source}</span>
            {threat.cveIds.length > 0 && (
              <>
                <span aria-hidden="true">·</span>
                <span className="text-cyan-300">{threat.cveIds.join(', ')}</span>
              </>
            )}
          </div>
          <time dateTime={threat.publishedAt} className="text-slate-400 shrink-0">
            {formattedDate} UTC
          </time>
        </div>

        {/* Primary Title */}
        <h3 className="text-base font-semibold text-slate-100 leading-snug mb-2">
          <button
            type="button"
            onClick={() => onSelect(threat, 'lifecycle')}
            className="text-left hover:text-cyan-300 transition-colors focus:outline-none focus-visible:underline"
          >
            {threat.title}
          </button>
        </h3>

        {/* 2-line Summary */}
        <p className="text-sm text-slate-300/90 line-clamp-2 leading-relaxed mb-3.5">
          {threat.summary}
        </p>

        {/* Clean Unboxed Technical Taxonomy Metadata */}
        <div className="text-xs text-slate-400 space-y-1.5 pt-3 border-t border-slate-800/80 font-mono tabular-nums">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="text-slate-400">Actor/Type:</span>
            <span className="text-slate-200">{threat.threatActor}</span>
            <span aria-hidden="true">·</span>
            <span className="text-slate-400">Malware:</span>
            <span className="text-emerald-300">{threat.malwareFamily}</span>
            <span className="text-slate-400">({threat.malwareCategory})</span>
          </div>
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="text-slate-400">Industries:</span>
            <span className="text-slate-300">{threat.targetIndustries.join(', ')}</span>
            <span aria-hidden="true">·</span>
            <span className="text-slate-400">Regions:</span>
            <span className="text-slate-300">{threat.targetRegions.join(', ')}</span>
          </div>
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-slate-400">
            <span>MITRE: {threat.mitreAttack.map((m) => m.techniqueId).slice(0, 4).join(', ')}</span>
            <span aria-hidden="true">·</span>
            <span>{totalIocs} Extracted IoCs</span>
            <span aria-hidden="true">·</span>
            <span>YARA-L 2.0 Ready</span>
          </div>
        </div>
      </div>

      {/* Action Footer */}
      <div className="flex flex-wrap items-center justify-between gap-2 pt-4 mt-4 border-t border-slate-800">
        <div className="flex items-center gap-3">
          <a
            href={threat.sourceUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs font-medium text-slate-400 hover:text-slate-200 transition-colors whitespace-nowrap shrink-0"
          >
            Source Advisory
            <ExternalLink className="w-3.5 h-3.5" />
          </a>
          <button
            type="button"
            onClick={() => onQuickExportMarkdown(threat)}
            className="inline-flex items-center gap-1 text-xs font-medium text-slate-400 hover:text-slate-200 transition-colors whitespace-nowrap shrink-0"
            aria-label={`Export Markdown report for ${threat.title}`}
          >
            <FileDown className="w-3.5 h-3.5" />
            Export .MD
          </button>
        </div>

        <button
          type="button"
          onClick={() => onSelect(threat, 'lifecycle')}
          className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md transition-colors whitespace-nowrap shrink-0"
        >
          <Terminal className="w-3.5 h-3.5" />
          Analyze &amp; Generate SecOps Hunt
        </button>
      </div>
    </article>
  );
};
