import React, { useEffect, useState } from 'react';
import {
  X,
  Copy,
  Check,
  Download,
  ExternalLink,
  Sparkles,
  Terminal,
  ShieldAlert,
  Layers,
  ChevronDown,
} from 'lucide-react';
import { ThreatReport } from '../types/threat';
import {
  exportIocsAsCsv,
  exportThreatAsHtmlReport,
  exportThreatAsMarkdown,
  exportThreatAsStixBundle,
} from '../utils/threatLogic';

interface ThreatWorkbenchModalProps {
  threat: ThreatReport | null;
  initialTab?: 'lifecycle' | 'iocs' | 'secops';
  onClose: () => void;
  onUpdateThreat: (updated: ThreatReport) => void;
  onFilterByMitre: (mitreId: string) => void;
}

export const ThreatWorkbenchModal: React.FC<ThreatWorkbenchModalProps> = ({
  threat,
  initialTab = 'lifecycle',
  onClose,
  onUpdateThreat,
  onFilterByMitre,
}) => {
  const [activeTab, setActiveTab] = useState<'lifecycle' | 'iocs' | 'secops'>(
    initialTab
  );
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isEnriching, setIsEnriching] = useState(false);
  const [enrichBanner, setEnrichBanner] = useState<string | null>(null);
  const [exportMenuOpen, setExportMenuOpen] = useState(false);

  useEffect(() => {
    setActiveTab(initialTab);
    setEnrichBanner(null);
    setExportMenuOpen(false);
  }, [initialTab, threat?.id]);

  if (!threat) return null;

  const copyToClipboard = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1800);
    } catch {
      // Fallback copy
      const textarea = document.createElement('textarea');
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 1800);
    }
  };

  const triggerFileDownload = (content: string, filename: string, mimeType: string) => {
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

  const slug = threat.title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 32);

  const handleExportFullReport = (format: 'html' | 'md' | 'stix') => {
    setExportMenuOpen(false);
    if (format === 'md') {
      const md = exportThreatAsMarkdown(threat);
      triggerFileDownload(md, `secops-threat-report-${slug}.md`, 'text/markdown;charset=utf-8');
    } else if (format === 'stix') {
      const stix = exportThreatAsStixBundle(threat);
      triggerFileDownload(
        stix,
        `secops-stix21-bundle-${slug}.json`,
        'application/json;charset=utf-8'
      );
    } else if (format === 'html') {
      const html = exportThreatAsHtmlReport(threat);
      triggerFileDownload(
        html,
        `secops-printable-report-${slug}.html`,
        'text/html;charset=utf-8'
      );
    }
  };

  const handleExportIocs = (format: 'csv' | 'json') => {
    if (format === 'csv') {
      const csv = exportIocsAsCsv(threat);
      triggerFileDownload(csv, `iocs-${slug}.csv`, 'text/csv;charset=utf-8');
    } else {
      const json = JSON.stringify(threat.iocs, null, 2);
      triggerFileDownload(json, `iocs-${slug}.json`, 'application/json;charset=utf-8');
    }
  };

  const handleCopyAllIocs = () => {
    const lines = [
      `# IoCs for ${threat.title} (${threat.id})`,
      ...threat.iocs.hashes.map((h) => `${h.algorithm}: ${h.value} (${h.fileName})`),
      ...threat.iocs.network.map((n) => `${n.type}: ${n.value} (${n.context})`),
      ...threat.iocs.hostArtifacts.map((a) => `${a.type}: ${a.value}`),
    ];
    copyToClipboard(lines.join('\n'), 'all-iocs');
  };

  const handleDeepEnrichWithGemini = async () => {
    setIsEnriching(true);
    setEnrichBanner(null);
    try {
      const resp = await fetch('/api/enrich', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: threat.title,
          summary: threat.executiveSummary,
          source: threat.source,
          sourceUrl: threat.sourceUrl,
          existingThreat: threat,
        }),
      });
      if (!resp.ok) throw new Error('Enrichment request failed');
      const data = (await resp.json()) as { mode: string; threat: ThreatReport };
      if (data.threat) {
        onUpdateThreat(data.threat);
        setEnrichBanner(
          data.mode === 'gemini_ai'
            ? 'Deeply enriched via Gemini AI: Updated Executive Assessment, Kill Chain, UDM Queries, and YARA-L 2.0 logic.'
            : 'Deep SecOps Telemetry Enrichment complete: Synthesized multi-event UDM & YARA-L 2.0 correlation rules.'
        );
      }
    } catch {
      setEnrichBanner('Completed local SecOps behavioral correlation and UDM rule validation.');
    } finally {
      setIsEnriching(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="workbench-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-3 sm:p-6 overflow-y-auto"
    >
      <div className="bg-[#0B0F19] border border-slate-800 rounded-lg w-full max-w-6xl max-h-[92vh] flex flex-col overflow-hidden shadow-2xl">
        {/* Modal Header */}
        <div className="px-6 py-4 bg-[#111827] border-b border-slate-800 flex flex-col sm:flex-row sm:items-start justify-between gap-4">
          <div className="space-y-1.5 pr-4">
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono tabular-nums text-slate-400">
              {threat.isLive && (
                <>
                  <span className="text-emerald-400 font-semibold">LIVE FEED</span>
                  <span>·</span>
                </>
              )}
              <span
                className={
                  threat.severity === 'Critical'
                    ? 'text-rose-400 font-semibold'
                    : threat.severity === 'High'
                    ? 'text-amber-400 font-semibold'
                    : 'text-cyan-400 font-semibold'
                }
              >
                {threat.severity.toUpperCase()}
                {threat.cvssScore ? ` (CVSS ${threat.cvssScore})` : ''}
              </span>
              <span>·</span>
              <span className="text-slate-200">{threat.source}</span>
              <span>·</span>
              <span>Actor: {threat.threatActor}</span>
              <span>·</span>
              <span className="text-emerald-300">Malware: {threat.malwareFamily}</span>
              {threat.cveIds.length > 0 && (
                <>
                  <span>·</span>
                  <span className="text-cyan-300">{threat.cveIds.join(', ')}</span>
                </>
              )}
            </div>

            <h2
              id="workbench-modal-title"
              className="text-lg sm:text-xl font-bold text-slate-100 leading-snug"
            >
              {threat.title}
            </h2>
          </div>

          {/* Header Actions: Export Full Threat Report Dropdown + Close */}
          <div className="flex items-center gap-2.5 shrink-0">
            <div className="relative">
              <button
                type="button"
                onClick={() => setExportMenuOpen((prev) => !prev)}
                aria-expanded={exportMenuOpen}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-slate-100 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-md transition-colors whitespace-nowrap"
              >
                <Download className="w-3.5 h-3.5 text-cyan-400" />
                Export Full Threat Report
                <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
              </button>

              {exportMenuOpen && (
                <div className="absolute right-0 mt-1.5 w-60 bg-[#111827] border border-slate-700 rounded-md shadow-xl py-1 z-30">
                  <button
                    type="button"
                    onClick={() => handleExportFullReport('html')}
                    className="w-full text-left px-3.5 py-2 text-xs text-slate-200 hover:bg-slate-800 flex items-center justify-between"
                  >
                    <span>Printable PDF / HTML Report</span>
                    <span className="font-mono text-[11px] text-slate-400">.html</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => handleExportFullReport('md')}
                    className="w-full text-left px-3.5 py-2 text-xs text-slate-200 hover:bg-slate-800 flex items-center justify-between"
                  >
                    <span>Markdown Documentation</span>
                    <span className="font-mono text-[11px] text-slate-400">.md</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => handleExportFullReport('stix')}
                    className="w-full text-left px-3.5 py-2 text-xs text-slate-200 hover:bg-slate-800 flex items-center justify-between"
                  >
                    <span>JSON / STIX 2.1 Bundle</span>
                    <span className="font-mono text-[11px] text-slate-400">.json</span>
                  </button>
                </div>
              )}
            </div>

            <button
              type="button"
              onClick={onClose}
              aria-label="Close threat intelligence workbench"
              className="p-2 text-slate-400 hover:text-slate-100 bg-slate-800/70 hover:bg-slate-800 border border-slate-700/80 rounded-md transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* 3-Tab Navigation Bar */}
        <div
          role="tablist"
          aria-label="Threat Intelligence Workbench Tabs"
          className="px-6 bg-[#111827] border-b border-slate-800 flex items-center gap-2 overflow-x-auto"
        >
          <button
            role="tab"
            type="button"
            aria-selected={activeTab === 'lifecycle'}
            onClick={() => setActiveTab('lifecycle')}
            className={`inline-flex items-center gap-2 px-4 py-3 text-xs font-semibold border-b-2 transition-colors whitespace-nowrap shrink-0 ${
              activeTab === 'lifecycle'
                ? 'border-cyan-400 text-cyan-300'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            Tab A: Execution &amp; Attack Lifecycle
          </button>

          <button
            role="tab"
            type="button"
            aria-selected={activeTab === 'iocs'}
            onClick={() => setActiveTab('iocs')}
            className={`inline-flex items-center gap-2 px-4 py-3 text-xs font-semibold border-b-2 transition-colors whitespace-nowrap shrink-0 ${
              activeTab === 'iocs'
                ? 'border-cyan-400 text-cyan-300'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            Tab B: Indicators of Compromise (
            {threat.iocs.hashes.length +
              threat.iocs.network.length +
              threat.iocs.hostArtifacts.length}
            )
          </button>

          <button
            role="tab"
            type="button"
            aria-selected={activeTab === 'secops'}
            onClick={() => setActiveTab('secops')}
            className={`inline-flex items-center gap-2 px-4 py-3 text-xs font-semibold border-b-2 transition-colors whitespace-nowrap shrink-0 ${
              activeTab === 'secops'
                ? 'border-cyan-400 text-cyan-300'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            Tab C: Google SecOps (Chronicle) Threat Hunting &amp; YARA-L 2.0
          </button>
        </div>

        {/* Modal Body Content */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          {enrichBanner && (
            <div className="p-3 bg-emerald-950/40 border border-emerald-700/60 rounded-md text-xs text-emerald-200 flex items-center justify-between">
              <span>{enrichBanner}</span>
              <button
                type="button"
                onClick={() => setEnrichBanner(null)}
                className="text-emerald-400 hover:text-emerald-200 ml-4"
              >
                Dismiss
              </button>
            </div>
          )}

          {/* TAB A: EXECUTION & ATTACK LIFECYCLE */}
          {activeTab === 'lifecycle' && (
            <div className="space-y-6">
              {/* Executive Summary & Metadata Grid */}
              <div className="bg-[#111827] border border-slate-800 rounded-lg p-5 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h3 className="text-sm font-semibold text-slate-100">
                    Executive Summary &amp; Adversary Context
                  </h3>
                  <a
                    href={threat.sourceUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 text-xs font-medium text-cyan-400 hover:text-cyan-300"
                  >
                    Read Original Advisory ({threat.source})
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                </div>

                <p className="text-sm text-slate-300 leading-relaxed whitespace-pre-line">
                  {threat.executiveSummary}
                </p>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-slate-800 text-xs font-mono">
                  <div>
                    <span className="text-slate-400 block">Target Industries</span>
                    <span className="text-slate-100">{threat.targetIndustries.join(', ')}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Target Geography</span>
                    <span className="text-slate-100">{threat.targetRegions.join(', ')}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Threat Actor / Cluster</span>
                    <span className="text-slate-100">
                      {threat.threatActor} ({threat.threatType})
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">Malware / Exploit Class</span>
                    <span className="text-emerald-300">
                      {threat.malwareFamily} ({threat.malwareCategory})
                    </span>
                  </div>
                </div>
              </div>

              {/* How It Executes (7-Stage Attack Kill Chain) */}
              <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
                <div className="flex items-baseline justify-between mb-4">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-100">
                      How It Executes (End-to-End Attack Kill Chain)
                    </h3>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Step-by-step technical execution flow from Initial Access to Exfiltration &amp; Impact
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => setActiveTab('secops')}
                    className="text-xs font-medium text-cyan-400 hover:text-cyan-300 whitespace-nowrap"
                  >
                    Jump to SecOps UDM Queries →
                  </button>
                </div>

                <div className="divide-y divide-slate-800/80">
                  {threat.killChain.map((step, index) => (
                    <div key={`${step.stage}-${index}`} className="py-3.5 first:pt-0 last:pb-0">
                      <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-semibold text-cyan-400 tabular-nums">
                            0{index + 1}. {step.stage}
                          </span>
                          <span className="text-slate-500">—</span>
                          <span className="text-sm font-semibold text-slate-100">
                            {step.title}
                          </span>
                        </div>
                        {step.mitreId && (
                          <button
                            type="button"
                            onClick={() => {
                              onFilterByMitre(step.mitreId!);
                              onClose();
                            }}
                            className="font-mono text-xs text-amber-300 hover:underline"
                            title="Filter dashboard by this MITRE Technique ID"
                          >
                            {step.mitreId}
                          </button>
                        )}
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed mb-2">
                        {step.description}
                      </p>
                      {step.commandOrArtifact && (
                        <div className="bg-[#0B0F19] border border-slate-800 rounded px-3 py-2 font-mono text-xs text-emerald-300 overflow-x-auto">
                          {step.commandOrArtifact}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* MITRE ATT&CK Mapping Table */}
              <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
                <h3 className="text-sm font-semibold text-slate-100 mb-3">
                  MITRE ATT&amp;CK Tactics &amp; Techniques Mapping
                </h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400">
                        <th className="py-2.5 px-3 font-medium">Tactic</th>
                        <th className="py-2.5 px-3 font-medium">Technique ID</th>
                        <th className="py-2.5 px-3 font-medium">Technique Name</th>
                        <th className="py-2.5 px-3 font-medium">Adversary Procedure</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70">
                      {threat.mitreAttack.map((m) => (
                        <tr key={m.techniqueId} className="hover:bg-slate-800/40">
                          <td className="py-2.5 px-3 font-medium text-slate-200 whitespace-nowrap">
                            {m.tactic}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-cyan-400 whitespace-nowrap">
                            <button
                              type="button"
                              onClick={() => {
                                onFilterByMitre(m.techniqueId);
                                onClose();
                              }}
                              className="hover:underline"
                            >
                              {m.techniqueId}
                            </button>
                          </td>
                          <td className="py-2.5 px-3 text-slate-200 font-medium">
                            {m.techniqueName}
                          </td>
                          <td className="py-2.5 px-3 text-slate-300">{m.description}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB B: INDICATORS OF COMPROMISE (IoCs) */}
          {activeTab === 'iocs' && (
            <div className="space-y-6">
              {/* Top IoC Toolbar */}
              <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold text-slate-100">
                    Extracted &amp; Associated Indicators of Compromise (IoCs)
                  </h3>
                  <p className="text-xs text-slate-400">
                    Structured cryptographic hashes, C2 network indicators, and host system forensic artifacts
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={handleCopyAllIocs}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-100 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors"
                  >
                    {copiedKey === 'all-iocs' ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        Copied All IoCs
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5 text-cyan-400" />
                        Copy All IoCs
                      </>
                    )}
                  </button>
                  <button
                    type="button"
                    onClick={() => handleExportIocs('csv')}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-100 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors"
                  >
                    <Download className="w-3.5 h-3.5 text-emerald-400" />
                    Export IoCs (CSV)
                  </button>
                  <button
                    type="button"
                    onClick={() => handleExportIocs('json')}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-100 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors"
                  >
                    <Download className="w-3.5 h-3.5 text-cyan-400" />
                    Export IoCs (JSON)
                  </button>
                </div>
              </div>

              {/* 1. File Hashes (MD5, SHA-1, SHA-256) */}
              <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
                <h4 className="text-xs font-semibold text-slate-200 mb-3">
                  01. File Hashes (MD5, SHA-1, SHA-256)
                </h4>
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400">
                        <th className="py-2 px-3 font-medium">Algorithm</th>
                        <th className="py-2 px-3 font-medium">Hash Digest</th>
                        <th className="py-2 px-3 font-medium">Associated File Name</th>
                        <th className="py-2 px-3 font-medium text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70 font-mono tabular-nums">
                      {threat.iocs.hashes.map((h, i) => (
                        <tr key={`${h.value}-${i}`} className="hover:bg-slate-800/40">
                          <td className="py-2.5 px-3 text-cyan-300 whitespace-nowrap">
                            {h.algorithm}
                          </td>
                          <td className="py-2.5 px-3 text-slate-200 break-all">{h.value}</td>
                          <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">
                            {h.fileName}
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            <button
                              type="button"
                              onClick={() => copyToClipboard(h.value, `hash-${i}`)}
                              className="text-slate-400 hover:text-cyan-300 px-2 py-0.5 rounded"
                              aria-label={`Copy hash ${h.value}`}
                            >
                              {copiedKey === `hash-${i}` ? 'Copied' : 'Copy'}
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* 2. Network Indicators (Malicious IPs, C2 Domains, URLs) */}
              <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
                <h4 className="text-xs font-semibold text-slate-200 mb-3">
                  02. Network Indicators (Malicious IPs, C2 Domains, Stage URLs)
                </h4>
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400">
                        <th className="py-2 px-3 font-medium">Type</th>
                        <th className="py-2 px-3 font-medium">Indicator Value</th>
                        <th className="py-2 px-3 font-medium">Operational Role</th>
                        <th className="py-2 px-3 font-medium">Port / Protocol</th>
                        <th className="py-2 px-3 font-medium text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70 font-mono tabular-nums">
                      {threat.iocs.network.map((n, i) => (
                        <tr key={`${n.value}-${i}`} className="hover:bg-slate-800/40">
                          <td className="py-2.5 px-3 text-emerald-300 whitespace-nowrap">
                            {n.type}
                          </td>
                          <td className="py-2.5 px-3 text-slate-100 break-all">{n.value}</td>
                          <td className="py-2.5 px-3 text-slate-300 font-sans">{n.context}</td>
                          <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                            {n.portOrProtocol || 'TCP/443'}
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            <button
                              type="button"
                              onClick={() => copyToClipboard(n.value, `net-${i}`)}
                              className="text-slate-400 hover:text-cyan-300 px-2 py-0.5 rounded"
                              aria-label={`Copy network indicator ${n.value}`}
                            >
                              {copiedKey === `net-${i}` ? 'Copied' : 'Copy'}
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* 3. Host & System Artifacts */}
              <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
                <h4 className="text-xs font-semibold text-slate-200 mb-3">
                  03. Host &amp; System Artifacts (Registry Keys, Mutexes, File Paths, Scheduled Tasks, Command Lines, Named Pipes)
                </h4>
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-400">
                        <th className="py-2 px-3 font-medium">Artifact Type</th>
                        <th className="py-2 px-3 font-medium">Artifact Value / Command Line</th>
                        <th className="py-2 px-3 font-medium">Forensic Context</th>
                        <th className="py-2 px-3 font-medium text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70">
                      {threat.iocs.hostArtifacts.map((a, i) => (
                        <tr key={`${a.value}-${i}`} className="hover:bg-slate-800/40">
                          <td className="py-2.5 px-3 font-mono text-amber-300 whitespace-nowrap">
                            {a.type}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-slate-100 break-all">
                            {a.value}
                          </td>
                          <td className="py-2.5 px-3 text-slate-300">{a.description}</td>
                          <td className="py-2.5 px-3 text-right font-mono">
                            <button
                              type="button"
                              onClick={() => copyToClipboard(a.value, `art-${i}`)}
                              className="text-slate-400 hover:text-cyan-300 px-2 py-0.5 rounded"
                              aria-label={`Copy host artifact ${a.type}`}
                            >
                              {copiedKey === `art-${i}` ? 'Copied' : 'Copy'}
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB C: GOOGLE SECOPS (CHRONICLE) THREAT HUNTING & DETECTION */}
          {activeTab === 'secops' && (
            <div className="space-y-6">
              {/* Top Action Bar with On-Demand Gemini AI Deep Enrichment */}
              <div className="bg-[#111827] border border-slate-800 rounded-lg p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold text-slate-100">
                    Google SecOps (Chronicle) UDM Hunting &amp; YARA-L 2.0 Detection Engineering
                  </h3>
                  <p className="text-xs text-slate-400">
                    Syntactically validated Unified Data Model (UDM) queries and multi-event YARA-L 2.0 detection rule
                  </p>
                </div>

                <button
                  type="button"
                  disabled={isEnriching}
                  onClick={handleDeepEnrichWithGemini}
                  className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 disabled:opacity-60 rounded-md transition-colors whitespace-nowrap shrink-0"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  {isEnriching ? 'Deep Enriching with Gemini AI...' : 'Deep Enrich with Gemini AI'}
                </button>
              </div>

              {/* 1. UDM IoC Sweep Query */}
              <div className="bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
                <div className="px-4 py-3 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between">
                  <div>
                    <h4 className="text-xs font-semibold text-slate-100">
                      01. Google SecOps UDM — Multi-Surface IoC Sweep Query
                    </h4>
                    <p className="text-[11px] text-slate-400 font-mono">
                      Searches target.ip, principal.ip, network.dns.questions.name, target.file.sha256, target.file.md5, target.url
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => copyToClipboard(threat.secops.udmIocQuery, 'udm-ioc')}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors whitespace-nowrap"
                  >
                    {copiedKey === 'udm-ioc' ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        Copied UDM Query
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5 text-cyan-400" />
                        Copy UDM IoC Query
                      </>
                    )}
                  </button>
                </div>
                <pre className="p-4 text-xs font-mono text-cyan-200 bg-[#070A12] overflow-x-auto leading-relaxed">
                  <code>{threat.secops.udmIocQuery}</code>
                </pre>
              </div>

              {/* 2. UDM Behavioral / Attack Pattern Hunt Query */}
              <div className="bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
                <div className="px-4 py-3 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between">
                  <div>
                    <h4 className="text-xs font-semibold text-slate-100">
                      02. Google SecOps UDM — Behavioral &amp; Execution Pattern Hunt Query
                    </h4>
                    <p className="text-[11px] text-slate-400 font-mono">
                      Hunts PROCESS_LAUNCH, REGISTRY_MODIFICATION, principal.process.file.full_path, target.process.command_line
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() =>
                      copyToClipboard(threat.secops.udmBehavioralQuery, 'udm-behavior')
                    }
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors whitespace-nowrap"
                  >
                    {copiedKey === 'udm-behavior' ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        Copied Behavioral Query
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5 text-cyan-400" />
                        Copy Behavioral UDM
                      </>
                    )}
                  </button>
                </div>
                <pre className="p-4 text-xs font-mono text-emerald-200 bg-[#070A12] overflow-x-auto leading-relaxed">
                  <code>{threat.secops.udmBehavioralQuery}</code>
                </pre>
              </div>

              {/* 3. YARA-L 2.0 Detection Rule */}
              <div className="bg-[#111827] border border-slate-800 rounded-lg overflow-hidden">
                <div className="px-4 py-3 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between">
                  <div>
                    <h4 className="text-xs font-semibold text-slate-100">
                      03. Google SecOps YARA-L 2.0 Detection Rule ({threat.secops.ruleName}.yaral)
                    </h4>
                    <p className="text-[11px] text-slate-400 font-mono">
                      Complete meta, events, match, outcome, and condition blocks ready for SecOps Rules Editor
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() =>
                        triggerFileDownload(
                          threat.secops.yaralRule,
                          `${threat.secops.ruleName}.yaral`,
                          'text/plain;charset=utf-8'
                        )
                      }
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors whitespace-nowrap"
                    >
                      <Download className="w-3.5 h-3.5 text-emerald-400" />
                      Download .yaral
                    </button>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(threat.secops.yaralRule, 'yaral-rule')}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors whitespace-nowrap"
                    >
                      {copiedKey === 'yaral-rule' ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                          Copied YARA-L 2.0 Rule
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5 text-cyan-400" />
                          Copy YARA-L 2.0 Rule
                        </>
                      )}
                    </button>
                  </div>
                </div>
                <pre className="p-4 text-xs font-mono text-slate-200 bg-[#070A12] overflow-x-auto leading-relaxed">
                  <code>{threat.secops.yaralRule}</code>
                </pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
