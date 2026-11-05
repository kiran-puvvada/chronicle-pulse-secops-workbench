import React, { useState } from 'react';
import { X, Rss, Sparkles, RefreshCw } from 'lucide-react';
import { FeedSourceConfig, ThreatReport } from '../types/threat';

interface FeedConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  sources: FeedSourceConfig[];
  onToggleSource: (id: string) => void;
  onSyncNow: () => void;
  isSyncing: boolean;
  onIngestCustomThreat: (threat: ThreatReport) => void;
}

export const FeedConfigModal: React.FC<FeedConfigModalProps> = ({
  isOpen,
  onClose,
  sources,
  onToggleSource,
  onSyncNow,
  isSyncing,
  onIngestCustomThreat,
}) => {
  const [customTitle, setCustomTitle] = useState('');
  const [customRawText, setCustomRawText] = useState('');
  const [customSourceUrl, setCustomSourceUrl] = useState('');
  const [isEnrichingCustom, setIsEnrichingCustom] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleCustomEnrichSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!customTitle.trim() || !customRawText.trim()) {
      setErrorMsg('Please provide both an advisory title and threat intelligence text or CVE details.');
      return;
    }
    setErrorMsg(null);
    setIsEnrichingCustom(true);

    try {
      const resp = await fetch('/api/enrich', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: customTitle.trim(),
          summary: customRawText.trim(),
          source: 'Analyst Custom Ingest',
          sourceUrl: customSourceUrl.trim() || 'https://www.cisa.gov/',
        }),
      });
      if (!resp.ok) throw new Error('Enrichment failed');
      const data = (await resp.json()) as { threat: ThreatReport };
      if (data.threat) {
        onIngestCustomThreat(data.threat);
        setCustomTitle('');
        setCustomRawText('');
        setCustomSourceUrl('');
        onClose();
      }
    } catch {
      setErrorMsg('Failed to enrich advisory. Please try again.');
    } finally {
      setIsEnrichingCustom(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="feed-config-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 overflow-y-auto"
    >
      <div className="bg-[#0B0F19] border border-slate-800 rounded-lg w-full max-w-4xl max-h-[90vh] flex flex-col overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="px-6 py-4 bg-[#111827] border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2
              id="feed-config-modal-title"
              className="text-base font-bold text-slate-100"
            >
              Live Feed Ingestion Sources &amp; AI Threat Enrichment Pipeline
            </h2>
            <p className="text-xs text-slate-400">
              Manage active RSS/JSON threat feeds or ingest raw threat advisories for instant Google SecOps UDM &amp; YARA-L 2.0 generation
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close feed configuration modal"
            className="p-2 text-slate-400 hover:text-slate-100 bg-slate-800/70 rounded-md"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-6 overflow-y-auto space-y-6">
          {/* Section 1: Live RSS & JSON API Feed Connectors */}
          <div className="bg-[#111827] border border-slate-800 rounded-lg p-5">
            <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
              <div className="flex items-center gap-2">
                <Rss className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-slate-100">
                  Configured Live Cybersecurity Feeds
                </h3>
              </div>
              <button
                type="button"
                onClick={onSyncNow}
                disabled={isSyncing}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-60 rounded transition-colors"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
                {isSyncing ? 'Syncing Feeds...' : 'Poll All Enabled Feeds Now'}
              </button>
            </div>

            <div className="divide-y divide-slate-800/80">
              {sources.map((src) => (
                <div
                  key={src.id}
                  className="py-2.5 flex items-center justify-between gap-4 text-xs"
                >
                  <div className="min-w-0">
                    <div className="font-medium text-slate-100 flex items-center gap-2">
                      <span>{src.name}</span>
                      <span className="text-slate-500">·</span>
                      <span className="font-mono text-[11px] text-cyan-400 uppercase">
                        {src.type}
                      </span>
                    </div>
                    <p className="text-slate-400 font-mono text-[11px] truncate">
                      {src.url}
                    </p>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <span className="font-mono tabular-nums text-slate-400">
                      {src.lastCount} items
                    </span>
                    <label className="inline-flex items-center gap-2 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={src.enabled}
                        onChange={() => onToggleSource(src.id)}
                        className="rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
                      />
                      <span className="text-slate-300">Enabled</span>
                    </label>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Section 2: Custom Threat Report / CVE AI Enrichment Form */}
          <form
            onSubmit={handleCustomEnrichSubmit}
            className="bg-[#111827] border border-slate-800 rounded-lg p-5 space-y-4"
          >
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-emerald-400" />
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  Ingest &amp; Enrich Custom Threat Advisory / CVE with Gemini AI
                </h3>
                <p className="text-xs text-slate-400">
                  Paste any raw threat blog, CERT bulletin, or CVE description to automatically extract Kill Chain stages, MITRE ATT&amp;CK IDs, IoCs, and SecOps UDM / YARA-L 2.0 rules
                </p>
              </div>
            </div>

            {errorMsg && (
              <div
                role="alert"
                className="p-3 bg-rose-950/50 border border-rose-700/70 rounded text-xs text-rose-200"
              >
                {errorMsg}
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label
                  htmlFor="custom-advisory-title"
                  className="block text-xs font-medium text-slate-300 mb-1"
                >
                  Advisory Title or CVE Identifier *
                </label>
                <input
                  id="custom-advisory-title"
                  type="text"
                  value={customTitle}
                  onChange={(e) => setCustomTitle(e.target.value)}
                  placeholder="e.g., CVE-2026-30911 Palo Alto PAN-OS Zero-Day Command Injection"
                  className="w-full bg-[#0B0F19] border border-slate-800 rounded px-3 py-2 text-xs text-slate-100 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <label
                  htmlFor="custom-advisory-url"
                  className="block text-xs font-medium text-slate-300 mb-1"
                >
                  Source Reference URL (Optional)
                </label>
                <input
                  id="custom-advisory-url"
                  type="url"
                  value={customSourceUrl}
                  onChange={(e) => setCustomSourceUrl(e.target.value)}
                  placeholder="https://unit42.paloaltonetworks.com/..."
                  className="w-full bg-[#0B0F19] border border-slate-800 rounded px-3 py-2 text-xs text-slate-100 focus:border-cyan-500 focus:outline-none font-mono"
                />
              </div>
            </div>

            <div>
              <label
                htmlFor="custom-advisory-body"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                Raw Threat Report / Technical Details / IoCs *
              </label>
              <textarea
                id="custom-advisory-body"
                rows={4}
                value={customRawText}
                onChange={(e) => setCustomRawText(e.target.value)}
                placeholder="Paste raw threat description, observed C2 IPv4 addresses, domains, SHA-256 hashes, or attack behavior..."
                className="w-full bg-[#0B0F19] border border-slate-800 rounded px-3 py-2 text-xs text-slate-100 focus:border-cyan-500 focus:outline-none font-mono"
              />
            </div>

            <div className="flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={onClose}
                className="px-4 py-2 text-xs font-medium text-slate-300 hover:text-white"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isEnrichingCustom}
                className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 disabled:opacity-60 rounded-md transition-colors"
              >
                <Sparkles className="w-3.5 h-3.5" />
                {isEnrichingCustom
                  ? 'Parsing & Generating SecOps Pack...'
                  : 'Enrich & Generate SecOps Hunt'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};
