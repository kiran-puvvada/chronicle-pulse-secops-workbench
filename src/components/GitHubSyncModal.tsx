import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  X,
  GitBranch,
  ExternalLink,
  Check,
  Copy,
  Download,
  Lock,
  Globe,
  FileCode,
  FolderGit2,
  LogOut,
  RefreshCw,
} from 'lucide-react';
import { ThreatReport } from '../types/threat';
import {
  buildGitHubRepoFiles,
  RepoCreationOptions,
  sanitizeGitHubRepoName,
  validateRepoCreationOptions,
} from '../utils/githubSyncLogic';

interface GitHubUser {
  login: string;
  name: string;
  avatarUrl?: string;
  htmlUrl: string;
  publicRepos: number;
}

interface GitHubRepoSummary {
  id: number;
  name: string;
  fullName: string;
  htmlUrl: string;
  private: boolean;
  updatedAt: string;
}

interface GitHubSyncModalProps {
  isOpen: boolean;
  onClose: () => void;
  threats: ThreatReport[];
}

const DEV_CALLBACK_URL =
  'https://ais-dev-sdg2uufzcvqhf4o2nz7spd-993435976511.asia-southeast1.run.app/auth/callback';
const SHARED_CALLBACK_URL =
  'https://ais-pre-sdg2uufzcvqhf4o2nz7spd-993435976511.asia-southeast1.run.app/auth/callback';

export const GitHubSyncModal: React.FC<GitHubSyncModalProps> = ({
  isOpen,
  onClose,
  threats,
}) => {
  const [connected, setConnected] = useState(false);
  const [oauthConfigured, setOauthConfigured] = useState(false);
  const [user, setUser] = useState<GitHubUser | null>(null);
  const [existingRepos, setExistingRepos] = useState<GitHubRepoSummary[]>([]);
  const [isLoadingStatus, setIsLoadingStatus] = useState(false);

  // Repository Creation Form State
  const [options, setOptions] = useState<RepoCreationOptions>({
    repoName: 'chronicle-pulse-secops-workbench',
    description:
      'Real-Time Threat Intelligence & Google SecOps (Chronicle) UDM / YARA-L 2.0 Detection Workbench',
    isPrivate: false,
    includeAppSource: true,
    includeSecOpsRules: true,
    includeThreatIntel: true,
  });

  const [isCreatingRepo, setIsCreatingRepo] = useState(false);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [createdRepoResult, setCreatedRepoResult] = useState<{
    repoUrl: string;
    fullName: string;
    committedFileCount: number;
  } | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [showFilePreview, setShowFilePreview] = useState(false);

  const generatedFiles = useMemo(
    () => buildGitHubRepoFiles(threats, options),
    [threats, options]
  );

  const fetchGitHubStatus = useCallback(async () => {
    setIsLoadingStatus(true);
    try {
      const origin = encodeURIComponent(window.location.origin);
      const resp = await fetch(`/api/github/status?origin=${origin}`);
      if (resp.ok) {
        const data = await resp.json();
        setConnected(Boolean(data.connected));
        setOauthConfigured(Boolean(data.oauthConfigured));
        setUser(data.user || null);
        setExistingRepos(Array.isArray(data.repos) ? data.repos : []);
        if (data.autoCreatedRepo?.repoUrl) {
          setCreatedRepoResult({
            repoUrl: data.autoCreatedRepo.repoUrl,
            fullName: data.autoCreatedRepo.fullName,
            committedFileCount: data.autoCreatedRepo.committedFileCount,
          });
        }
      }
    } catch {
      // Ignore network error during status check
    } finally {
      setIsLoadingStatus(false);
    }
  }, []);

  useEffect(() => {
    if (isOpen) {
      fetchGitHubStatus();
      setStatusError(null);
    }
  }, [isOpen, fetchGitHubStatus]);

  // Listen for OAuth popup completion via postMessage
  useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      const origin = event.origin;
      if (
        origin &&
        !origin.endsWith('.run.app') &&
        !origin.includes('localhost')
      ) {
        return;
      }
      if (event.data?.type === 'OAUTH_AUTH_SUCCESS') {
        setStatusError(null);
        if (event.data.autoCreatedRepo?.repoUrl) {
          setCreatedRepoResult({
            repoUrl: event.data.autoCreatedRepo.repoUrl,
            fullName: event.data.autoCreatedRepo.fullName,
            committedFileCount: event.data.autoCreatedRepo.committedFileCount,
          });
        }
        fetchGitHubStatus();
      } else if (event.data?.type === 'OAUTH_AUTH_ERROR') {
        setStatusError(
          event.data.error || 'GitHub OAuth authentication did not complete.'
        );
      }
    };
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, [fetchGitHubStatus]);

  if (!isOpen) return null;

  const copyText = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const handleConnectGitHubOAuth = async () => {
    setStatusError(null);
    try {
      const origin = encodeURIComponent(window.location.origin);
      const resp = await fetch(`/api/github/auth/url?origin=${origin}`);
      const data = await resp.json();

      if (!resp.ok || !data.url) {
        setStatusError(
          data.error ||
            'Please configure CLIENT_ID and CLIENT_SECRET in AI Studio Settings > Secrets first.'
        );
        return;
      }

      // Open GitHub's OAuth authorization endpoint directly in popup
      const authPopup = window.open(
        data.url,
        'github_oauth_popup',
        'width=620,height=720'
      );

      if (!authPopup) {
        setStatusError(
          'Popup window was blocked by the browser. Please allow popups for this site and try again.'
        );
      }
    } catch {
      setStatusError('Could not initiate GitHub OAuth flow. Please try again.');
    }
  };

  const handleDisconnect = async () => {
    await fetch('/api/github/logout', { method: 'POST' });
    setConnected(false);
    setUser(null);
    setExistingRepos([]);
    setCreatedRepoResult(null);
  };

  const handleCreateRepository = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatusError(null);
    setCreatedRepoResult(null);

    const validation = validateRepoCreationOptions(options);
    if (!validation.valid) {
      setStatusError(validation.error || 'Invalid repository configuration.');
      return;
    }

    if (!connected) {
      setStatusError(
        'Please connect your GitHub account via OAuth first, or use the "Export Git-Ready Bundle" button below.'
      );
      return;
    }

    setIsCreatingRepo(true);
    try {
      const resp = await fetch('/api/github/create-repo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repoName: sanitizeGitHubRepoName(options.repoName),
          description: options.description,
          isPrivate: options.isPrivate,
          includeAppSource: options.includeAppSource,
          generatedFiles: generatedFiles.map((f) => ({
            path: f.path,
            content: f.content,
          })),
        }),
      });

      const data = await resp.json();
      if (!resp.ok || !data.ok) {
        setStatusError(
          data.error || 'Failed to create repository on GitHub.'
        );
        return;
      }

      setCreatedRepoResult({
        repoUrl: data.repoUrl,
        fullName: data.fullName,
        committedFileCount: data.committedFileCount,
      });
      fetchGitHubStatus();
    } catch {
      setStatusError('Network error while creating GitHub repository.');
    } finally {
      setIsCreatingRepo(false);
    }
  };

  const handleDownloadGitBundle = async () => {
    let appFiles: Array<{ path: string; content: string }> = [];
    if (options.includeAppSource) {
      try {
        const resp = await fetch('/api/github/source-files');
        if (resp.ok) {
          const data = await resp.json();
          appFiles = data.files || [];
        }
      } catch {
        // Proceed with generated files
      }
    }

    const bundle = {
      repositoryName: sanitizeGitHubRepoName(options.repoName),
      description: options.description,
      visibility: options.isPrivate ? 'private' : 'public',
      exportedAt: new Date().toISOString(),
      files: [
        ...appFiles,
        ...generatedFiles.map((f) => ({ path: f.path, content: f.content })),
      ],
    };

    const blob = new Blob([JSON.stringify(bundle, null, 2)], {
      type: 'application/json;charset=utf-8',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${sanitizeGitHubRepoName(options.repoName) || 'secops-repo'}-git-bundle.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const estimatedTotalFiles =
    (options.includeAppSource ? 20 : 0) + generatedFiles.length;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="github-sync-modal-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 overflow-y-auto"
    >
      <div className="bg-[#0B0F19] border border-slate-800 rounded-lg w-full max-w-4xl max-h-[92vh] flex flex-col overflow-hidden shadow-2xl">
        {/* Header */}
        <div className="px-6 py-4 bg-[#111827] border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <FolderGit2 className="w-5 h-5 text-cyan-400" />
            <div>
              <h2
                id="github-sync-modal-title"
                className="text-base font-bold text-slate-100"
              >
                GitHub Repository Creator &amp; SecOps Detection Sync
              </h2>
              <p className="text-xs text-slate-400">
                Connect via GitHub OAuth to create a new repository and commit the full application source code, YARA-L 2.0 rules, and UDM hunt queries
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            aria-label="Close GitHub repository modal"
            className="p-2 text-slate-400 hover:text-slate-100 bg-slate-800/70 rounded-md"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          {statusError && (
            <div
              role="alert"
              className="p-3.5 bg-rose-950/50 border border-rose-700/70 rounded-md text-xs text-rose-200 flex items-center justify-between gap-4"
            >
              <span>{statusError}</span>
              <button
                type="button"
                onClick={() => setStatusError(null)}
                className="text-rose-300 hover:text-white shrink-0"
              >
                Dismiss
              </button>
            </div>
          )}

          {createdRepoResult && (
            <div className="p-4 bg-emerald-950/40 border border-emerald-600/60 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <div className="text-sm font-semibold text-emerald-300 flex items-center gap-2">
                  <Check className="w-4 h-4" />
                  Repository Created &amp; Populated: {createdRepoResult.fullName}
                </div>
                <p className="text-xs text-slate-300 mt-0.5 font-mono tabular-nums">
                  Committed {createdRepoResult.committedFileCount} files (App source, YARA-L 2.0 rules, UDM queries, and STIX 2.1 bundle) to main branch.
                </p>
              </div>
              <a
                href={createdRepoResult.repoUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 rounded-md transition-colors whitespace-nowrap shrink-0"
              >
                Open on GitHub
                <ExternalLink className="w-3.5 h-3.5" />
              </a>
            </div>
          )}

          {/* Section 1: GitHub Account Connection & OAuth Setup */}
          <div className="bg-[#111827] border border-slate-800 rounded-lg p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  1. GitHub OAuth Authentication Status
                </h3>
                <p className="text-xs text-slate-400">
                  Authenticate with `repo` scope to create public or private repositories in your GitHub account
                </p>
              </div>

              {connected && user ? (
                <div className="flex items-center gap-3">
                  <a
                    href={user.htmlUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs font-mono text-emerald-300 hover:underline"
                  >
                    Connected as @{user.login}
                  </a>
                  <button
                    type="button"
                    onClick={handleDisconnect}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    Disconnect
                  </button>
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={fetchGitHubStatus}
                    disabled={isLoadingStatus}
                    className="inline-flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-md transition-colors"
                  >
                    <RefreshCw
                      className={`w-3.5 h-3.5 ${isLoadingStatus ? 'animate-spin' : ''}`}
                    />
                    Check Status
                  </button>
                  <button
                    type="button"
                    onClick={handleConnectGitHubOAuth}
                    className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-md transition-colors whitespace-nowrap"
                  >
                    <GitBranch className="w-3.5 h-3.5" />
                    Connect with GitHub OAuth
                  </button>
                </div>
              )}
            </div>

            {/* Callback URL Reference Box for GitHub OAuth App Configuration */}
            {!connected && (
              <div className="bg-[#0B0F19] border border-slate-800 rounded-md p-3.5 space-y-2 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-medium text-slate-200">
                    GitHub OAuth App Callback URLs (Register at{' '}
                    <a
                      href="https://github.com/settings/developers"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-cyan-400 hover:underline"
                    >
                      github.com/settings/developers
                    </a>
                    , then set <code className="text-emerald-300">CLIENT_ID</code> &amp;{' '}
                    <code className="text-emerald-300">CLIENT_SECRET</code> in Settings &gt; Secrets):
                  </span>
                  <span className="font-mono text-[11px] text-slate-400">
                    {oauthConfigured ? 'OAuth Client ID Detected' : 'Awaiting CLIENT_ID Secret'}
                  </span>
                </div>

                <div className="grid grid-cols-1 gap-2 pt-1 font-mono">
                  <div className="flex items-center justify-between gap-2 bg-[#111827] border border-slate-800/90 px-3 py-1.5 rounded">
                    <span className="text-slate-400 shrink-0">Dev Callback:</span>
                    <span className="text-cyan-300 truncate">{DEV_CALLBACK_URL}</span>
                    <button
                      type="button"
                      onClick={() => copyText(DEV_CALLBACK_URL, 'dev-cb')}
                      className="text-slate-300 hover:text-white shrink-0 inline-flex items-center gap-1"
                    >
                      {copiedKey === 'dev-cb' ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                      {copiedKey === 'dev-cb' ? 'Copied' : 'Copy'}
                    </button>
                  </div>

                  <div className="flex items-center justify-between gap-2 bg-[#111827] border border-slate-800/90 px-3 py-1.5 rounded">
                    <span className="text-slate-400 shrink-0">Shared Callback:</span>
                    <span className="text-cyan-300 truncate">{SHARED_CALLBACK_URL}</span>
                    <button
                      type="button"
                      onClick={() => copyText(SHARED_CALLBACK_URL, 'shared-cb')}
                      className="text-slate-300 hover:text-white shrink-0 inline-flex items-center gap-1"
                    >
                      {copiedKey === 'shared-cb' ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                      {copiedKey === 'shared-cb' ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Existing Repositories Quick List when Connected */}
            {connected && existingRepos.length > 0 && (
              <div className="pt-2 border-t border-slate-800/80">
                <span className="text-xs text-slate-400 block mb-2">
                  Recent Repositories on Your GitHub Account:
                </span>
                <div className="flex flex-wrap gap-2">
                  {existingRepos.map((repo) => (
                    <a
                      key={repo.id}
                      href={repo.htmlUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-[#0B0F19] border border-slate-800 hover:border-slate-700 rounded text-xs font-mono text-slate-300 hover:text-cyan-300"
                    >
                      <span>{repo.fullName}</span>
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Section 2: Create New GitHub Repository & Commit Form */}
          <form
            onSubmit={handleCreateRepository}
            className="bg-[#111827] border border-slate-800 rounded-lg p-5 space-y-4"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h3 className="text-sm font-semibold text-slate-100">
                  2. Create New GitHub Repository &amp; Commit Files
                </h3>
                <p className="text-xs text-slate-400">
                  Initializes a new repository on GitHub and pushes {estimatedTotalFiles} files in an atomic commit
                </p>
              </div>

              <button
                type="button"
                onClick={() => setShowFilePreview((prev) => !prev)}
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300"
              >
                {showFilePreview
                  ? 'Hide Commit Tree Preview'
                  : `Inspect Commit Tree (${estimatedTotalFiles} files)`}
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label
                  htmlFor="github-repo-name"
                  className="block text-xs font-medium text-slate-300 mb-1"
                >
                  Repository Name *
                </label>
                <input
                  id="github-repo-name"
                  type="text"
                  value={options.repoName}
                  onChange={(e) =>
                    setOptions((prev) => ({ ...prev, repoName: e.target.value }))
                  }
                  placeholder="chronicle-pulse-secops-workbench"
                  className="w-full bg-[#0B0F19] border border-slate-800 rounded px-3 py-2 text-xs text-slate-100 font-mono focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <div>
                <span className="block text-xs font-medium text-slate-300 mb-1">
                  Repository Visibility
                </span>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    onClick={() =>
                      setOptions((prev) => ({ ...prev, isPrivate: false }))
                    }
                    className={`flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-medium rounded border transition-colors ${
                      !options.isPrivate
                        ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-300'
                        : 'bg-[#0B0F19] border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Globe className="w-3.5 h-3.5" />
                    Public Repo
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      setOptions((prev) => ({ ...prev, isPrivate: true }))
                    }
                    className={`flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-medium rounded border transition-colors ${
                      options.isPrivate
                        ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-300'
                        : 'bg-[#0B0F19] border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Lock className="w-3.5 h-3.5" />
                    Private Repo
                  </button>
                </div>
              </div>
            </div>

            <div>
              <label
                htmlFor="github-repo-desc"
                className="block text-xs font-medium text-slate-300 mb-1"
              >
                Repository Description
              </label>
              <input
                id="github-repo-desc"
                type="text"
                value={options.description}
                onChange={(e) =>
                  setOptions((prev) => ({
                    ...prev,
                    description: e.target.value,
                  }))
                }
                className="w-full bg-[#0B0F19] border border-slate-800 rounded px-3 py-2 text-xs text-slate-100 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            {/* Content Checkboxes */}
            <div className="space-y-2 pt-2 border-t border-slate-800/80">
              <span className="block text-xs font-medium text-slate-300">
                Packages to Commit into Repository:
              </span>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 text-xs">
                <label className="flex items-start gap-2.5 p-3 bg-[#0B0F19] border border-slate-800 rounded cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.includeAppSource}
                    onChange={(e) =>
                      setOptions((prev) => ({
                        ...prev,
                        includeAppSource: e.target.checked,
                      }))
                    }
                    className="mt-0.5 rounded border-slate-700 bg-slate-900 text-cyan-500"
                  />
                  <div>
                    <span className="font-medium text-slate-100 block">
                      Full Web App Source Code
                    </span>
                    <span className="text-[11px] text-slate-400 font-mono">
                      package.json, server.ts, src/**
                    </span>
                  </div>
                </label>

                <label className="flex items-start gap-2.5 p-3 bg-[#0B0F19] border border-slate-800 rounded cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.includeSecOpsRules}
                    onChange={(e) =>
                      setOptions((prev) => ({
                        ...prev,
                        includeSecOpsRules: e.target.checked,
                      }))
                    }
                    className="mt-0.5 rounded border-slate-700 bg-slate-900 text-cyan-500"
                  />
                  <div>
                    <span className="font-medium text-slate-100 block">
                      SecOps YARA-L 2.0 &amp; UDM
                    </span>
                    <span className="text-[11px] text-slate-400 font-mono">
                      secops-rules/*.yaral &amp; *.udm
                    </span>
                  </div>
                </label>

                <label className="flex items-start gap-2.5 p-3 bg-[#0B0F19] border border-slate-800 rounded cursor-pointer">
                  <input
                    type="checkbox"
                    checked={options.includeThreatIntel}
                    onChange={(e) =>
                      setOptions((prev) => ({
                        ...prev,
                        includeThreatIntel: e.target.checked,
                      }))
                    }
                    className="mt-0.5 rounded border-slate-700 bg-slate-900 text-cyan-500"
                  />
                  <div>
                    <span className="font-medium text-slate-100 block">
                      STIX 2.1 &amp; Advisories
                    </span>
                    <span className="text-[11px] text-slate-400 font-mono">
                      threat-intel/stix21-bundle.json
                    </span>
                  </div>
                </label>
              </div>
            </div>

            {/* File Tree Preview */}
            {showFilePreview && (
              <div className="bg-[#0B0F19] border border-slate-800 rounded p-3 max-h-44 overflow-y-auto space-y-1 font-mono text-xs">
                {options.includeAppSource && (
                  <div className="text-slate-400 pb-1 border-b border-slate-800/80">
                    + 20 Application Source Files (package.json, server.ts, index.html, src/App.tsx, src/components/*.tsx, src/utils/*.ts)
                  </div>
                )}
                {generatedFiles.map((f) => (
                  <div
                    key={f.path}
                    className="flex items-center justify-between gap-2 py-0.5 text-slate-300"
                  >
                    <span className="inline-flex items-center gap-1.5 text-cyan-300 truncate">
                      <FileCode className="w-3.5 h-3.5 shrink-0" />
                      {f.path}
                    </span>
                    <span className="text-[11px] text-slate-500 truncate">
                      {f.description}
                    </span>
                  </div>
                ))}
              </div>
            )}

            {/* Submit & Bundle Download Footer */}
            <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
              <button
                type="button"
                onClick={handleDownloadGitBundle}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-medium text-slate-200 bg-[#0B0F19] hover:bg-slate-800 border border-slate-800 rounded-md transition-colors"
              >
                <Download className="w-3.5 h-3.5 text-cyan-400" />
                Download Git-Ready Repository Bundle (.json)
              </button>

              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-3.5 py-2 text-xs font-medium text-slate-400 hover:text-white"
                >
                  Close
                </button>
                <button
                  type="submit"
                  disabled={isCreatingRepo}
                  className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 disabled:opacity-60 rounded-md transition-colors whitespace-nowrap"
                >
                  <FolderGit2 className="w-3.5 h-3.5" />
                  {isCreatingRepo
                    ? 'Creating Repo & Committing Files...'
                    : 'Create GitHub Repository & Push Files'}
                </button>
              </div>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};
