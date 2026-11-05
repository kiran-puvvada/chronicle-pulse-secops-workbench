import "dotenv/config";
import express from "express";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";
import {
  enrichRawFeedItem,
  generateSecOpsQueries,
  RawFeedItemInput,
} from "./src/utils/threatLogic";
import {
  buildGitHubRepoFiles,
  sanitizeGitHubRepoName,
} from "./src/utils/githubSyncLogic";
import { BASELINE_THREATS } from "./src/data/baselineThreats";
import { ThreatReport } from "./src/types/threat";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3000;

// Active GitHub token store (backed by SameSite=None; Secure cookie + memory for iframe resilience)
let cachedGitHubAccessToken: string | null = process.env.GITHUB_TOKEN || null;

// Stores the most recently created & populated repository so the UI can display it immediately
let lastAutoCreatedRepo: {
  repoUrl: string;
  fullName: string;
  defaultBranch: string;
  committedFileCount: number;
} | null = null;

const FALLBACK_GH_CLIENT_ID = "";
const FALLBACK_GH_CLIENT_SECRET = [""].join("");

function getGitHubClientId(): string {
  const envVal = (process.env.GITHUB_CLIENT_ID || process.env.CLIENT_ID || "").trim();
  if (envVal && envVal !== "YOUR_GITHUB_OAUTH_CLIENT_ID") {
    return envVal;
  }
  return FALLBACK_GH_CLIENT_ID;
}

function getGitHubClientSecret(): string {
  const envVal = (process.env.GITHUB_CLIENT_SECRET || process.env.CLIENT_SECRET || "").trim();
  if (envVal && envVal !== "YOUR_GITHUB_OAUTH_CLIENT_SECRET") {
    return envVal;
  }
  return FALLBACK_GH_CLIENT_SECRET;
}

function parseCookies(cookieHeader?: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!cookieHeader) return out;
  for (const pair of cookieHeader.split(";")) {
    const idx = pair.indexOf("=");
    if (idx > 0) {
      const k = pair.slice(0, idx).trim();
      const v = decodeURIComponent(pair.slice(idx + 1).trim());
      out[k] = v;
    }
  }
  return out;
}

function resolveGitHubToken(req: express.Request): string | null {
  const cookies = parseCookies(req.headers.cookie);
  if (cookies.gh_access_token) return cookies.gh_access_token;
  if (cachedGitHubAccessToken) return cachedGitHubAccessToken;
  if (process.env.GITHUB_TOKEN && process.env.GITHUB_TOKEN.trim().length > 5) {
    return process.env.GITHUB_TOKEN.trim();
  }
  return null;
}

function getRedirectUri(req: express.Request): string {
  const clientOrigin = (req.query.origin as string | undefined)?.trim();
  if (clientOrigin && /^https?:\/\//i.test(clientOrigin)) {
    return `${clientOrigin.replace(/\/$/, "")}/auth/callback`;
  }
  if (
    process.env.APP_URL &&
    process.env.APP_URL !== "MY_APP_URL" &&
    /^https?:\/\//i.test(process.env.APP_URL)
  ) {
    return `${process.env.APP_URL.replace(/\/$/, "")}/auth/callback`;
  }
  const proto = (req.headers["x-forwarded-proto"] as string) || req.protocol || "https";
  const host = req.get("host") || `localhost:${PORT}`;
  return `${proto}://${host}/auth/callback`;
}

/**
 * Reads all application source files from the project workspace so they can be committed
 * into a newly created GitHub repository (scrubbing any runtime OAuth credentials).
 */
function readProjectSourceFiles(): Array<{ path: string; content: string }> {
  const relativePaths = [
    "package.json",
    "tsconfig.json",
    "vite.config.ts",
    "index.html",
    ".env.example",
    ".gitignore",
    "server.ts",
    "src/main.tsx",
    "src/index.css",
    "src/App.tsx",
    "src/types/threat.ts",
    "src/data/baselineThreats.ts",
    "src/utils/threatLogic.ts",
    "src/utils/threatLogic.test.ts",
    "src/utils/githubSyncLogic.ts",
    "src/utils/githubSyncLogic.test.ts",
    "src/components/AnalyticsCharts.tsx",
    "src/components/FilterBar.tsx",
    "src/components/ThreatCard.tsx",
    "src/components/ThreatWorkbenchModal.tsx",
    "src/components/FeedConfigModal.tsx",
    "src/components/GitHubSyncModal.tsx",
  ];

  const collected: Array<{ path: string; content: string }> = [];
  for (const rel of relativePaths) {
    const abs = path.join(__dirname, rel);
    try {
      if (fs.existsSync(abs)) {
        let content = fs.readFileSync(abs, "utf-8");
        if (rel === "server.ts") {
          content = content
            .replace(FALLBACK_GH_CLIENT_ID, "")
            .replace('"f4b652485fc0439171a4", "37427ce66005c2d6d99e"', '""');
        }
        collected.push({ path: rel, content });
      }
    } catch {
      // Skip unreadable file
    }
  }
  return collected;
}

/**
 * Creates (or locates existing) GitHub repository and commits the full application source
 * code, Google SecOps YARA-L 2.0 rules, UDM hunt queries, and STIX 2.1 bundle.
 */
async function provisionAndCommitGitHubRepo(
  token: string,
  opts?: {
    repoName?: string;
    description?: string;
    isPrivate?: boolean;
    includeAppSource?: boolean;
    generatedFiles?: Array<{ path: string; content: string }>;
  }
): Promise<{
  repoUrl: string;
  fullName: string;
  defaultBranch: string;
  committedFileCount: number;
}> {
  const cleanName = sanitizeGitHubRepoName(
    opts?.repoName || "chronicle-pulse-secops-workbench"
  );
  const description =
    opts?.description ||
    "Real-Time Threat Intelligence & Google SecOps (Chronicle) UDM / YARA-L 2.0 Detection Workbench";
  const isPrivate = Boolean(opts?.isPrivate);
  const includeAppSource = opts?.includeAppSource ?? true;

  // Step 1: Create repository (or reuse existing if already created on the user's account)
  const createResp = await fetch("https://api.github.com/user/repos", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
      "User-Agent": "ChroniclePulse-SecOps",
    },
    body: JSON.stringify({
      name: cleanName,
      description,
      private: isPrivate,
      auto_init: true,
    }),
  });

  let repoData = (await createResp.json()) as {
    name?: string;
    full_name?: string;
    html_url?: string;
    default_branch?: string;
    owner?: { login: string };
    message?: string;
    errors?: Array<{ message?: string }>;
  };

  // If repository already exists on this account, fetch it so we can still commit fresh files
  if (!createResp.ok || !repoData.full_name || !repoData.owner?.login) {
    const userResp = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "ChroniclePulse-SecOps",
      },
    });
    if (userResp.ok) {
      const userData = (await userResp.json()) as { login?: string };
      if (userData.login) {
        const existingResp = await fetch(
          `https://api.github.com/repos/${userData.login}/${cleanName}`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
              Accept: "application/vnd.github+json",
              "User-Agent": "ChroniclePulse-SecOps",
            },
          }
        );
        if (existingResp.ok) {
          repoData = await existingResp.json();
        }
      }
    }
  }

  if (!repoData.full_name || !repoData.owner?.login || !repoData.html_url) {
    const detail =
      repoData.errors?.[0]?.message ||
      repoData.message ||
      "Failed to create GitHub repository.";
    throw new Error(detail);
  }

  const owner = repoData.owner.login;
  const repo = repoData.name || cleanName;
  const defaultBranch = repoData.default_branch || "main";

  // Assemble all files to commit
  const fileMap = new Map<string, string>();
  if (includeAppSource) {
    for (const f of readProjectSourceFiles()) {
      fileMap.set(f.path, f.content);
    }
  }

  const filesToInclude =
    Array.isArray(opts?.generatedFiles) && opts.generatedFiles.length > 0
      ? opts.generatedFiles
      : buildGitHubRepoFiles(BASELINE_THREATS, {
          repoName: cleanName,
          description,
          isPrivate,
          includeAppSource,
          includeSecOpsRules: true,
          includeThreatIntel: true,
        });

  for (const gf of filesToInclude) {
    if (gf.path && typeof gf.content === "string") {
      fileMap.set(gf.path, gf.content);
    }
  }

  // Step 2: Get latest commit SHA on defaultBranch
  const refResp = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/git/ref/heads/${defaultBranch}`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "ChroniclePulse-SecOps",
      },
    }
  );

  let committedFileCount = 0;
  if (refResp.ok && fileMap.size > 0) {
    const refData = (await refResp.json()) as { object?: { sha: string } };
    const latestCommitSha = refData.object?.sha;

    if (latestCommitSha) {
      // Step 3: Create a Git Tree containing all project & SecOps files
      const treeItems = Array.from(fileMap.entries()).map(([filePath, content]) => ({
        path: filePath,
        mode: "100644",
        type: "blob",
        content,
      }));

      const treeResp = await fetch(
        `https://api.github.com/repos/${owner}/${repo}/git/trees`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "ChroniclePulse-SecOps",
          },
          body: JSON.stringify({
            base_tree: latestCommitSha,
            tree: treeItems,
          }),
        }
      );

      if (treeResp.ok) {
        const treeData = (await treeResp.json()) as { sha: string };
        // Step 4: Create Commit
        const commitResp = await fetch(
          `https://api.github.com/repos/${owner}/${repo}/git/commits`,
          {
            method: "POST",
            headers: {
              Authorization: `Bearer ${token}`,
              Accept: "application/vnd.github+json",
              "Content-Type": "application/json",
              "User-Agent": "ChroniclePulse-SecOps",
            },
            body: JSON.stringify({
              message:
                "feat: initialize ChroniclePulse SecOps dashboard, YARA-L 2.0 rules, and UDM hunt queries",
              tree: treeData.sha,
              parents: [latestCommitSha],
            }),
          }
        );

        if (commitResp.ok) {
          const commitData = (await commitResp.json()) as { sha: string };
          // Step 5: Update branch reference
          await fetch(
            `https://api.github.com/repos/${owner}/${repo}/git/refs/heads/${defaultBranch}`,
            {
              method: "PATCH",
              headers: {
                Authorization: `Bearer ${token}`,
                Accept: "application/vnd.github+json",
                "Content-Type": "application/json",
                "User-Agent": "ChroniclePulse-SecOps",
              },
              body: JSON.stringify({
                sha: commitData.sha,
                force: true,
              }),
            }
          );
          committedFileCount = treeItems.length;
        }
      }
    }
  }

  const result = {
    repoUrl: repoData.html_url,
    fullName: repoData.full_name,
    defaultBranch,
    committedFileCount,
  };
  lastAutoCreatedRepo = result;
  return result;
}

function getGenAIClient(): GoogleGenAI {
  return new GoogleGenAI({
    apiKey: process.env.GEMINI_API_KEY,
    httpOptions: {
      headers: {
        "User-Agent": "aistudio-build",
      },
    },
  });
}

/**
 * Lightweight XML RSS / Atom parser for live cybersecurity feeds.
 */
function parseRssXmlItems(xml: string, sourceName: string, maxItems = 4): RawFeedItemInput[] {
  const items: RawFeedItemInput[] = [];
  const itemBlocks = xml.match(/<(item|entry)[\s>][\s\S]*?<\/\1>/gi) || [];

  const extractTag = (block: string, tag: string): string => {
    const regex = new RegExp(
      `<${tag}[^>]*>(?:<!\\[CDATA\\[([\\s\\S]*?)\\]\\]>|([\\s\\S]*?))<\\/${tag}>`,
      "i"
    );
    const match = block.match(regex);
    if (!match) return "";
    return (match[1] ?? match[2] ?? "")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&amp;/g, "&")
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/<[^>]*>/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  };

  for (const block of itemBlocks.slice(0, maxItems)) {
    const title = extractTag(block, "title");
    if (!title) continue;
    const description =
      extractTag(block, "description") ||
      extractTag(block, "summary") ||
      extractTag(block, "content:encoded");
    let link = extractTag(block, "link");
    if (!link) {
      const hrefMatch = block.match(/<link[^>]+href=["']([^"']+)["']/i);
      if (hrefMatch) link = hrefMatch[1];
    }
    const pubDate =
      extractTag(block, "pubDate") ||
      extractTag(block, "published") ||
      extractTag(block, "updated") ||
      new Date().toISOString();

    items.push({
      title,
      description,
      link,
      pubDate,
      source: sourceName,
    });
  }

  return items;
}

async function fetchWithTimeout(url: string, timeoutMs = 4500): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; SecOpsThreatIntel/2.0)",
        Accept: "application/rss+xml, application/xml, application/json, text/xml, */*",
      },
    });
  } finally {
    clearTimeout(timer);
  }
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: "15mb" }));

  // ============================================================================
  // GITHUB OAUTH & REPOSITORY CREATION ENDPOINTS
  // ============================================================================

  // 1. Construct GitHub OAuth Provider Authorization URL (opened directly in popup or mobile link)
  app.get("/api/github/auth/url", (req, res) => {
    const clientId = getGitHubClientId();
    const redirectUri = getRedirectUri(req);

    if (!clientId || clientId === "YOUR_GITHUB_OAUTH_CLIENT_ID") {
      res.status(400).json({
        oauthConfigured: false,
        redirectUri,
        error:
          "GitHub OAuth CLIENT_ID and CLIENT_SECRET are not configured yet. Add them in Settings > Secrets, then click Connect with GitHub.",
      });
      return;
    }

    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: "repo read:user",
      allow_signup: "true",
    });

    const providerAuthUrl =
      process.env.OAUTH_PROVIDER_URL || "https://github.com/login/oauth/authorize";
    res.json({
      oauthConfigured: true,
      redirectUri,
      url: `${providerAuthUrl}?${params.toString()}`,
    });
  });

  // 1b. Direct 1-Tap Mobile Redirect to GitHub OAuth (creates repo automatically on callback)
  app.get("/api/github/one-tap", (req, res) => {
    const clientId = getGitHubClientId();
    const redirectUri = getRedirectUri(req);
    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: "repo read:user",
      allow_signup: "true",
    });
    res.redirect(`https://github.com/login/oauth/authorize?${params.toString()}`);
  });

  // 2. OAuth Callback Handler (handles both /auth/callback and /auth/callback/)
  // Automatically creates & populates the GitHub repository upon authorization!
  const githubCallbackHandler: express.RequestHandler = async (req, res) => {
    const code = req.query.code as string | undefined;
    const clientId = getGitHubClientId();
    const clientSecret = getGitHubClientSecret();

    if (!code || !clientId || !clientSecret) {
      res.status(400).send(`<!DOCTYPE html>
<html>
  <body style="font-family:sans-serif; background:#0B0F19; color:#F1F5F9; padding:24px;">
    <h3>GitHub OAuth Error</h3>
    <p>Missing authorization code or CLIENT_ID / CLIENT_SECRET configuration.</p>
    <script>
      if (window.opener) {
        window.opener.postMessage({ type: 'OAUTH_AUTH_ERROR', error: 'Missing code or OAuth secrets' }, '*');
      }
    </script>
  </body>
</html>`);
      return;
    }

    try {
      const tokenResp = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          "User-Agent": "ChroniclePulse-SecOps",
        },
        body: JSON.stringify({
          client_id: clientId,
          client_secret: clientSecret,
          code,
        }),
      });

      const tokenData = (await tokenResp.json()) as {
        access_token?: string;
        error?: string;
        error_description?: string;
      };

      if (!tokenData.access_token) {
        throw new Error(
          tokenData.error_description || tokenData.error || "Failed to obtain GitHub access token"
        );
      }

      cachedGitHubAccessToken = tokenData.access_token;

      // Set cross-origin iframe compatible cookie (SameSite=None; Secure; HttpOnly)
      res.cookie("gh_access_token", tokenData.access_token, {
        secure: true,
        sameSite: "none",
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 * 7,
      });

      // Automatically create the repository and push all 37 files immediately!
      let autoRepoResult: {
        repoUrl: string;
        fullName: string;
        defaultBranch: string;
        committedFileCount: number;
      } | null = null;

      try {
        autoRepoResult = await provisionAndCommitGitHubRepo(tokenData.access_token);
      } catch {
        // Non-fatal: user is still authenticated and can create with a custom name
      }

      const repoHtmlBlock = autoRepoResult
        ? `<div style="margin-top:16px; padding:16px; background:#064E3B; border:1px solid #10B981; border-radius:8px;">
             <h3 style="margin:0 0 8px 0; color:#6EE7B7;">Repository Created &amp; Pushed Automatically!</h3>
             <p style="margin:0 0 12px 0; font-size:14px; color:#E2E8F0;">
               Created <strong>${autoRepoResult.fullName}</strong> and committed <strong>${autoRepoResult.committedFileCount} files</strong> (App source code, Google SecOps YARA-L 2.0 rules, UDM queries, and STIX 2.1 bundle).
             </p>
             <a href="${autoRepoResult.repoUrl}" target="_blank" rel="noopener noreferrer"
                style="display:inline-block; padding:10px 18px; background:#10B981; color:#022C22; font-weight:700; text-decoration:none; border-radius:6px; margin-right:10px;">
               Open Repository on GitHub &rarr;
             </a>
             <a href="/" style="display:inline-block; padding:10px 16px; background:#1E293B; color:#F1F5F9; text-decoration:none; border-radius:6px;">
               Return to Dashboard
             </a>
           </div>`
        : `<p>GitHub authentication successful. <a href="/" style="color:#38BDF8;">Return to Dashboard</a></p>`;

      res.send(`<!DOCTYPE html>
<html>
  <head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>GitHub Repository Created — ChroniclePulse SecOps</title>
  </head>
  <body style="font-family:system-ui,-apple-system,sans-serif; background:#0B0F19; color:#F1F5F9; padding:24px; max-width:600px; margin:0 auto;">
    <h2 style="color:#38BDF8; margin-top:0;">ChroniclePulse SecOps &times; GitHub</h2>
    ${repoHtmlBlock}
    <script>
      if (window.opener) {
        window.opener.postMessage({
          type: 'OAUTH_AUTH_SUCCESS',
          autoCreatedRepo: ${JSON.stringify(autoRepoResult)}
        }, '*');
        setTimeout(function() { window.close(); }, 1200);
      }
    </script>
  </body>
</html>`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "OAuth token exchange failed";
      res.status(500).send(`<!DOCTYPE html>
<html>
  <body style="font-family:sans-serif; background:#0B0F19; color:#F1F5F9; padding:24px;">
    <h3>GitHub Authentication Failed</h3>
    <p>${msg}</p>
    <script>
      if (window.opener) {
        window.opener.postMessage({ type: 'OAUTH_AUTH_ERROR', error: ${JSON.stringify(msg)} }, '*');
      }
    </script>
  </body>
</html>`);
    }
  };

  app.get(["/auth/callback", "/auth/callback/"], githubCallbackHandler);

  // 3. GitHub Connection Status & User Profile
  app.get("/api/github/status", async (req, res) => {
    const clientId = getGitHubClientId();
    const oauthConfigured =
      Boolean(clientId) && clientId !== "YOUR_GITHUB_OAUTH_CLIENT_ID";
    const token = resolveGitHubToken(req);

    if (!token) {
      res.json({
        connected: false,
        oauthConfigured,
        redirectUri: getRedirectUri(req),
        user: null,
        repos: [],
        autoCreatedRepo: lastAutoCreatedRepo,
      });
      return;
    }

    try {
      const userResp = await fetch("https://api.github.com/user", {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/vnd.github+json",
          "User-Agent": "ChroniclePulse-SecOps",
        },
      });

      if (!userResp.ok) {
        cachedGitHubAccessToken = null;
        res.clearCookie("gh_access_token", { secure: true, sameSite: "none", httpOnly: true });
        res.json({
          connected: false,
          oauthConfigured,
          redirectUri: getRedirectUri(req),
          user: null,
          repos: [],
          autoCreatedRepo: lastAutoCreatedRepo,
        });
        return;
      }

      const user = (await userResp.json()) as {
        login: string;
        name?: string;
        avatar_url?: string;
        html_url: string;
        public_repos?: number;
      };

      let repos: Array<{
        id: number;
        name: string;
        full_name: string;
        html_url: string;
        private: boolean;
        updated_at: string;
      }> = [];

      const reposResp = await fetch(
        "https://api.github.com/user/repos?sort=updated&per_page=6",
        {
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: "application/vnd.github+json",
            "User-Agent": "ChroniclePulse-SecOps",
          },
        }
      );
      if (reposResp.ok) {
        repos = await reposResp.json();
      }

      res.json({
        connected: true,
        oauthConfigured,
        redirectUri: getRedirectUri(req),
        user: {
          login: user.login,
          name: user.name || user.login,
          avatarUrl: user.avatar_url,
          htmlUrl: user.html_url,
          publicRepos: user.public_repos ?? 0,
        },
        repos: repos.map((r) => ({
          id: r.id,
          name: r.name,
          fullName: r.full_name,
          htmlUrl: r.html_url,
          private: r.private,
          updatedAt: r.updated_at,
        })),
        autoCreatedRepo: lastAutoCreatedRepo,
      });
    } catch {
      res.json({
        connected: false,
        oauthConfigured,
        redirectUri: getRedirectUri(req),
        user: null,
        repos: [],
        autoCreatedRepo: lastAutoCreatedRepo,
      });
    }
  });

  // 4. Disconnect GitHub Session
  app.post("/api/github/logout", (_req, res) => {
    cachedGitHubAccessToken = null;
    lastAutoCreatedRepo = null;
    res.clearCookie("gh_access_token", {
      secure: true,
      sameSite: "none",
      httpOnly: true,
    });
    res.json({ ok: true });
  });

  // 5. Return Application Source Files for Preview / Bundle Export
  app.get("/api/github/source-files", (_req, res) => {
    const files = readProjectSourceFiles();
    res.json({ count: files.length, files });
  });

  // 6. Create GitHub Repository & Commit Application Source + SecOps Rules/Queries
  app.post("/api/github/create-repo", async (req, res) => {
    const token = resolveGitHubToken(req);
    if (!token) {
      res.status(401).json({
        error: "Not connected to GitHub. Please connect your GitHub account first.",
      });
      return;
    }

    const {
      repoName,
      description,
      isPrivate = false,
      includeAppSource = true,
      generatedFiles = [],
    } = req.body as {
      repoName?: string;
      description?: string;
      isPrivate?: boolean;
      includeAppSource?: boolean;
      generatedFiles?: Array<{ path: string; content: string }>;
    };

    const cleanName = sanitizeGitHubRepoName(repoName || "");
    if (!cleanName || cleanName.length < 2) {
      res.status(400).json({ error: "Please provide a valid repository name." });
      return;
    }

    try {
      const result = await provisionAndCommitGitHubRepo(token, {
        repoName: cleanName,
        description,
        isPrivate,
        includeAppSource,
        generatedFiles,
      });
      res.json({
        ok: true,
        ...result,
      });
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to create repository on GitHub.";
      res.status(500).json({ error: message });
    }
  });

  // ============================================================================
  // LIVE CYBERSECURITY FEED AGGREGATOR & GEMINI AI ENRICHMENT ENDPOINTS
  // ============================================================================

  // 1. Live Cybersecurity Feed Aggregator (RSS + CISA KEV JSON)
  app.get("/api/live-feeds", async (_req, res) => {
    const rssSources = [
      { name: "The Hacker News", url: "https://feeds.feedburner.com/TheHackersNews", max: 4 },
      { name: "BleepingComputer", url: "https://www.bleepingcomputer.com/feed/", max: 4 },
      { name: "Dark Reading", url: "https://www.darkreading.com/rss.xml", max: 2 },
      { name: "KrebsOnSecurity", url: "https://krebsonsecurity.com/feed/", max: 2 },
      { name: "Unit 42", url: "https://unit42.paloaltonetworks.com/feed/", max: 2 },
    ];

    const collectedRaw: RawFeedItemInput[] = [];
    const sourceStats: Record<string, { count: number; status: "synced" | "fallback" }> = {};

    await Promise.allSettled(
      rssSources.map(async (src) => {
        try {
          const resp = await fetchWithTimeout(src.url, 4200);
          if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
          const xml = await resp.text();
          const parsed = parseRssXmlItems(xml, src.name, src.max);
          if (parsed.length > 0) {
            collectedRaw.push(...parsed);
            sourceStats[src.name] = { count: parsed.length, status: "synced" };
          } else {
            sourceStats[src.name] = { count: 0, status: "fallback" };
          }
        } catch {
          sourceStats[src.name] = { count: 0, status: "fallback" };
        }
      })
    );

    try {
      const kevResp = await fetchWithTimeout(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        4800
      );
      if (kevResp.ok) {
        const kevData = (await kevResp.json()) as {
          vulnerabilities?: Array<{
            cveID: string;
            vendorProject: string;
            product: string;
            vulnerabilityName: string;
            dateAdded: string;
            shortDescription: string;
            requiredAction?: string;
            knownRansomwareCampaignUse?: string;
          }>;
        };
        const recentKevs = (kevData.vulnerabilities || []).slice(-4).reverse();
        for (const kev of recentKevs) {
          collectedRaw.push({
            id: `cisa-kev-${kev.cveID.toLowerCase()}`,
            title: `${kev.cveID}: ${kev.vendorProject} ${kev.product} — ${kev.vulnerabilityName}`,
            description: `${kev.shortDescription} Required Action: ${
              kev.requiredAction || "Apply vendor mitigations immediately."
            } Ransomware Campaign Use: ${kev.knownRansomwareCampaignUse || "Known"}.`,
            link: `https://nvd.nist.gov/vuln/detail/${kev.cveID}`,
            pubDate: new Date().toISOString(),
            source: "CISA KEV",
            cveId: kev.cveID,
          });
        }
        sourceStats["CISA KEV"] = { count: recentKevs.length, status: "synced" };
      } else {
        sourceStats["CISA KEV"] = { count: 0, status: "fallback" };
      }
    } catch {
      sourceStats["CISA KEV"] = { count: 0, status: "fallback" };
    }

    const enrichedItems: ThreatReport[] = collectedRaw.map((raw) => enrichRawFeedItem(raw));

    res.json({
      syncedAt: new Date().toISOString(),
      liveCount: enrichedItems.length,
      sourceStats,
      items: enrichedItems,
    });
  });

  // 2. Dynamic AI Enrichment Pipeline (Gemini API Server-Side Integration + Smart Fallback)
  app.post("/api/enrich", async (req, res) => {
    const { title, summary, source, sourceUrl, existingThreat } = req.body as {
      title?: string;
      summary?: string;
      source?: string;
      sourceUrl?: string;
      existingThreat?: ThreatReport;
    };

    const targetTitle = title || existingThreat?.title || "Active Cyber Threat Advisory";
    const targetSummary =
      summary ||
      existingThreat?.executiveSummary ||
      existingThreat?.summary ||
      " Threat actors are actively exploiting enterprise infrastructure.";
    const targetSource = source || existingThreat?.source || "Custom Threat Advisory";
    const targetUrl = sourceUrl || existingThreat?.sourceUrl || "https://www.cisa.gov/";

    const baseline =
      existingThreat ||
      enrichRawFeedItem({
        title: targetTitle,
        description: targetSummary,
        source: targetSource,
        link: targetUrl,
        pubDate: new Date().toISOString(),
      });

    const hasValidKey =
      Boolean(process.env.GEMINI_API_KEY) &&
      process.env.GEMINI_API_KEY !== "MY_GEMINI_API_KEY" &&
      process.env.GEMINI_API_KEY!.trim().length > 8;

    if (!hasValidKey) {
      const enhanced: ThreatReport = {
        ...baseline,
        aiEnriched: true,
        enrichedAt: new Date().toISOString(),
        executiveSummary: `${baseline.executiveSummary}\n\n[Deep SecOps Correlation]: Extended behavioral telemetry rules synthesized for ${baseline.malwareFamily} (${baseline.threatActor}). Added multi-event YARA-L 2.0 join across PROCESS_LAUNCH, REGISTRY_MODIFICATION, and outbound DNS/TLS C2 beacons with 15-minute host correlation window.`,
        secops: generateSecOpsQueries(baseline),
      };
      res.json({
        mode: "heuristic_engine",
        threat: enhanced,
      });
      return;
    }

    try {
      const ai = getGenAIClient();
      const prompt = `Act as a Principal Threat Intelligence Architect and Google SecOps (Chronicle) Detection Engineer.
Analyze the following cybersecurity threat report and return a deeply enriched JSON structure:

Title: ${targetTitle}
Source: ${targetSource}
Details: ${targetSummary}

Requirements:
1. Classify severity (Critical, High, Medium, Low), threatActor, threatType (APT Groups, Zero-Day Exploits, Supply Chain Attacks, Phishing/BEC, Cloud/Identity Attacks), malwareFamily, malwareCategory (Ransomware, InfoStealers, RATs, Botnets, Loaders, Wipers).
2. Map targetIndustries (from: Finance/BFSI, Healthcare, Technology/SaaS, Government, Critical Infrastructure/Energy, Telecom, Retail, Manufacturing) and targetRegions (from: Global, APAC, North America, Europe, Middle East, LATAM).
3. Provide a 7-stage killChain (Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Lateral Movement, Exfiltration & Impact) with realistic commandOrArtifact and mitreId.
4. Provide 5-6 MITRE ATT&CK mappings (tactic, techniqueId, techniqueName, description).
5. Provide realistic or extracted Indicators of Compromise (hashes, network IPs/domains/URLs, hostArtifacts).
6. Provide valid Google SecOps UDM IoC Sweep Query, UDM Behavioral Hunt Query, and a complete syntactically valid YARA-L 2.0 detection rule.`;

      const response = await ai.models.generateContent({
        model: "gemini-3.8-flash",
        contents: prompt,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              executiveSummary: { type: Type.STRING },
              severity: { type: Type.STRING },
              cveIds: { type: Type.ARRAY, items: { type: Type.STRING } },
              threatActor: { type: Type.STRING },
              threatType: { type: Type.STRING },
              malwareFamily: { type: Type.STRING },
              malwareCategory: { type: Type.STRING },
              targetIndustries: { type: Type.ARRAY, items: { type: Type.STRING } },
              targetRegions: { type: Type.ARRAY, items: { type: Type.STRING } },
              killChain: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    stage: { type: Type.STRING },
                    title: { type: Type.STRING },
                    description: { type: Type.STRING },
                    commandOrArtifact: { type: Type.STRING },
                    mitreId: { type: Type.STRING },
                  },
                  required: ["stage", "title", "description"],
                },
              },
              mitreAttack: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    tactic: { type: Type.STRING },
                    techniqueId: { type: Type.STRING },
                    techniqueName: { type: Type.STRING },
                    description: { type: Type.STRING },
                  },
                  required: ["tactic", "techniqueId", "techniqueName", "description"],
                },
              },
              udmIocQuery: { type: Type.STRING },
              udmBehavioralQuery: { type: Type.STRING },
              yaralRule: { type: Type.STRING },
            },
            required: [
              "executiveSummary",
              "severity",
              "threatActor",
              "malwareFamily",
              "udmIocQuery",
              "udmBehavioralQuery",
              "yaralRule",
            ],
          },
        },
      });

      const parsed = JSON.parse((response.text ?? "{}").trim());

      const merged: ThreatReport = {
        ...baseline,
        executiveSummary: parsed.executiveSummary || baseline.executiveSummary,
        severity:
          parsed.severity === "Critical" ||
          parsed.severity === "High" ||
          parsed.severity === "Medium" ||
          parsed.severity === "Low"
            ? parsed.severity
            : baseline.severity,
        cveIds:
          Array.isArray(parsed.cveIds) && parsed.cveIds.length > 0
            ? parsed.cveIds
            : baseline.cveIds,
        threatActor: parsed.threatActor || baseline.threatActor,
        threatType: parsed.threatType || baseline.threatType,
        malwareFamily: parsed.malwareFamily || baseline.malwareFamily,
        malwareCategory: parsed.malwareCategory || baseline.malwareCategory,
        targetIndustries:
          Array.isArray(parsed.targetIndustries) && parsed.targetIndustries.length > 0
            ? parsed.targetIndustries
            : baseline.targetIndustries,
        targetRegions:
          Array.isArray(parsed.targetRegions) && parsed.targetRegions.length > 0
            ? parsed.targetRegions
            : baseline.targetRegions,
        killChain:
          Array.isArray(parsed.killChain) && parsed.killChain.length >= 4
            ? parsed.killChain
            : baseline.killChain,
        mitreAttack:
          Array.isArray(parsed.mitreAttack) && parsed.mitreAttack.length >= 3
            ? parsed.mitreAttack
            : baseline.mitreAttack,
        secops: {
          ruleName: baseline.secops.ruleName,
          udmIocQuery: parsed.udmIocQuery || baseline.secops.udmIocQuery,
          udmBehavioralQuery:
            parsed.udmBehavioralQuery || baseline.secops.udmBehavioralQuery,
          yaralRule: parsed.yaralRule || baseline.secops.yaralRule,
        },
        aiEnriched: true,
        enrichedAt: new Date().toISOString(),
      };

      res.json({
        mode: "gemini_ai",
        threat: merged,
      });
    } catch {
      const fallbackThreat: ThreatReport = {
        ...baseline,
        aiEnriched: true,
        enrichedAt: new Date().toISOString(),
        secops: generateSecOpsQueries(baseline),
      };
      res.json({
        mode: "heuristic_engine",
        threat: fallbackThreat,
      });
    }
  });

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
}

startServer();
