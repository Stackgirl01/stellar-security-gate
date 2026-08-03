#!/usr/bin/env node
'use strict';

/**
 * Reads whatever report files each prior step produced, normalizes them into
 * a single findings list, posts (or updates) one PR comment summarizing
 * everything, and exits non-zero if the highest severity found meets or
 * exceeds FAIL_ON_SEVERITY.
 *
 * All report files are optional — if a step was skipped or produced nothing,
 * its section is just omitted rather than treated as an error.
 */

const fs = require('fs');

const COMMENT_MARKER = '<!-- stellar-security-gate:report -->';
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function readJsonSafe(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    if (!raw.trim()) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function normalizeGitleaks(data) {
  if (!Array.isArray(data)) return [];
  return data.map((leak) => ({
    source: 'secrets',
    severity: 'critical',
    file: leak.File || leak.file || 'unknown',
    line: leak.StartLine ?? leak.line ?? null,
    message: `Potential secret detected (rule: ${leak.RuleID || leak.rule || 'unknown'}).`,
  }));
}

function normalizeCargoAudit(data) {
  const list = data?.vulnerabilities?.list;
  if (!Array.isArray(list)) return [];
  return list.map((v) => ({
    source: 'cargo-audit',
    severity: 'high',
    file: 'Cargo.lock',
    line: null,
    message: `${v.advisory?.id || 'Advisory'}: ${v.advisory?.title || 'Vulnerable dependency'} ` +
      `(package: ${v.package?.name || 'unknown'} ${v.package?.version || ''})`,
  }));
}

function mapNpmSeverity(sev) {
  if (sev === 'critical' || sev === 'high') return sev;
  if (sev === 'moderate') return 'medium';
  return 'low';
}

function normalizeNpmAudit(data) {
  const vulns = data?.vulnerabilities;
  if (!vulns || typeof vulns !== 'object') return [];
  return Object.entries(vulns).map(([pkg, info]) => ({
    source: 'npm-audit',
    severity: mapNpmSeverity(info.severity),
    file: 'package-lock.json',
    line: null,
    message: `${pkg}: ${info.severity} severity vulnerability` +
      (Array.isArray(info.via) && info.via.length && typeof info.via[0] === 'object'
        ? ` (${info.via[0].title || info.via[0].name || ''})`
        : ''),
  }));
}

function normalizeSoroban(data) {
  if (!Array.isArray(data)) return [];
  return data.map((f) => ({
    source: 'soroban-check',
    severity: f.severity || 'medium',
    file: f.file || 'unknown',
    line: f.line ?? null,
    message: `${f.message} [${f.rule}, fn ${f.function}]`,
  }));
}

function highestSeverity(findings) {
  let top = null;
  for (const f of findings) {
    const rank = SEVERITY_RANK[f.severity] ?? 0;
    if (top === null || rank > SEVERITY_RANK[top]) top = f.severity;
  }
  return top;
}

function severityMeetsThreshold(severity, threshold) {
  if (threshold === 'off') return false;
  if (!severity) return false;
  const thresholdRank = SEVERITY_RANK[threshold] ?? SEVERITY_RANK.high;
  return (SEVERITY_RANK[severity] ?? 0) >= thresholdRank;
}

function severityEmoji(severity) {
  return { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' }[severity] || '⚪';
}

function buildCommentBody(findings) {
  if (findings.length === 0) {
    return `${COMMENT_MARKER}\n### 🛡️ Stellar Security Gate\n\n✅ No findings. Nice work!`;
  }

  const bySource = findings.reduce((acc, f) => {
    (acc[f.source] ||= []).push(f);
    return acc;
  }, {});

  const sectionTitles = {
    secrets: 'Secret Scanning',
    'cargo-audit': 'Cargo Dependency Audit',
    'npm-audit': 'npm Dependency Audit',
    'soroban-check': 'Soroban Contract Checks',
  };

  let body = `${COMMENT_MARKER}\n### 🛡️ Stellar Security Gate\n\n`;
  body += `Found **${findings.length}** finding(s) across ${Object.keys(bySource).length} check(s).\n\n`;

  for (const [source, items] of Object.entries(bySource)) {
    body += `#### ${sectionTitles[source] || source}\n\n`;
    for (const f of items) {
      const loc = f.line ? `${f.file}:${f.line}` : f.file;
      body += `- ${severityEmoji(f.severity)} **${f.severity.toUpperCase()}** — ` + `\`${loc}\` — ${f.message}\n`;
    }
    body += '\n';
  }

  body += '_Heuristic checks — please review findings rather than treating them as ground truth._';
  return body;
}

async function postOrUpdateComment(body, token) {
  const repoFull = process.env.GITHUB_REPOSITORY;
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!token) {
    console.warn('GITHUB_TOKEN not provided — skipping PR comment');
    return;
  }
  if (!repoFull) {
    console.warn('GITHUB_REPOSITORY not set — skipping PR comment');
    return;
  }
  if (!eventPath) {
    console.warn('GITHUB_EVENT_PATH not set — skipping PR comment');
    return;
  }
  if (!fs.existsSync(eventPath)) {
    console.warn(`Event file ${eventPath} not found — skipping PR comment`);
    return;
  }

  // Prefer global fetch (Node 18+); fall back to node-fetch if available.
  let fetchFn = global.fetch;
  if (!fetchFn) {
    try {
      // node-fetch v2 is CJS; v3 is ESM-only so this may fail in some setups.
      fetchFn = require('node-fetch');
    } catch (err) {
      console.warn('fetch not available and node-fetch could not be required — skipping POST to GitHub API');
      return;
    }
  }

  const event = readJsonSafe(eventPath);
  const prNumber = event?.pull_request?.number;
  if (!prNumber) return; // not a PR event, nothing to comment on

  const [owner, repo] = repoFull.split('/');
  const apiBase = `https://api.github.com/repos/${owner}/${repo}`;
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };

  try {
    const listRes = await fetchFn(`${apiBase}/issues/${prNumber}/comments?per_page=100`, { headers });
    const comments = listRes.ok ? await listRes.json() : [];
    const existing = Array.isArray(comments)
      ? comments.find((c) => typeof c.body === 'string' && c.body.includes(COMMENT_MARKER))
      : null;

    if (existing) {
      await fetchFn(`${apiBase}/issues/comments/${existing.id}`, {
        method: 'PATCH',
        headers,
        body: JSON.stringify({ body }),
      });
    } else {
      await fetchFn(`${apiBase}/issues/${prNumber}/comments`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ body }),
      });
    }
  } catch (err) {
    console.error('Failed to post PR comment:', err.message);
  }
}

function writeOutput(name, value) {
  const outFile = process.env.GITHUB_OUTPUT;
  if (!outFile) return;
  fs.appendFileSync(outFile, `${name}=${value}\n`);
}

async function main() {
  try {
    const findings = [
      ...normalizeGitleaks(readJsonSafe('gitleaks-report.json')),
      ...normalizeCargoAudit(readJsonSafe('cargo-audit-report.json')),
      ...normalizeNpmAudit(readJsonSafe('npm-audit-report.json')),
      ...normalizeSoroban(readJsonSafe('soroban-report.json')),
    ];

    const top = highestSeverity(findings);
    const threshold = (process.env.FAIL_ON_SEVERITY || 'high').toLowerCase();
    const token = process.env.GITHUB_TOKEN;

    const body = buildCommentBody(findings);
    await postOrUpdateComment(body, token);

    writeOutput('findings-count', String(findings.length));
    writeOutput('highest-severity', top || 'none');

    console.log(`Stellar Security Gate: ${findings.length} finding(s), highest severity: ${top || 'none'}.`);

    if (severityMeetsThreshold(top, threshold)) {
      console.error(`Failing: highest severity "${top}" meets or exceeds threshold "${threshold}".`);
      process.exitCode = 1;
    }
  } catch (err) {
    // A bug in the aggregator itself shouldn't produce an opaque crash with no
    // explanation — surface it clearly, but don't fail the whole workflow for
    // an internal tooling error (that's a false signal to the developer about
    // their code, not a real security finding).
    console.error(`Stellar Security Gate: internal error while aggregating results: ${err.message}`);
    console.error(err.stack);
  }
}

main();
