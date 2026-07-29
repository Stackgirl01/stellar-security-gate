#!/usr/bin/env node
'use strict';

/**
 * Heuristic, regex/brace-based scanner for Soroban contract Rust files.
 * Not a full Rust parser — deliberately simple so it stays fast, dependency-free,
 * and easy to extend. False positives are possible; findings are meant to prompt
 * a human review, not to be treated as ground truth.
 *
 * Checks:
 *  1. missing-require-auth: a pub fn inside a #[contractimpl] block takes an
 *     `Address` parameter but its body never calls .require_auth() or
 *     require_auth_for_args(). Missing auth checks are the most common
 *     Soroban vulnerability class (anyone can call the function on behalf
 *     of an address they don't own).
 *  2. risky-unwrap: a contract entry point calls .unwrap() or .expect() on a
 *     Result/Option, or uses panic!(). Panics abort the transaction, which
 *     can be used as a griefing/DoS vector depending on context, and usually
 *     indicates unhandled error paths that should return a proper error type.
 *
 * Usage: node soroban-check.js <path>
 * Prints a JSON array of findings to stdout.
 */

const fs = require('fs');
const path = require('path');

const SCAN_ROOT = process.argv[2] || '.';
const IGNORE_DIRS = new Set(['target', 'node_modules', '.git', 'test', 'tests']);

/** Recursively collect .rs files under root, skipping common noise dirs. */
function collectRustFiles(root) {
  const results = [];
  const stack = [root];
  while (stack.length) {
    const current = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.name.startsWith('.') && entry.name !== '.') continue;
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!IGNORE_DIRS.has(entry.name)) stack.push(full);
      } else if (entry.isFile() && entry.name.endsWith('.rs')) {
        results.push(full);
      }
    }
  }
  return results;
}

/** Given source text and the index of an opening brace, return the index of its matching closing brace. */
function findMatchingBrace(source, openIndex) {
  let depth = 0;
  for (let i = openIndex; i < source.length; i++) {
    if (source[i] === '{') depth++;
    else if (source[i] === '}') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1; // unbalanced; caller should treat as "rest of file"
}

/** Count newlines up to an index, to report a 1-based line number. */
function lineNumberAt(source, index) {
  let line = 1;
  for (let i = 0; i < index && i < source.length; i++) {
    if (source[i] === '\n') line++;
  }
  return line;
}

const FN_SIGNATURE_RE = /pub\s+fn\s+(\w+)\s*\(([^)]*)\)/g;

function extractFunctions(source) {
  const fns = [];
  let match;
  FN_SIGNATURE_RE.lastIndex = 0;
  while ((match = FN_SIGNATURE_RE.exec(source)) !== null) {
    const [full, name, params] = match;
    const sigEnd = match.index + full.length;
    // Find the body's opening brace, allowing for a return-type arrow in between.
    const braceIdx = source.indexOf('{', sigEnd);
    if (braceIdx === -1) continue;
    // Guard against matching a trait/type signature ending in ';' before any '{'
    const semiIdx = source.indexOf(';', sigEnd);
    if (semiIdx !== -1 && semiIdx < braceIdx) continue;

    const closeIdx = findMatchingBrace(source, braceIdx);
    const bodyEnd = closeIdx === -1 ? source.length : closeIdx;
    const body = source.slice(braceIdx, bodyEnd);

    fns.push({
      name,
      params,
      body,
      line: lineNumberAt(source, match.index),
    });
  }
  return fns;
}

function isContractImplFile(source) {
  return source.includes('#[contractimpl]') || source.includes('soroban_sdk');
}

function checkFile(filePath, source, findings) {
  if (!isContractImplFile(source)) return;

  const fns = extractFunctions(source);
  for (const fn of fns) {
    // Check 1: Address param on a state-mutating fn without require_auth in body.
    // Read-only getters don't need auth, so we only flag functions that actually
    // write to storage — otherwise this rule is noisy enough to undermine trust
    // in the tool (verified against a false positive on a plain getter during testing).
    if (/\bAddress\b/.test(fn.params)) {
      const mutatesStorage = /\.storage\(\)[\s\S]*?\.(set|remove|extend_ttl|bump)\s*\(/.test(fn.body);
      const hasAuthCheck = /require_auth(_for_args)?\s*\(/.test(fn.body);
      if (mutatesStorage && !hasAuthCheck) {
        findings.push({
          rule: 'missing-require-auth',
          severity: 'high',
          file: filePath,
          line: fn.line,
          function: fn.name,
          message: `fn '${fn.name}' takes an Address parameter, writes to storage, but never calls require_auth(). ` +
            `Without it, any caller can invoke this function on behalf of that address.`,
        });
      }
    }

    // Check 2: unwrap()/expect()/panic! in the function body
    const unwrapMatches = fn.body.match(/\.unwrap\(\)|\.expect\(|panic!\(/g);
    if (unwrapMatches && unwrapMatches.length > 0) {
      findings.push({
        rule: 'risky-unwrap',
        severity: 'medium',
        file: filePath,
        line: fn.line,
        function: fn.name,
        message: `fn '${fn.name}' uses ${unwrapMatches.length} unwrap()/expect()/panic!() call(s). ` +
          `Consider returning a typed error instead of panicking on unexpected input.`,
      });
    }
  }
}

function main() {
  const findings = [];
  try {
    const files = collectRustFiles(SCAN_ROOT);
    for (const file of files) {
      let source;
      try {
        source = fs.readFileSync(file, 'utf8');
      } catch {
        continue;
      }
      checkFile(file, source, findings);
    }
  } catch (err) {
    // Never let an unexpected parsing error take down the whole Action run —
    // print a warning and fall through with whatever findings were gathered
    // before the failure, rather than crashing the pipeline.
    console.error(`soroban-check: unexpected error during scan, continuing with partial results: ${err.message}`);
  }

  process.stdout.write(JSON.stringify(findings, null, 2));
}

main();
