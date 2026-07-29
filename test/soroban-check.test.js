'use strict';

/**
 * Minimal, dependency-free test runner for soroban-check.js.
 * Run with: node test/soroban-check.test.js
 */

const { execFileSync } = require('child_process');
const path = require('path');
const assert = require('assert');

const SCRIPT = path.join(__dirname, '..', 'scripts', 'soroban-check.js');
const FIXTURES = path.join(__dirname, 'fixtures');

function run() {
  const output = execFileSync('node', [SCRIPT, FIXTURES], { encoding: 'utf8' });
  return JSON.parse(output);
}

function testFlagsRealVulnerability(findings) {
  const hit = findings.find(
    (f) => f.rule === 'missing-require-auth' && f.function === 'withdraw' && f.file.includes('vulnerable.rs')
  );
  assert.ok(hit, 'expected withdraw() in vulnerable.rs to be flagged for missing require_auth');
  console.log('✅ flags real missing-require-auth vulnerability');
}

function testNoFalsePositiveOnGetter(findings) {
  const hit = findings.find(
    (f) => f.rule === 'missing-require-auth' && f.function === 'get_balance'
  );
  assert.strictEqual(hit, undefined, 'expected read-only get_balance() to NOT be flagged');
  console.log('✅ no false positive on read-only getter');
}

function testDoesNotFlagCorrectlyAuthedFn(findings) {
  const hit = findings.find(
    (f) => f.rule === 'missing-require-auth' && f.function === 'deposit'
  );
  assert.strictEqual(hit, undefined, 'expected deposit() (which calls require_auth) to NOT be flagged');
  console.log('✅ does not flag a correctly-authed function');
}

function testFlagsRiskyUnwrap(findings) {
  const hit = findings.find(
    (f) => f.rule === 'risky-unwrap' && f.function === 'withdraw' && f.file.includes('vulnerable.rs')
  );
  assert.ok(hit, 'expected withdraw() in vulnerable.rs to be flagged for unwrap() usage');
  console.log('✅ flags risky unwrap() usage');
}

function testSafeFileHasNoAuthFindings(findings) {
  const hits = findings.filter((f) => f.file.includes('safe.rs') && f.rule === 'missing-require-auth');
  assert.strictEqual(hits.length, 0, 'expected safe.rs to have zero missing-require-auth findings');
  console.log('✅ safe.rs produces zero missing-require-auth findings');
}

function main() {
  const findings = run();
  testFlagsRealVulnerability(findings);
  testNoFalsePositiveOnGetter(findings);
  testDoesNotFlagCorrectlyAuthedFn(findings);
  testFlagsRiskyUnwrap(findings);
  testSafeFileHasNoAuthFindings(findings);
  console.log(`\nAll tests passed. (${findings.length} total findings across fixtures)`);
}

main();
