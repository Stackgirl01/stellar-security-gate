# Seed issues to post

Copy each of these into a new GitHub issue. They're pulled directly from your
own README's "Known limitations" and "Roadmap" sections, so they're
guaranteed relevant — no invented scope. Complexity tags follow Drips Wave's
100/150/200 convention in case you apply this repo to a Wave later.

---

## 1. Fix mismatched action reference in README usage example

**Complexity: 100 (low)**

The README's usage example currently references
`Sycosmile/stellar-security-gate@v1`, but the repo lives at
`Stackgirl01/stellar-security-gate`. This is confusing for anyone copying the
snippet directly.

**Acceptance criteria:**
- [ ] Usage example in README.md references the correct action path
- [ ] Confirm the tag/version referenced (`@v1`) actually exists as a release;
      if not, either cut a `v1` tag or update the example to `@main`

**Good first issue** — no code changes, just docs accuracy.

---

## 2. Handle nested parentheses in function signature parsing

**Complexity: 150 (medium)**

From the README: "The function-signature regex breaks on nested parentheses
in parameter types (e.g. `Vec<(u32, u32)>`) — the parameter list will be
truncated at the first `)`."

**Acceptance criteria:**
- [ ] Add a fixture under `test/fixtures/` with a Soroban function taking a
      parameter like `Vec<(u32, u32)>` or similar nested-paren type
- [ ] Update the signature-parsing logic to correctly find the matching
      closing paren (balanced-paren counting rather than first-match)
- [ ] `npm test` passes, including the new fixture
- [ ] No change in behavior for existing fixtures

**Note:** this can stay regex/brace-based per the project's existing
tradeoffs — doesn't need a full parser, just balanced-paren counting instead
of first-match.

---

## 3. Cross-function auth-check tracing (single-hop)

**Complexity: 200 (high)**

From the README: "Doesn't currently follow cross-function calls — if
`withdraw()` calls a private helper that itself calls `require_auth()`, the
check won't see it and may false-positive."

**Scope for v1 of this fix (deliberately limited):**
- [ ] Detect the single-hop case: a `pub fn` in a `#[contractimpl]` block
      calls a private helper function defined in the *same file*, and that
      helper calls `.require_auth()`
- [ ] Add fixtures for: (a) the false-positive case this fixes, (b) a case
      that should still correctly flag (e.g., helper doesn't call
      require_auth at all)
- [ ] Document in README that cross-file/multi-hop tracing is still out of
      scope (avoid over-promising)

**Explicitly out of scope for this issue** (call these out as follow-ups,
don't try to solve them here): multi-hop chains, calls across files/modules,
trait method resolution.

---

## 4. Configurable rule severities and per-rule ignore lists

**Complexity: 150 (medium)**

From the Roadmap: "Configurable rule severities and per-rule ignore lists."

**Acceptance criteria:**
- [ ] Support a config file (e.g. `.security-gate.yml`) or new `action.yml`
      inputs to override default severity per rule
      (`missing-require-auth`, `risky-unwrap`, secrets, dependency-audit)
- [ ] Support an ignore list (e.g. specific file paths or line-level
      `// security-gate-ignore` comments)
- [ ] Update README with the new config format and at least one example
- [ ] Add a fixture/test proving an ignored finding doesn't appear in output
      and a per-rule severity override changes `fail-on-severity` behavior

---

## 5. SARIF output for GitHub code scanning integration

**Complexity: 150 (medium)**

From the Roadmap: "SARIF output for GitHub code scanning integration."

**Acceptance criteria:**
- [ ] Add a new action output/input to emit findings in SARIF 2.1.0 format
- [ ] Map severity levels (`critical`/`high`/`medium`/`low`) to SARIF's
      `level` field sensibly
- [ ] Include a sample workflow snippet in README showing upload via
      `github/codeql-action/upload-sarif`
- [ ] Existing PR-comment output format is unaffected (this is additive)
