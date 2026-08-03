# Contributing to Stellar Security Gate

Thanks for taking a look — this project exists to catch Soroban-specific footguns
(missing `require_auth()`, risky `unwrap()`) and basic secret/dependency issues
before they land on `main`. Contributions that improve accuracy or reduce false
positives/negatives are especially welcome.

## Before you start

1. Read the **Known limitations** section in the [README](./README.md) first —
   most "obvious" improvements (AST parsing, cross-function tracing, generic
   parameter handling) are already tracked there or in the Roadmap. If what
   you want to fix isn't listed, open an issue describing it before sending a
   PR, so we can agree on the approach.
2. Check open issues and PRs for overlap before starting work.
3. Small, focused PRs are much easier to review than large ones. If you're
   tackling something roadmap-sized (e.g. AST parsing via `syn`), open a
   draft PR early so we can align on direction before you invest a lot of time.

## Local setup

```bash
git clone https://github.com/Stackgirl01/stellar-security-gate.git
cd stellar-security-gate
npm install
npm test
```

Tests run against fixtures in `test/fixtures/` — a contract with a real
missing-auth bug and a clean one. Any change to the Soroban heuristics should
come with a fixture (or an addition to an existing one) that would have
caught the bug, plus a regression test in `test/soroban-check.test.js`.

## Testing your change against a real contract

You can run the action locally against any Soroban repo by pointing
`soroban-path` at it:

```bash
node scripts/<entry-point>.js --path /path/to/some/soroban/repo/contracts
```

(See `scripts/` for the actual entry point name — if it's unclear from the
code, that's itself a good first "docs" issue to fix.)

## What makes a good PR here

- **A fixture, not just a claim.** Since the checks are heuristic
  (regex/brace-based, not a real parser), "I tested it manually" isn't
  verifiable by a reviewer — a fixture is. Add a minimal Rust snippet under
  `test/fixtures/` that demonstrates the case you're fixing.
- **Understand what you're submitting.** Contributions that are clearly
  copy-pasted without understanding the heuristic being changed take longer
  to review than they save — please make sure you can explain *why* your
  regex/logic change is correct, not just that it passes locally.
- **Call out tradeoffs.** This project deliberately favors "fast,
  dependency-free, less precise" over a full parser (see README). If your
  fix reintroduces a dependency or meaningfully slows down the scan, say so
  in the PR description so we can weigh it.
- **Update the README's Known limitations list** if your change removes a
  limitation, or add to it if it introduces a new edge case.

## Reporting false positives / false negatives

These are the most valuable reports for this project. Please include:
- The Soroban/Rust snippet that triggered (or should have triggered) a finding
- What you expected vs. what happened
- Whether it's `missing-require-auth` or `risky-unwrap`

## Code of conduct

Be respectful, assume good faith, and keep discussion focused on the code.
