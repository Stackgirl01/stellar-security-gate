# Stellar Security Gate

A GitHub Action that runs on every pull request to a Stellar/Soroban repo and checks for:

1. **Leaked secrets** — private keys, API keys, `.env` files accidentally committed (via the [gitleaks](https://github.com/gitleaks/gitleaks) CLI, run directly rather than through a marketplace action so its JSON output can feed into the aggregated PR comment).
2. **Vulnerable dependencies** — `cargo audit` for Rust/Soroban crates, `npm audit` for JS/TS packages.
3. **Soroban-specific issues**:
   - `missing-require-auth` — a function takes an `Address` and writes to storage but never calls `.require_auth()`, meaning anyone could call it on behalf of that address.
   - `risky-unwrap` — `.unwrap()` / `.expect()` / `panic!()` in a contract entry point, which aborts the transaction on unexpected input instead of returning a typed error.

Findings are posted as a single, auto-updating comment on the PR, and the check can optionally fail the workflow based on severity.

## Usage

```yaml
name: Stellar Security Gate

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: Sycosmile/stellar-security-gate@v1
        with:
          fail-on-severity: high   # "critical" | "high" | "medium" | "low" | "off"
          soroban-path: contracts  # where to look for .rs contract files
```

## Inputs

| Input                    | Default        | Description                                              |
|---------------------------|----------------|------------------------------------------------------------|
| `github-token`             | `${{ github.token }}` | Token used to post/update the PR comment.           |
| `fail-on-severity`         | `high`         | Minimum severity that fails the workflow. `off` never fails. |
| `soroban-path`             | `.`            | Path to scan for Soroban contract source files.          |
| `skip-secrets`              | `false`        | Skip gitleaks secret scanning.                            |
| `skip-dependency-audit`     | `false`        | Skip `cargo audit` / `npm audit`.                          |

## Outputs

| Output              | Description                                  |
|----------------------|-----------------------------------------------|
| `findings-count`      | Total findings across all checks.            |
| `highest-severity`    | The highest severity found (`critical`/`high`/`medium`/`low`/`none`). |

## How the Soroban checks work

These are **heuristic, regex/brace-based checks** on Rust source — not a full AST parser. That's a deliberate v1 tradeoff: fast, dependency-free, and easy to extend, at the cost of being less precise than a proper static analyzer. Findings are meant to prompt a human review, not to be treated as ground truth.

Known limitations:
- Only scans `pub fn` inside files containing `#[contractimpl]` or importing `soroban_sdk`.
- The `missing-require-auth` check only fires when the function also writes to storage (`.set(`/`.remove(`/etc.) — pure read-only getters that take an `Address` are intentionally not flagged, since they don't need auth. This was tuned after an early version produced a false positive on a plain getter during testing (see `test/soroban-check.test.js`).
- Directories named `test`, `tests`, `target`, and `node_modules` are skipped when scanning, so contracts placed inside a `tests/` integration folder won't be picked up. Point `soroban-path` at your actual contract source directory to avoid this.
- Doesn't currently follow cross-function calls — if `withdraw()` calls a private helper that itself calls `require_auth()`, the check won't see it and may false-positive. Contributions to handle this are welcome.
- The gitleaks install step currently pulls the Linux x64 binary and assumes an `ubuntu-latest` runner (the GitHub-hosted default). It'll fail on macOS/Windows runners — swap the download URL if you're running elsewhere. The gitleaks version is pinned in `action.yml`; bump it periodically.
- Brace-matching to find function bodies doesn't understand string or char literals, so a `{` or `}` inside a string (e.g. `"curly { brace"`) will throw off body boundaries for that function. Uncommon in Soroban contracts, but possible.
- The function-signature regex breaks on nested parentheses in parameter types (e.g. `Vec<(u32, u32)>`) — the parameter list will be truncated at the first `)`. A real Rust parser doesn't have this problem; this scanner deliberately trades that precision for speed and zero dependencies.

## Testing

```bash
npm test
```

Runs `test/soroban-check.test.js` against the fixtures in `test/fixtures/` (a contract with a real missing-auth bug, and a clean one) to guard against regressions in the heuristics.

## Roadmap

- [ ] Proper Rust AST parsing (e.g. via `syn`-based helper binary) instead of regex/brace matching, to reduce false negatives on unusual formatting.
- [ ] Cross-function auth-check tracing.
- [ ] Configurable rule severities and per-rule ignore lists.
- [ ] SARIF output for GitHub code scanning integration.

## License

MIT
