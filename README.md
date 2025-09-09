# NPM Blast Radius

Executive summary

This CLI maps the blast radius of compromised npm packages. Given a CSV of known-bad packages and versions, it finds their direct dependents (the packages that use them), shows how each dependent references the package (dep/peer/dev and the exact semver range), and captures timing signals to understand impact:

- Who likely pulled the compromised version at their release time.
- Who would still pull the compromised version on a fresh install today.
- Which dependents pin exactly to the compromised version.

Why it’s useful

- Rapid triage: identify potentially impacted dependents to prioritize outreach, patches, and advisories.
- Evidence-driven: combines declared ranges with publish timestamps to approximate what versions were actually resolved, without lockfiles.
- Scalable output: streams CSV for large ecosystems; includes provenance of where each dependent was discovered.

What it does

- Discovers direct dependents per source package (one hop; no recursion).
- Attributes usage via npm registry metadata across dependencies, peerDependencies, and optional devDependencies.
- Computes blast-radius fields (at-release vs now) from publish timelines and semver ranges.
- Writes a detailed CSV you can filter/sort to drive incident response and follow-up.

## Input

CSV with header:

package,version

Example:

strip-ansi,6.0.1
react,18.2.0

## Usage

Install and run:

- Local run (repo checkout):
  - Install deps: `npm install`
  - Run: `node src/index.js -i sample.input.csv -o output.csv`
  - Visible demo: `npm run demo:one`

- Global bin (recommended):
  - Link locally for dev: `npm link`
  - Then run: `npm-blast-radius -i sample.input.csv -o output.csv`

Environment file:

- Copy `.env.example` to `.env` and fill in your keys.
- The CLI loads `.env` automatically.

Options:

- `--include-dev` include devDependencies (off by default)
- `--no-peer` exclude peerDependencies (included by default)
- `--max <n>` cap dependents per input package (useful to chunk very large results)
- `-c, --concurrency <n>` concurrent HTTP requests (default 8)
- `--append` append to existing output.csv (skips header)
- `--progress <n>` log every N dependents processed (default 25)
- `--quiet` minimal logging (suppresses progress messages)
- `--verbose` extra diagnostics about which source returned each dependent
- `--no-libraries` disable Libraries.io fallback
- `--no-scrape` disable npm website scraping fallback
- `--timeout <ms>` HTTP request timeout (default 15000)

Environment:

- `NPM_REGISTRY` override registry (default https://registry.npmjs.org)
- `NPM_SEARCH_URL` override dependents search API (default https://api.npms.io/v2/search)
- `LIBRARIES_IO_API_KEY` optional fallback to Libraries.io dependents API
- `NPM_TOKEN` optional npm auth token for private packages/rate limits
- `CONCURRENCY` default concurrency
- `HTTP_TIMEOUT_MS` default per-request timeout (ms) used when `--timeout` is not passed

Output columns

See the CSV Data Dictionary for complete column definitions and guidance:

- docs/data-dictionary.md

How to use:

- Provide compromised versions in your input CSV (package,version).
- Inspect likely_impacted_at_release and still_impacted_now to prioritize outreach and patch coordination.
- Filter uses_exact_pin to catch dependents that are most certain to be impacted.

Limitations

- If matched_version is not available, we fall back to latest to estimate dependent_version_published_at.
- Pre-releases are considered (includePrerelease=true) for range resolution.

Notes:

- One level only: direct dependents of each input package (no recursion).
- Discovery uses npms.io across dependencies/peer/dev with fallbacks:
  - Libraries.io dependents API (when `LIBRARIES_IO_API_KEY` is set). As of 2025-09-09, the endpoint often responds with `{ "message": "Disabled for performance reasons" }`, so it may yield no results.
  - npmjs.com depended pages (scraped) as a last resort
- Last update from npm registry `time.modified` (fallback `time.created`).
- `dependency_type` and `dependent_matched_version` show where/how the usage was declared. If blank, the dependent was found via a fallback source and couldn’t be attributed from registry metadata.
- Output is streamed to CSV as rows are processed; memory use stays low.
- Progress logs show discovery counts and per-package processed counters.

Tips

- For very large packages (10k+ dependents), run in chunks with `--max` and combine outputs.
- Prefer setting `NPM_TOKEN` and `LIBRARIES_IO_API_KEY` to improve coverage and rate limits.

Quick, visible tests

- One-row demo with logs and quick exit:

  ```sh
  printf 'package,version\nchalk,5.3.0\n' > tmp.visible.csv
  npm-blast-radius -i tmp.visible.csv -o out.visible.csv --max 2 --progress 1 --verbose --timeout 8000
  sed -n '1,10p' out.visible.csv
  ```

- Capped sample file (keeps run fast):

  ```sh
  npm-blast-radius -i sample.input.csv -o out.sample.csv --max 1 --progress 10 --verbose --timeout 8000
  sed -n '1,20p' out.sample.csv
  ```

License

MIT — see `LICENSE`.
