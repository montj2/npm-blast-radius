# CSV Data Dictionary

This document defines each column emitted by the CLI. Use it as a reference when filtering or joining data.

## Core columns

- source_package
  - The input (target) package name.
- source_version
  - The compromised version from input CSV for blast-radius analysis; may be empty if unknown.
- dependent
  - The package that directly depends on `source_package` (one hop; no recursion).
- dependent_version_range
  - The semver spec declared by the dependent (dependencies/peer/dev) for `source_package`.
- dependent_latest_version
  - The dependent's current `dist-tags.latest` at time of analysis.
- last_update
  - The dependent's packument `time.modified` timestamp (fallback `time.created`).
- dependent_matched_version
  - The dependent version where a dependency match was found. We first try latest; if absent, we scan historical versions from newest to oldest.
- dependency_type
  - Where the dependency was declared: `dep` (dependencies), `peer` (peerDependencies), or `dev` (devDependencies).
- is_dev_dependency (boolean)
  - True if the match came from `devDependencies`.
- source_version_satisfies (boolean)
  - True if `source_version` statically satisfies `dependent_version_range`.
- dependent_source
  - Provenance for discovery: `npms`, `libraries`, or `scraped`.
- error
  - Error message if row-level processing failed (e.g., network/packument issues).

## Blast-radius columns

- compromised_published_at
  - Publish timestamp of `source_version` in the source package timeline.
- dependent_version_published_at
  - Publish timestamp of `dependent_matched_version` (or latest if historical match not found).
- resolved_at_dependent_release
  - The highest source package version that satisfied `dependent_version_range` at the time `dependent_matched_version` was published.
- resolved_now
  - The highest source package version that satisfies `dependent_version_range` today (using all known source versions).
- likely_impacted_at_release (boolean)
  - True if `resolved_at_dependent_release` equals `source_version`.
- still_impacted_now (boolean)
  - True if `resolved_now` equals `source_version`.
- uses_exact_pin (boolean)
  - True if `dependent_version_range` is an exact version and equals `source_version`.

## Notes

- Timestamps are ISO strings from the npm registry time map.
- Range checks include prereleases (includePrerelease=true).
- Actual installs depend on lockfiles; these fields are heuristics derived from publish times and semver.
