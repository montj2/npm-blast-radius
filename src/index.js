#!/usr/bin/env node
import 'dotenv/config';
import { stat } from 'node:fs/promises';
import { createReadStream, createWriteStream } from 'node:fs';
import { resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { setTimeout as setNodeTimeout, clearTimeout as clearNodeTimeout } from 'node:timers';
import Papa from 'papaparse';
import pLimit from 'p-limit';
import semver from 'semver';
import { fetch } from 'undici';
import { Command } from 'commander';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const pkg = require('../package.json');

const DEFAULT_CONCURRENCY = Number(process.env.CONCURRENCY || 8);
const NPM_REGISTRY = process.env.NPM_REGISTRY || 'https://registry.npmjs.org';
const NPM_SEARCH_URL = process.env.NPM_SEARCH_URL || 'https://api.npms.io/v2/search';
const DEFAULT_TIMEOUT_MS = Number(process.env.HTTP_TIMEOUT_MS || 15000);

function parseArgs(argv) {
  const program = new Command();
  program
    .name('npm-blast-radius')
    .description(
      'Map the blast radius of compromised npm packages (direct dependents, attribution, and timing signals).',
    )
    .version(pkg.version || '0.0.0');

  program.requiredOption('-i, --input <file>', 'input CSV (columns: package,version)');
  program.option('-o, --output <file>', 'output CSV path', 'dependents.csv');
  program.option('--max <n>', 'cap dependents per source package', (v) => Number(v), 0);
  program.option(
    '-c, --concurrency <n>',
    'concurrent HTTP requests',
    (v) => Number(v),
    DEFAULT_CONCURRENCY,
  );
  program.option('--include-dev', 'include devDependencies when attributing usage', false);
  program.option('--no-peer', 'exclude peerDependencies (included by default)');
  program.option('--append', 'append to output (skip header if file exists)', false);
  program.option('--progress <n>', 'log every N dependents processed', (v) => Number(v), 25);
  program.option('--quiet', 'minimal logging', false);
  program.option('--verbose', 'extra diagnostics about discovery sources', false);
  program.option('--no-libraries', 'disable Libraries.io fallback', false);
  program.option('--no-scrape', 'disable npm website scraping fallback', false);
  program.option(
    '--timeout <ms>',
    'HTTP request timeout in milliseconds',
    (v) => Number(v),
    DEFAULT_TIMEOUT_MS,
  );

  program.addHelpText(
    'after',
    `\nOutput CSV columns:\n  See docs/data-dictionary.md for the complete list and definitions.\n`,
  );

  program.parse(argv);
  const opts = program.opts();
  // Normalize option names to existing code expectations
  return {
    input: opts.input,
    output: opts.output,
    maxDependents: opts.max,
    concurrency: opts.concurrency,
    includeDev: !!opts.includeDev,
    includePeer: opts.peer !== false, // commander sets opts.peer when using --no-peer
    append: !!opts.append,
    progress: opts.progress,
    quiet: !!opts.quiet,
    verbose: !!opts.verbose,
    noLibraries: !!opts.noLibraries,
    noScrape: !!opts.noScrape,
  };
}

async function readInput(file) {
  const abs = resolve(process.cwd(), file);
  return new Promise((resolveP, rejectP) => {
    const rows = [];
    Papa.parse(createReadStream(abs), {
      header: true,
      skipEmptyLines: true,
      transformHeader: (h) => h.trim().toLowerCase(),
      step: (res) => {
        const r = res.data;
        if (!r.package) return;
        rows.push({ package: r.package.trim(), version: (r.version || '').trim() });
      },
      complete: () => resolveP(rows),
      error: (err) => rejectP(err),
    });
  });
}

async function fetchJSON(url, options = {}, retries = 3, timeoutMs = DEFAULT_TIMEOUT_MS) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const ac = new globalThis.AbortController();
    const to = setNodeTimeout(() => ac.abort(), Math.max(1000, timeoutMs));
    const isRegistry = url.startsWith(NPM_REGISTRY);
    const authHeaders = {};
    if (isRegistry && process.env.NPM_TOKEN) {
      authHeaders['authorization'] = `Bearer ${process.env.NPM_TOKEN}`;
    }
    let res;
    try {
      res = await fetch(url, {
        ...options,
        signal: ac.signal,
        headers: {
          'user-agent': `npm-blast-radius/${pkg.version || '0.0.0'} (+https://www.npmjs.com)`,
          accept: 'application/json',
          ...authHeaders,
          ...(options.headers || {}),
        },
      });
    } catch (e) {
      clearNodeTimeout(to);
      if (attempt === retries) throw new Error(`Fetch error for ${url}: ${e?.message || e}`);
      await delay((attempt + 1) * 500);
      continue;
    } finally {
      clearNodeTimeout(to);
    }

    if (res.status === 429) {
      const wait = Number(res.headers.get('retry-after')) || Math.min(60, 2 ** attempt * 2);
      await delay(wait * 1000);
      continue;
    }

    if (res.ok) {
      return res.json();
    }

    if (attempt === retries) {
      throw new Error(`Fetch failed ${res.status} ${res.statusText} for ${url}`);
    }

    await delay((attempt + 1) * 500);
  }
}

function encodePkg(name) {
  return name.startsWith('@') ? name.replace('/', '%2F') : name;
}

async function getPackageMetadata(name, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const url = `${NPM_REGISTRY}/${encodePkg(name)}`;
  return fetchJSON(url, {}, 3, timeoutMs);
}

function extractLastUpdate(pkgMeta) {
  // npm registry returns time.modified or time[version]
  const t = pkgMeta?.time;
  return t?.modified || t?.created || null;
}

function toDateSafe(s) {
  if (!s) return null;
  try {
    const d = new Date(s);
    return isNaN(d.getTime()) ? null : d;
  } catch {
    return null;
  }
}

function listVersionDatesFromTimeMap(timeMap) {
  // Return [{version, date}] excluding created/modified and non-semver versions
  if (!timeMap) return [];
  const out = [];
  for (const [k, v] of Object.entries(timeMap)) {
    if (k === 'created' || k === 'modified') continue;
    if (!semver.valid(semver.coerce(k))) continue;
    const dt = toDateSafe(v);
    if (dt) out.push({ version: semver.coerce(k).version, date: dt });
  }
  // De-dupe by normalized version
  const seen = new Set();
  const dedup = [];
  for (const it of out) {
    if (!seen.has(it.version)) {
      seen.add(it.version);
      dedup.push(it);
    }
  }
  // Sort ascending by date
  dedup.sort((a, b) => a.date - b.date);
  return dedup;
}

function maxSatisfyingAtOrBefore(versionDates, range, atDate) {
  if (!range || !atDate) return null;
  const candidates = versionDates.filter((vd) => vd.date <= atDate).map((vd) => vd.version);
  if (candidates.length === 0) return null;
  try {
    return semver.maxSatisfying(candidates, range, { includePrerelease: true }) || null;
  } catch {
    return null;
  }
}

function maxSatisfyingNow(versions, range) {
  if (!range || !versions || versions.length === 0) return null;
  try {
    return semver.maxSatisfying(versions, range, { includePrerelease: true }) || null;
  } catch {
    return null;
  }
}

function isExactPin(range, compromisedVersion) {
  // Exact pin if the spec resolves to a single exact version (e.g., "1.2.3").
  // Also treat equality or v-prefixed exacts as exact.
  if (!range) return false;
  const v = semver.valid(semver.coerce(range));
  if (!v) return false;
  // If a compromised version is provided, also ensure it's the same exact pin for stronger signal.
  if (compromisedVersion && semver.valid(semver.coerce(compromisedVersion))) {
    return semver.eq(v, semver.coerce(compromisedVersion));
  }
  return true;
}

function listDependentsQuery(name, from, qualifier = 'dependencies') {
  // npms.io search for packages that depend on name
  const q = encodeURIComponent(`${qualifier}:${name}`);
  const size = 250; // max per npms API
  const url = `${NPM_SEARCH_URL}?q=${q}&from=${from}&size=${size}`;
  return url;
}

async function fetchAllDependents(
  name,
  includeDev = false,
  includePeer = true,
  max = 0,
  verbose = false,
  options = {},
) {
  const { noLibraries = false, noScrape = false, timeoutMs = DEFAULT_TIMEOUT_MS } = options || {};
  // Query npms.io for dependencies, and optionally devDependencies and peerDependencies
  const qualifiers = ['dependencies'];
  if (includeDev) qualifiers.push('devDependencies');
  if (includePeer) qualifiers.push('peerDependencies');
  const seen = new Set();
  const sourceByPkg = new Map();
  const stats = { npms: 0, libraries: 0, scraped: 0 };
  for (const qualifier of qualifiers) {
    let from = 0;
    while (true) {
      const url = listDependentsQuery(name, from, qualifier);
      let data;
      try {
        data = await fetchJSON(url, {}, 3, timeoutMs);
      } catch (e) {
        if (verbose) console.warn(`[${name}] npms.io ${qualifier} fetch error: ${e?.message || e}`);
        break;
      }
      const results = data?.results || [];
      if (verbose)
        console.log(
          `[${name}] npms.io ${qualifier} total=${data?.total ?? 'unknown'} from=${from} got=${results.length}`,
        );
      if (results.length === 0) break;
      let addedThisPage = 0;
      for (const r of results) {
        const pkg = r.package?.name;
        if (!pkg || pkg === name) continue;
        if (!seen.has(pkg)) {
          seen.add(pkg);
          if (!sourceByPkg.has(pkg)) sourceByPkg.set(pkg, 'npms');
          addedThisPage++;
        }
        if (max && seen.size >= max) break;
      }
      stats.npms += addedThisPage;
      from += results.length;
      if (from >= Math.min(data.total || Infinity, max || Infinity) || (max && seen.size >= max))
        break;
      await delay(150);
    }
  }
  // Fallback: Libraries.io if npms returns few/none and API key available
  if (!noLibraries && (seen.size === 0 || (max && seen.size < max))) {
    const remaining = max ? Math.max(0, max - seen.size) : 0;
    try {
      const more = await fetchDependentsFromLibrariesIO(name, remaining, timeoutMs);
      let added = 0;
      for (const pkg of more) {
        if (!seen.has(pkg)) {
          seen.add(pkg);
          if (!sourceByPkg.has(pkg)) sourceByPkg.set(pkg, 'libraries');
          added++;
        }
        if (max && seen.size >= max) break;
      }
      stats.libraries += added;
      if (verbose)
        console.log(
          `[${name}] libraries.io added ${added} (requested up to ${remaining || 'all'})`,
        );
    } catch (e) {
      if (verbose) console.warn(`[${name}] libraries.io fetch error: ${e?.message || e}`);
    }
  }
  // Fallback: scrape npm website dependents page if still empty/insufficient
  if (!noScrape && (seen.size === 0 || (max && seen.size < max))) {
    const remaining = max ? Math.max(0, max - seen.size) : 0;
    const more = await fetchDependentsFromNpmWebsite(name, remaining || 500, timeoutMs);
    let added = 0;
    for (const pkg of more) {
      if (!seen.has(pkg)) {
        seen.add(pkg);
        if (!sourceByPkg.has(pkg)) sourceByPkg.set(pkg, 'scraped');
        added++;
      }
      if (max && seen.size >= max) break;
    }
    stats.scraped += added;
    if (verbose)
      console.log(`[${name}] scraped added ${added} (requested up to ${remaining || 'all'})`);
  }
  return { names: Array.from(seen.keys()), stats, sources: sourceByPkg };
}

async function fetchDependentsFromLibrariesIO(name, max = 0, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const apiKey = process.env.LIBRARIES_IO_API_KEY;
  if (!apiKey) return [];
  const perPage = 100;
  const out = [];
  for (let page = 1; page < 1000; page++) {
    if (max && out.length >= max) break;
    const base = `https://libraries.io/api/npm/${encodeURIComponent(name)}/dependents?api_key=${encodeURIComponent(apiKey)}&per_page=${perPage}&page=${page}`;
    const data = await fetchJSON(base, {}, 3, timeoutMs);
    if (!Array.isArray(data)) {
      // Likely disabled: { message: "Disabled for performance reasons" }
      if (data && typeof data === 'object' && data.message) {
        throw new Error(`libraries.io response: ${data.message}`);
      }
      break;
    }
    if (data.length === 0) break;
    for (const item of data) {
      const pkg = item?.name;
      if (pkg) out.push(pkg);
      if (max && out.length >= max) break;
    }
    await delay(150);
  }
  return out;
}

async function fetchDependentsFromNpmWebsite(name, max = 0, timeoutMs = DEFAULT_TIMEOUT_MS) {
  // Scrape https://www.npmjs.com/browse/depended/<name>?offset=<n>
  // We'll extract hrefs matching /package/<pkg>
  const results = new Set();
  const pageSize = 36; // observed
  for (let offset = 0; offset < 50000; offset += pageSize) {
    if (max && results.size >= max) break;
    const url = `https://www.npmjs.com/browse/depended/${encodeURIComponent(name)}?offset=${offset}`;
    const html = await fetchText(url, 3, timeoutMs);
    if (!html) break;
    const beforeCount = results.size;
    const re = /href="\/package\/([^"?#]+)"/g;
    let m;
    while ((m = re.exec(html)) !== null) {
      const pkg = decodeURIComponent(m[1]);
      // skip the package itself and non-npm links
      if (!pkg || pkg === name) continue;
      // Exclude anchors like /package/ in header navigation if any present by filtering obvious names
      if (pkg.includes('policies') || pkg.includes('signup') || pkg.includes('login')) continue;
      results.add(pkg);
      if (max && results.size >= max) break;
    }
    if (results.size === beforeCount) break; // no progress -> stop
    await delay(400);
  }
  return Array.from(results);
}

async function fetchText(url, retries = 3, timeoutMs = DEFAULT_TIMEOUT_MS) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    const ac = new globalThis.AbortController();
    const to = setNodeTimeout(() => ac.abort(), Math.max(1000, timeoutMs));
    let res;
    try {
      res = await fetch(url, {
        signal: ac.signal,
        headers: {
          'user-agent': `npm-blast-radius/${pkg.version || '0.0.0'} (+https://www.npmjs.com)`,
          accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        },
      });
    } catch (e) {
      clearNodeTimeout(to);
      if (attempt === retries) {
        return '';
      }
      await delay((attempt + 1) * 500);
      continue;
    } finally {
      clearNodeTimeout(to);
    }
    if (res.status === 429) {
      const wait = Number(res.headers.get('retry-after')) || Math.min(60, 2 ** attempt * 2);
      await delay(wait * 1000);
      continue;
    }
    if (res.ok) return res.text();
    if (attempt === retries) return '';
    await delay((attempt + 1) * 500);
  }
}

function findDependencyRange(pkgMeta, targetName, includeDev = false, includePeer = true) {
  const latestTag = pkgMeta['dist-tags']?.latest;
  const versions = pkgMeta.versions || {};
  const latest = latestTag && versions[latestTag];

  // First try the latest version
  if (latest) {
    if (latest.dependencies?.[targetName])
      return {
        range: latest.dependencies[targetName],
        latestVersion: latestTag || null,
        isDev: false,
        dependencyType: 'dep',
        matchedVersion: latestTag || '',
      };
    if (includePeer && latest.peerDependencies?.[targetName])
      return {
        range: latest.peerDependencies[targetName],
        latestVersion: latestTag || null,
        isDev: false,
        dependencyType: 'peer',
        matchedVersion: latestTag || '',
      };
    if (includeDev && latest.devDependencies?.[targetName])
      return {
        range: latest.devDependencies[targetName],
        latestVersion: latestTag || null,
        isDev: true,
        dependencyType: 'dev',
        matchedVersion: latestTag || '',
      };
  }

  // Fallback: scan historical versions from newest to oldest
  const allVersionKeys = Object.keys(versions).sort((a, b) => {
    try {
      return semver.rcompare(semver.coerce(a), semver.coerce(b));
    } catch {
      return 0;
    }
  });
  for (const v of allVersionKeys) {
    const man = versions[v];
    if (!man) continue;
    if (man.dependencies?.[targetName])
      return {
        range: man.dependencies[targetName],
        latestVersion: latestTag || null,
        isDev: false,
        dependencyType: 'dep',
        matchedVersion: v,
      };
    if (includePeer && man.peerDependencies?.[targetName])
      return {
        range: man.peerDependencies[targetName],
        latestVersion: latestTag || null,
        isDev: false,
        dependencyType: 'peer',
        matchedVersion: v,
      };
    if (includeDev && man.devDependencies?.[targetName])
      return {
        range: man.devDependencies[targetName],
        latestVersion: latestTag || null,
        isDev: true,
        dependencyType: 'dev',
        matchedVersion: v,
      };
  }
  return {
    range: null,
    latestVersion: latestTag || null,
    isDev: false,
    dependencyType: null,
    matchedVersion: '',
  };
}

function satisfies(version, range) {
  try {
    if (!version || !range) return false;
    return semver.satisfies(semver.coerce(version), range, { includePrerelease: true });
  } catch {
    return false;
  }
}

async function processPackage(
  targetName,
  targetVersion,
  includeDev,
  includePeer,
  limit,
  maxDependents,
  onRow,
  args,
) {
  if (!args.quiet) console.log(`[${targetName}] discovering dependents…`);
  // Fetch target package metadata once for blast-radius computations
  let targetMeta = null;
  try {
    targetMeta = await getPackageMetadata(targetName, args.timeout);
  } catch (e) {
    if (!args.quiet)
      console.warn(`[${targetName}] failed to fetch target metadata: ${e?.message || e}`);
  }
  const targetTimeMap = targetMeta?.time || null;
  const targetVersionDates = listVersionDatesFromTimeMap(targetTimeMap);
  const targetAllVersions = targetVersionDates.map((v) => v.version);
  const compromisedVersion = targetVersion || '';
  const compromisedPublishedAt =
    compromisedVersion && targetTimeMap ? targetTimeMap[compromisedVersion] || '' : '';

  const {
    names: dependents,
    stats,
    sources,
  } = await fetchAllDependents(targetName, includeDev, includePeer, maxDependents, args.verbose, {
    noLibraries: args.noLibraries,
    noScrape: args.noScrape,
    timeoutMs: args.timeout,
  });
  if (!args.quiet)
    console.log(
      `[${targetName}] found ${dependents.length} dependents (npms:${stats.npms}, libraries:${stats.libraries}, scraped:${stats.scraped})`,
    );
  await Promise.all(
    dependents.map((depName, idx) =>
      limit(async () => {
        try {
          const meta = await getPackageMetadata(depName, args.timeout);
          const { range, latestVersion, isDev, dependencyType, matchedVersion } =
            findDependencyRange(meta, targetName, includeDev, includePeer);
          const lastUpdate = extractLastUpdate(meta);
          // Determine dependent version publish date
          const depTime = meta?.time || {};
          const depVersionToUse = matchedVersion || latestVersion || '';
          const dependentPublishedAt = depVersionToUse ? depTime[depVersionToUse] || '' : '';

          // Blast-radius calculations
          const resolvedAtRelease =
            range && depVersionToUse && targetVersionDates.length > 0
              ? maxSatisfyingAtOrBefore(targetVersionDates, range, toDateSafe(dependentPublishedAt))
              : null;
          const resolvedNow =
            range && targetAllVersions.length > 0
              ? maxSatisfyingNow(targetAllVersions, range)
              : null;
          const likelyImpactedAtRelease = !!(
            resolvedAtRelease &&
            compromisedVersion &&
            semver.eq(semver.coerce(resolvedAtRelease), semver.coerce(compromisedVersion))
          );
          const stillImpactedNow = !!(
            resolvedNow &&
            compromisedVersion &&
            semver.eq(semver.coerce(resolvedNow), semver.coerce(compromisedVersion))
          );
          const exactPin = isExactPin(range, compromisedVersion);
          onRow({
            source_package: targetName,
            source_version: targetVersion || '',
            dependent: depName,
            dependent_version_range: range || '',
            dependent_latest_version: latestVersion || '',
            last_update: lastUpdate || '',
            dependent_matched_version: matchedVersion || '',
            dependency_type: dependencyType || '',
            is_dev_dependency: isDev,
            source_version_satisfies: range ? satisfies(targetVersion, range) : false,
            dependent_source: sources?.get(depName) || '',
            compromised_published_at: compromisedPublishedAt || '',
            dependent_version_published_at: dependentPublishedAt || '',
            resolved_at_dependent_release: resolvedAtRelease || '',
            resolved_now: resolvedNow || '',
            likely_impacted_at_release: likelyImpactedAtRelease,
            still_impacted_now: stillImpactedNow,
            uses_exact_pin: exactPin,
          });
        } catch (e) {
          onRow({
            source_package: targetName,
            source_version: targetVersion || '',
            dependent: depName,
            dependent_version_range: '',
            dependent_latest_version: '',
            last_update: '',
            dependent_matched_version: '',
            dependency_type: '',
            is_dev_dependency: false,
            source_version_satisfies: false,
            error: String(e?.message || e),
            dependent_source: sources?.get(depName) || '',
            compromised_published_at: '',
            dependent_version_published_at: '',
            resolved_at_dependent_release: '',
            resolved_now: '',
            likely_impacted_at_release: false,
            still_impacted_now: false,
            uses_exact_pin: false,
          });
        }
        if (!args.quiet) {
          const processed = idx + 1;
          if (processed % (args.progress || 25) === 0 || processed === dependents.length) {
            console.log(`[${targetName}] processed ${processed}/${dependents.length}`);
          }
        }
        await delay(50);
      }),
    ),
  );
}

async function main() {
  const args = parseArgs(process.argv);
  const inputRows = await readInput(args.input);
  const limit = pLimit(args.concurrency);

  const fields = [
    'source_package',
    'source_version',
    'dependent',
    'dependent_version_range',
    'dependent_latest_version',
    'last_update',
    'dependent_matched_version',
    'dependency_type',
    'is_dev_dependency',
    'source_version_satisfies',
    'dependent_source',
    'compromised_published_at',
    'dependent_version_published_at',
    'resolved_at_dependent_release',
    'resolved_now',
    'likely_impacted_at_release',
    'still_impacted_now',
    'uses_exact_pin',
    'error',
  ];
  const outPath = resolve(process.cwd(), args.output);
  const { stream, wroteHeader } = await openCsvWriter(outPath, fields, args.append);
  let count = 0;
  const onRow = (row) => {
    const line = Papa.unparse({ fields, data: [row] }, { header: false });
    stream.write(line.endsWith('\n') ? line : line + '\n');
    count++;
  };

  for (const row of inputRows) {
    await processPackage(
      row.package,
      row.version,
      args.includeDev,
      args.includePeer,
      limit,
      args.maxDependents,
      onRow,
      args,
    );
  }

  await new Promise((res) => stream.end(res));
  console.log(`Wrote ${count} rows to ${outPath}${wroteHeader ? ' (with header)' : ''}`);
}

async function openCsvWriter(outPath, fields, append = false) {
  let fileExists = false;
  try {
    const s = await stat(outPath);
    fileExists = s.size > 0;
  } catch (_e) {
    // ignore stat errors (file does not exist yet)
  }
  const stream = createWriteStream(outPath, { flags: append ? 'a' : 'w' });
  let wroteHeader = false;
  if (!append || !fileExists) {
    const header = Papa.unparse({ fields, data: [] }, { header: true });
    stream.write(header.endsWith('\n') ? header : header + '\n');
    wroteHeader = true;
  }
  return { stream, wroteHeader };
}

// Execute CLI unconditionally. This file is intended as a bin entry point, not a library.
main().catch((e) => {
  console.error(e);
  process.exit(1);
});
