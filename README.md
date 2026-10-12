# Scorpion Bug Hunter

An automated bug-bounty recon & vulnerability-scanning pipeline. Feed it a
`targets.txt` file of in-scope URLs/domains (copied from a HackerOne/Bugcrowd
program), and it runs each target through a tiered scan sequence -- passive
recon, active recon, fuzzing/detection, and (optionally, gated) exploitation
-- fanning out across every discovered subdomain, then produces one report
per target.

Full architecture, tier definitions, and the tool-to-category mapping live in
the project's architecture doc (see the link shared in chat / project notes).

## Status

**Working now:** `targets.txt` -> scope-checked -> Tier 0 passive recon
(8 merged subdomain sources: subfinder, assetfinder, github-subdomains,
gitlab-subdomains, chaos, cero, amass [passive mode], tlsx [cert SAN/CN
scraping]; plus gau/waybackurls for archived URLs, asnmap for ASN -> CIDR
`ip_range` assets, cloud_enum for storage-bucket `bucket` assets, and
gitdorker for GitHub code-search exposure findings) -> active subdomain
brute force (puredns/massdns, run once per root target) merged in, plus
a shuffledns bulk-resolve pass (informational, doesn't gate), a dnstwist
typosquat/lookalike-domain check, and s3scanner validating every
cloud_enum bucket's permissions -> fan-out per subdomain -> Tier 1 active
recon chain:

1. `dnsx` -- does the host even resolve? (skips the rest cleanly if not)
2. `httpx` -- liveness + tech fingerprint
3. `naabu` -- broad port sweep
4. `nmap` -- targeted service/version detection, only on naabu's open ports
5. `subzy` and `dnsreaper` -- two independent subdomain-takeover checks
6. `cdncheck` -- CDN/WAF/cloud-provider fingerprinting
7. `tlsx` (posture mode) -- expired certs, deprecated TLS versions, weak ciphers
8. if a live URL was found: `gowitness` (screenshot), `webanalyze` +
   `whatweb` (two independent tech-fingerprint sources), `wafw00f` (WAF
   detection), `katana` (crawl for more endpoints, fed back into the
   asset list), `git-exposure` (native curl check for a world-readable
   `.git/HEAD`), `nuclei` (safe-mode scan: info/low/medium severity only,
   intrusive/fuzz/dos templates excluded; optionally reports out-of-band
   findings via `-interactsh-server` if `integrations.interactsh_server`
   is set, otherwise nuclei falls back to its own default public server)

If Tier 1 found a live URL for an asset, Tier 2 batch 1 (parameter +
content discovery) runs next, same granularity (once per live asset):

1. `uro` -- dedupe every URL already known for this target (gau
   archives, katana's crawl, the live URL itself) before fuzzing
2. `arjun` -- hidden GET/POST parameter discovery
3. `x8` -- a second, independent parameter-discovery pass
4. `ffuf` -- content/path discovery (single-level fuzz)
5. `feroxbuster` -- recursive content discovery (follows directories
   ffuf finds)
6. `kiterunner` -- API route brute-forcing against a wordlist of known
   route/parameter combos
7. `gospider` and `cariddi` -- two further JS-aware crawlers, same
   "feeds new endpoint assets" role as katana
8. `xnLinkFinder` -- endpoint/parameter extraction straight from the
   live URL's response (JS, HTML, inline sourcemaps)
9. `anew` -- records every URL fuzzed this run into a per-target state
   file, so a later run against the same target skips what's already
   been tested instead of re-fuzzing it from scratch

Every new endpoint/parameter these find is persisted as a new asset,
same "feeds the next pass" pattern as katana in Tier 1 -- and batch 2
(vuln-class scanning) runs right after, against the same asset/live URL,
using batch 1's (and Tier 1's) discovered endpoints as its candidate pool:

1. `gf` -- filters the full known-URL list (gau/katana/batch 1's finds)
   down to URLs matching an "xss"-shaped or "redirect"-shaped pattern.
   If `gf` isn't installed, the xss candidate list falls back to just
   the live URL itself (so `dalfox` still runs against something),
   while the redirect candidate list falls back to empty (an
   unfiltered URL list would defeat `openredirex`'s point, so it's
   skipped entirely rather than fuzzed blind). `kxss` (actual-request
   reflection testing, not just a static pattern match) runs against the
   same candidate pool and its results are unioned into the xss
   candidate list alongside `gf`'s.
2. `dalfox` -- XSS scanning, against up to 5 gf+kxss-filtered (or
   fallback) candidate URLs
3. `qsreplace` -- substitutes a `FUZZ` marker into each gf-filtered
   "redirect" URL's query string; `openredirex` then substitutes its
   own payload list into that marker, against up to 5 candidates
4. `corsy` -- CORS misconfiguration checks, against the live URL
5. `crlfuzz` -- CRLF injection checks, against the live URL
6. `smuggler` -- HTTP request smuggling checks, against the live URL
7. `testssl.sh` -- deeper TLS/cipher audit than Tier 1's fast `tlsx`
   posture check, against the live URL
8. `nuclei` (full-template run, tool name `nuclei-full`, separate from
   Tier 1's safe-mode `nuclei` scan) -- every template, not just
   info/low/medium, against the live URL; same optional
   `-interactsh-server` passthrough as Tier 1's nuclei
9. `graphql-cop` -- GraphQL-specific misconfig/introspection checks,
   against up to 3 candidate URLs whose path/query looks like a GraphQL
   endpoint (skipped entirely if none do)

The same `anew`-backed per-target state file also gates the whole of
Tier 2 (both batches): if a live URL was already fuzzed in a previous
run against this target, the entire Tier 2 run for that asset is
skipped rather than re-run from scratch.

Also implemented but **not yet auto-wired** into the per-asset loop
(different input shape than what the pipeline currently has on hand --
see each module's own docstring for the detail):
- `modules/vuln/ssrfmap.py` -- needs a captured HTTP request file to
  replay, which the pipeline doesn't build yet. (Out-of-band/blind
  confirmation itself is covered -- see nuclei's `-interactsh-server`
  support above -- so this is the one remaining blocker, not a missing
  callback server.)
- `modules/vuln/wpscan.py` -- needs a persisted "is this target running
  WordPress" signal; nothing in the current schema records that yet, so
  there's no trigger to call it conditionally.

Results persisted to sqlite. Every tool call degrades gracefully (warns
+ skips, never crashes the run) if its binary isn't installed or its API
token isn't set -- see `docker/Dockerfile` for the expected tool set and
`.env.example` for the tokens each source can use (including
`GITHUB_TOKEN`, required for `gitdorker`). Covered by 301 passing unit
tests (`python -m unittest discover -s tests`).

A few "pick one" choices were made when wiring in the full tool
suggestion list, where two tools cover essentially the same job:
`kxss` over `gxss` (actual-request reflection confirmation), `testssl.sh`
over `sslyze` (deeper TLS audit), `graphql-cop` over `graphqlmap`
(GraphQL misconfig scanning), and `xnLinkFinder` over a bare `LinkFinder`
run (it can fetch a live URL directly instead of needing a pre-downloaded
JS file, so it's auto-wired where `jsluice`'s URL-extraction mode isn't).
`aquatone`/`EyeWitness` were left out as they're the same "screenshot
every live URL" job `gowitness` already does in Tier 1 -- adding a third
screenshotter would triple screenshot time for no new signal, unlike the
other pairs above where each tool genuinely adds an independent
detection angle (second takeover check, second TLS auditor, etc).

**Raw output + step log:** every tool invocation also gets its own raw
output file and an entry in a human + machine readable steps log, under
`output/<target>/<run_id>/`:

```
output/example.com/20261011T071305Z/
  raw/
    tier0_example.com_subfinder.txt
    tier0_example.com_gau.txt
    tier1_app.example.com_dnsx.txt
    tier1_app.example.com_httpx.txt
    tier1_app.example.com_naabu.txt
    tier1_app.example.com_nmap.txt
    ...
  steps.log      -- one line per step, in order: tool, asset, status, result count, raw file
  steps.jsonl    -- the same steps as one JSON object per line
```

A fresh `run_id` (UTC timestamp) is used per run, so re-scanning the same
target never overwrites a previous run's evidence. This is how the chain
between tools stays inspectable: e.g. `nmap`'s step record says exactly
which ports it got from `naabu`'s result, and `katana`'s endpoints show
up as new `endpoint` assets that the next pass fans out over. See
`core/evidence_store.py` for the implementation.

Also implemented, not yet auto-wired into the chain above:
- `modules/recon/jsluice.py`'s `urls`/`secrets` modes -- extracts
  endpoints and secrets from a local JS file. Needs a "download katana's
  discovered .js URLs to disk" step before it can run automatically;
  until then, call it directly with a JS file path.

Also implemented, but not auto-wired into the per-target loop (different
input shape -- see each module's own docstring for how it fits in):
- `modules/recon/trufflehog.py` / `gitleaks.py` -- secrets scanning
  against a repo URL/path, not a domain.
- `modules/recon/bbscope.py` -- pulls a program's scope from HackerOne/
  Bugcrowd/etc, run once per *program* to build `targets/scope/*.json`.
- `modules/recon/hacker_scoper.py` -- a second, independent scope filter
  for cleaning up a raw candidate list before scanning.

**Report generation:** once every tier has run for a target, the
orchestrator calls `reports/generator.py`, which turns the db's findings/
assets/scans rows (never raw tool output directly) into three files
written straight into that run's evidence folder, next to `raw/` and the
steps log:

```
output/example.com/20261011T071305Z/
  report.md      -- full human-readable report (Markdown)
  report.html    -- same content, styled, opens straight in a browser
  report.json    -- same data as structured JSON, for feeding into
                     another tool (dashboard, ticket importer, etc.)
```

Each report includes an executive summary with a severity breakdown, a
tool-coverage table (what ran / was skipped / failed, and how long each
tool spent), the full asset inventory, and one section per finding --
asset, tier, which tool found it, whether it was directly confirmed or
needs manual verification, a short remediation suggestion
(`reports/remediation.py`, pattern-matched off the finding's title), and
a link to the exact raw-output file backing it when one was recorded
(`db.add_evidence`, wired in from Tier 1's subzy/nmap/wafw00f/nuclei and
Tier 2's vuln-class scanners). A clean scan (no findings) still gets a
full report, saying so explicitly rather than looking broken or empty.
A report-generation failure is logged, not raised -- it never erases a
completed scan's already-persisted results.

**Not implemented yet:** Tier 3 (exploitation). It's wired into the
orchestrator's loop (only reached with `--enable-tier3`) but logs "not
implemented" and does nothing, see the TODO in
`core/pipeline/tier3_exploit.py` -- see that file's docstring for why
this tier stays unbuilt (it crosses from vulnerability *detection* into
automated *exploitation*, a different category of tooling this project
doesn't automate).

Run it yourself:
```bash
cp targets/targets.txt.example targets/targets.txt   # then edit it
python cli.py --targets targets/targets.txt -v
```

## Quick layout

- `cli.py` -- entry point
- `config/` -- settings, scope rules, notification config
- `targets/` -- your `targets.txt` and per-program scope files
- `core/` -- orchestrator, scheduler, scope guard, tier pipeline logic
- `modules/` -- one thin wrapper per external tool (recon / fuzzing / vuln / exploit)
- `db/` -- data models and migrations (targets, assets, scans, findings, evidence)
- `reports/` -- report templates and the generator
- `output/` -- per-target, per-run results (git-ignored)
- `logs/` -- full audit trail of every run (git-ignored)
- `docker/` -- containerized Kali-tools environment
- `tests/` -- test suite

## Setup (once dependencies are added)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in API keys, webhook URLs, etc.
python cli.py --targets targets/targets.txt
```

## Safety

Tier 3 (exploitation) is not implemented -- `--enable-tier3` exists as a
flag and logs "not implemented" per asset, but runs no exploitation
tooling. See `core/pipeline/tier3_exploit.py`'s docstring: this project
automates recon, fingerprinting, and vulnerability *detection* only, and
deliberately stops short of automated exploitation.

**Scope enforcement is currently DISABLED for testing** (`config/settings.yaml`
-> `scope.enforce: false`). Every host in `targets.txt` is scanned with no
scope file needed. Set it back to `true` before pointing this at a real
bug bounty program -- once re-enabled, the tool refuses to run active
modules against anything not covered by `targets/scope/<program>.json`
(see `core/scope_guard.py`).
