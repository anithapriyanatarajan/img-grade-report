# RHTAS CVE tracker

Builds an Excel tracker of the fixable CVEs in every RHTAS container image. It covers each supported release stream (1.3, 1.4, 1.5, …), using live data from the [Red Hat Ecosystem Catalog](https://catalog.redhat.com) API (Pyxis). The API is public, so no credentials are needed.

The catalog lists only CVEs in RPMs for which Red Hat has **already shipped a fix** (an RHSA). So every finding in the tracker can be cleared by rebuilding the image on current packages; no upstream code change is needed.

## Run it

```bash
pip install -r requirements.txt
python3 rhtas_cve_tracker.py                          # auto-detect active streams
python3 rhtas_cve_tracker.py --streams 1.3 1.4 1.5    # pick streams explicitly
python3 rhtas_cve_tracker.py --save-json pull.json    # keep the raw pull for diffing
python3 rhtas_cve_tracker.py --from-json pull.json    # rebuild the workbook offline
```

The output is `rhtas_cve_tracker_<date>.xlsx`, or the path given with `--out`.

| Option | Default | What it does |
| --- | --- | --- |
| `--streams X.Y …` | auto | Release streams to report |
| `--namespace` | `rhtas` | Catalog namespace; works for any product (`rhtap`, `rhacs`, …) |
| `--arch` | `amd64` | Architecture to read; other arches normally match |
| `--active-days` | 180 | Auto-detect: a stream is active if built within this many days |
| `--min-repos` | 5 | Auto-detect: the stream must appear in at least this many repos |
| `--max-images` | 400 | Newest images scanned per repo when looking for stream tags |
| `--no-independent` | off | Drop repos versioned on their own scheme (policy-controller, ec, model-*) |

Auto-detect prints the streams it found. If an end-of-life stream is still being rebuilt, pass `--streams` with only the supported ones.

## What's in the workbook

| Tab | One row per | Use it for |
| --- | --- | --- |
| Summary | stream | Headline counts per stream (all formulas) |
| Images | stream × image | Catalog grade today, when it next drops, CVE counts, link to the catalog security tab, owner and status |
| CVEs | stream × CVE | Triage: severity, package, fixing RHSA, affected images |
| Fix by package | stream × RPM/RHSA | The z-stream work list: one row per package bump, and how many CVEs and images it clears |
| Image×CVE | stream × image × CVE | Raw pairs; every count above is computed from this tab |

Yellow cells are inputs (owner, status, notes). Everything else is catalog data or formulas, so refresh it by re-running the script, not by editing.

## How streams are chosen

For each repository, the script reads the newest images, up to `--max-images`. It maps every `x.y.z` tag to the stream `x.y` and keeps the newest image per stream. A repo with no image in any selected stream is reported as `independent (x.y)` with its newest image. This covers components with their own versioning, such as policy-controller 1.0.x, ec 0.9 and model-validation 0.1.x.

## Automation

`.github/workflows/cve-tracker.yml` does three things:

- **On pull requests:** runs the tests.
- **Every Monday:** builds the tracker and uploads the `.xlsx` plus the raw `pull.json` as a run artifact, kept for 90 days.
- **On demand:** "Run workflow" lets you pick the streams or another namespace.

## Development

```bash
pip install -r requirements.txt pytest
pytest -q
```

`tests/fixture_pull.json` is a small saved pull, so the workbook build can be tested without network access. If the catalog API changes shape, update `pull()` and refresh the fixture with `--save-json`.

## Caveats

- **Architecture:** only amd64 is read by default.
- **Bundles:** operator bundle images usually show 0 CVEs; check that they reference the rebuilt operator digest.
- **Time to appear:** catalog data lags a release by a few hours; re-run after publishing to confirm the image reached grade A.
