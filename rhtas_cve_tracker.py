#!/usr/bin/env python3
"""
rhtas_cve_tracker.py: per-release-stream CVE tracker for Red Hat container images.

Pulls every repository in a catalog namespace (default: rhtas) from the Red Hat
Ecosystem Catalog API (Pyxis). For each repository and each release stream, it
takes the newest image tagged in that stream. It then reads the image's
vulnerabilities and freshness grade, and writes an Excel tracker with the same
tabs as RHTAS_1.4.5_CVE_Tracker.xlsx, with a Stream column added throughout.

The catalog API is public, so no login is needed.

Usage
  pip install openpyxl
  python3 rhtas_cve_tracker.py                          # auto-detect active streams
  python3 rhtas_cve_tracker.py --streams 1.3 1.4 1.5    # explicit streams
  python3 rhtas_cve_tracker.py --save-json pull.json    # also keep the raw pull
  python3 rhtas_cve_tracker.py --from-json pull.json    # rebuild workbook offline
  python3 rhtas_cve_tracker.py --namespace rhtap --out rhtap.xlsx   # another product

What the catalog lists: CVEs in RPMs inside the image that Red Hat has already
fixed in a shipped advisory. Every finding can therefore be fixed by rebuilding
the image with current packages.
"""
import argparse
import datetime as dt
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

API = "https://catalog.redhat.com/api/containers/v1"
CATALOG_UI = "https://catalog.redhat.com/en/software/containers"
SEVS = ["Critical", "Important", "Moderate", "Low"]
RANK = {s: i for i, s in enumerate(SEVS)}
TAG_RE = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?(?:-\d+)?$")


# ----------------------------------------------------------------- catalog API
def get(path, params):
    url = f"{API}{path}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "User-Agent": "rhtas-cve-tracker"})
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                return json.load(r)
        except Exception as e:  # network blips and rate limits
            if attempt == 4:
                raise RuntimeError(f"GET {url} failed: {e}") from e
            time.sleep(2 ** attempt)


def paged(path, params, page_size=100, max_items=None):
    page, n = 0, 0
    while True:
        data = get(path, {**params, "page_size": page_size, "page": page}).get("data") or []
        for item in data:
            yield item
            n += 1
            if max_items and n >= max_items:
                return
        if len(data) < page_size:
            return
        page += 1


def list_repos(namespace):
    flt = f'repository=regex="^{namespace}/"'
    inc = "data._id,data.repository,data.registry,data.published,data.eol_date"
    return [r for r in paged("/repositories", {"filter": flt, "include": inc})
            if r.get("published", True)]


def list_images(repo, arch, max_images):
    flt = f'repositories.repository=="{repo}" and architecture=="{arch}"'
    inc = ("data._id,data.creation_date,data.freshness_grades,"
           "data.repositories.repository,data.repositories.tags.name,"
           "data.repositories.manifest_list_digest")
    return list(paged("/images", {"filter": flt, "include": inc,
                                  "sort_by": "creation_date[desc]"},
                      max_items=max_images))


def image_vulns(image_id):
    out = {}
    for v in paged(f"/images/id/{image_id}/vulnerabilities", {}, page_size=250):
        cve = v.get("cve_id")
        if not cve:
            continue
        sev = (v.get("severity") or "").capitalize()
        pk = {(p.get("srpm_nevra") or p.get("rpm_nvra") or "") for p in (v.get("packages") or [])}
        rec = out.setdefault(cve, {"cve": cve, "severity": sev, "advisories": set(),
                                   "public_date": (v.get("public_date") or "")[:10],
                                   "packages": set()})
        if RANK.get(sev, 9) < RANK.get(rec["severity"], 9):
            rec["severity"] = sev
        if v.get("advisory_id"):
            adv = v["advisory_id"]
            rec["advisories"].add(adv if adv.startswith("RH") else f"{v.get('advisory_type') or 'RHSA'}-{adv}")
        rec["packages"] |= {srpm_name(p) for p in pk if p}
    return [{**r, "advisories": sorted(r["advisories"]), "packages": sorted(r["packages"])}
            for r in out.values()]


def srpm_name(nevra):
    """'pcre2-0:10.40-7.el9_8.src' -> 'pcre2'"""
    return re.sub(r"-(\d+:)?[^-]+-[^-]+$", "", nevra.replace(".src", ""))


# ----------------------------------------------------------- stream handling
def tags_of(img, repo):
    return [t["name"] for r in img.get("repositories", []) if r.get("repository") == repo
            for t in (r.get("tags") or [])]


def stream_and_version(tags):
    """Best x.y stream and full version from an image's tags, or (None, None)."""
    best = None
    for t in tags:
        m = TAG_RE.match(t)
        if m:
            key = (int(m[1]), int(m[2]), int(m[3] or 0))
            if best is None or key > best[0]:
                best = (key, t)
    if not best:
        return None, None
    return f"{best[0][0]}.{best[0][1]}", best[1]


def grade_now(img, now):
    cur, nxt = None, None
    for g in sorted(img.get("freshness_grades") or [], key=lambda g: g.get("start_date", "")):
        start = parse_ts(g.get("start_date"))
        end = parse_ts(g.get("end_date"))
        if start and start <= now and (end is None or end > now):
            cur = g.get("grade")
        elif start and start > now and nxt is None:
            nxt = (g.get("grade"), g.get("start_date", "")[:10])
    return cur, nxt


def parse_ts(s):
    if not s:
        return None
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def pull(args):
    now = dt.datetime.now(dt.timezone.utc)
    repos = list_repos(args.namespace)
    if not repos:
        sys.exit(f"No published repositories found under '{args.namespace}/'.")
    print(f"{len(repos)} repositories under {args.namespace}/", file=sys.stderr)

    def scan(repo):
        name = repo["repository"]
        per_stream = {}
        for img in list_images(name, args.arch, args.max_images):
            stream, version = stream_and_version(tags_of(img, name))
            if stream and stream not in per_stream:   # newest first, so first hit wins
                per_stream[stream] = (img, version)
        newest = None
        if per_stream:
            newest = max(per_stream.values(), key=lambda iv: iv[0]["creation_date"])
        return repo, per_stream, newest

    with ThreadPoolExecutor(args.workers) as ex:
        scanned = list(ex.map(scan, repos))

    # Stream selection
    if args.streams:
        streams = args.streams
    else:
        cutoff = now - dt.timedelta(days=args.active_days)
        count = defaultdict(int)
        for _, per_stream, _ in scanned:
            for s, (img, _) in per_stream.items():
                if parse_ts(img["creation_date"]) >= cutoff:
                    count[s] += 1
        streams = sorted((s for s, n in count.items() if n >= args.min_repos),
                         key=lambda s: tuple(map(int, s.split("."))))
        print(f"Auto-detected streams (built in last {args.active_days} days, in "
              f">= {args.min_repos} repos): {', '.join(streams) or 'none'}. "
              f"Pass --streams to override.", file=sys.stderr)

    jobs = []
    for repo, per_stream, newest in scanned:
        hit = False
        for s in streams:
            if s in per_stream:
                jobs.append((repo, s, *per_stream[s]))
                hit = True
        if not hit and args.include_independent and newest:
            img, version = newest
            jobs.append((repo, f"independent ({stream_and_version([version])[0]})", img, version))

    def enrich(job):
        repo, stream, img, version = job
        grade, nxt = grade_now(img, now)
        digest = next((r.get("manifest_list_digest") for r in img.get("repositories", [])
                       if r.get("repository") == repo["repository"]), None)
        return {"repo": repo["repository"], "repo_id": repo["_id"], "stream": stream,
                "version": version, "image_id": img["_id"],
                "created": img["creation_date"][:10], "digest": digest,
                "grade": grade, "next_grade": nxt[0] if nxt else None,
                "next_grade_date": nxt[1] if nxt else None,
                "eol_date": (repo.get("eol_date") or "")[:10] or None,
                "vulns": image_vulns(img["_id"])}

    with ThreadPoolExecutor(args.workers) as ex:
        rows = list(ex.map(enrich, jobs))
    return {"generated": now.isoformat(timespec="seconds"), "namespace": args.namespace,
            "arch": args.arch, "streams": streams, "rows": rows}


# ------------------------------------------------------------------- workbook
def build_workbook(d, out):
    from openpyxl import Workbook
    from openpyxl.formatting.rule import CellIsRule
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.datavalidation import DataValidation

    A = "Arial"
    F, B = Font(name=A, size=10), Font(name=A, size=10, bold=True)
    H, HF = Font(name=A, bold=True, color="FFFFFF"), PatternFill("solid", fgColor="1F3864")
    LINK = Font(name=A, size=10, color="0563C1", underline="single")
    INPUT = PatternFill("solid", fgColor="FFF2CC")
    SEVCOL = {"Critical": "C00000", "Important": "E26B0A", "Moderate": "BF9000", "Low": "548235"}
    STATUS = '"Open,In progress,Fixed in build,Verified in catalog,Not affected (VEX),Deferred"'
    ns = d["namespace"]

    def header(ws, cols, widths):
        for c, (h, w) in enumerate(zip(cols, widths), 1):
            x = ws.cell(1, c, h)
            x.font, x.fill = H, HF
            x.alignment = Alignment(wrap_text=True, vertical="center")
            ws.column_dimensions[get_column_letter(c)].width = w
        ws.row_dimensions[1].height = 30
        ws.freeze_panes = "C2"

    def sevfmt(ws, col, last):
        for s, c in SEVCOL.items():
            ws.conditional_formatting.add(f"{col}2:{col}{last}", CellIsRule(
                operator="equal", formula=[f'"{s}"'], font=Font(name=A, bold=True, color=c)))

    def put(ws, r, vals, font=F):
        for c, v in enumerate(vals, 1):
            ws.cell(r, c, v).font = font

    def inputs(ws, r, cols, dv=None, status_col=None):
        for c in cols:
            ws.cell(r, c).fill, ws.cell(r, c).font = INPUT, F
        if dv and status_col:
            ws.cell(r, status_col, "Open")
            dv.add(ws.cell(r, status_col).coordinate)

    def short(repo):
        return repo.split("/", 1)[1].replace("-rhel9", "").replace("-rhel10", "")

    rows = sorted(d["rows"], key=lambda r: (r["stream"], short(r["repo"])))
    streams = list(dict.fromkeys([s for s in d["streams"]] +
                                 sorted({r["stream"] for r in rows} - set(d["streams"]))))

    wb = Workbook()
    wb.calculation.fullCalcOnLoad = True

    # Image×CVE (long form; every count in the workbook comes from here)
    p = wb.active
    p.title = "Image×CVE"
    header(p, ["Stream", "Image", "Repository", "CVE", "Severity", "Package(s)", "Fixing advisory"],
           [16, 28, 40, 18, 12, 26, 30])
    n = 1
    for r in rows:
        for v in sorted(r["vulns"], key=lambda v: (RANK.get(v["severity"], 9), v["cve"])):
            n += 1
            put(p, n, [r["stream"], short(r["repo"]), r["repo"], v["cve"], v["severity"],
                       ", ".join(v["packages"]), ", ".join(v["advisories"])])
    PN = max(n, 2)
    sevfmt(p, "E", PN)
    p.auto_filter.ref = f"A1:G{PN}"
    IX = "'Image×CVE'!"

    # Images
    s = wb.create_sheet("Images", 0)
    header(s, ["Stream", "Image", "Repository", "Version tag", "Built", "Grade today",
               "Next grade", "Grade changes on", "Critical", "Important", "Moderate", "Low",
               "Total", "Catalog", "Owner", "Status", "Target", "Notes"],
           [16, 28, 40, 16, 11, 9, 9, 13, 9, 10, 10, 8, 8, 10, 16, 18, 10, 36])
    dv = DataValidation(type="list", formula1=STATUS, allow_blank=True)
    s.add_data_validation(dv)
    for k, r in enumerate(rows, 2):
        put(s, k, [r["stream"], short(r["repo"]), r["repo"], r["version"], r["created"],
                   r["grade"], r["next_grade"], r["next_grade_date"]])
        for c, sev in zip(range(9, 13), SEVS):
            s.cell(k, c, f'=COUNTIFS({IX}$A$2:$A${PN},$A{k},{IX}$C$2:$C${PN},$C{k},'
                         f'{IX}$E$2:$E${PN},"{sev}")').font = F
        s.cell(k, 13, f"=SUM(I{k}:L{k})").font = B
        lk = s.cell(k, 14, "open")
        lk.hyperlink = (f"{CATALOG_UI}/{r['repo']}/{r['repo_id']}"
                        f"?image={r['image_id']}&container-tabs=security")
        lk.font = LINK
        inputs(s, k, range(15, 19), dv, 16)
    SN = len(rows) + 1
    s.conditional_formatting.add(f"I2:I{SN}", CellIsRule(operator="greaterThan", formula=["0"],
                                 fill=PatternFill("solid", fgColor="F4CCCC")))
    s.conditional_formatting.add(f"F2:F{SN}", CellIsRule(operator="equal", formula=['"F"'],
                                 fill=PatternFill("solid", fgColor="F4CCCC")))
    s.auto_filter.ref = f"A1:R{SN}"

    # CVEs: one row per (stream, CVE)
    cv = wb.create_sheet("CVEs", 1)
    header(cv, ["Stream", "CVE", "Severity", "Package(s)", "Fixing advisory", "Public date",
                "# images", "Affected images", "Owner", "Status", "Notes"],
           [16, 18, 11, 24, 30, 11, 9, 60, 14, 18, 30])
    agg = {}
    for r in rows:
        for v in r["vulns"]:
            key = (r["stream"], v["cve"])
            a = agg.setdefault(key, {**v, "images": []})
            a["images"].append(short(r["repo"]))
    dv2 = DataValidation(type="list", formula1=STATUS, allow_blank=True)
    cv.add_data_validation(dv2)
    cves = sorted(agg.items(), key=lambda kv: (streams.index(kv[0][0]), RANK.get(kv[1]["severity"], 9),
                                               -len(kv[1]["images"]), kv[0][1]))
    for k, ((stream, cve), a) in enumerate(cves, 2):
        put(cv, k, [stream, cve, a["severity"], ", ".join(a["packages"]),
                    ", ".join(a["advisories"]), a["public_date"]])
        cv.cell(k, 2).hyperlink = f"https://access.redhat.com/security/cve/{cve}"
        cv.cell(k, 2).font = LINK
        cv.cell(k, 7, f"=COUNTIFS({IX}$A$2:$A${PN},A{k},{IX}$D$2:$D${PN},B{k})").font = F
        cv.cell(k, 8, ", ".join(sorted(a["images"]))).font = F
        inputs(cv, k, (9, 10, 11), dv2, 10)
    CN = max(len(cves) + 1, 2)
    sevfmt(cv, "C", CN)
    cv.auto_filter.ref = f"A1:K{CN}"

    # Fix by package: the work list per stream
    fp = wb.create_sheet("Fix by package", 2)
    header(fp, ["Stream", "Package (SRPM)", "Fixing advisory", "Worst severity", "CVEs closed",
                "Critical", "Important", "Moderate", "Low", "Images affected", "Images",
                "Owner", "Status"],
           [16, 22, 30, 12, 10, 9, 10, 10, 8, 10, 60, 14, 18])
    grp = {}
    for (stream, cve), a in agg.items():
        g = grp.setdefault((stream, ", ".join(a["packages"]), ", ".join(a["advisories"])),
                           {"sev": set(), "images": set()})
        g["sev"].add(a["severity"])
        g["images"] |= set(a["images"])
    dv3 = DataValidation(type="list", formula1=STATUS, allow_blank=True)
    fp.add_data_validation(dv3)
    items = sorted(grp.items(), key=lambda kv: (streams.index(kv[0][0]),
                                                min(RANK.get(x, 9) for x in kv[1]["sev"]),
                                                -len(kv[1]["images"])))
    for k, ((stream, pk, adv), g) in enumerate(items, 2):
        put(fp, k, [stream, pk, adv, min(g["sev"], key=lambda x: RANK.get(x, 9))])
        fp.cell(k, 2).font = B
        fp.cell(k, 5, f"=SUM(F{k}:I{k})").font = F
        for c, sev in zip(range(6, 10), SEVS):
            fp.cell(k, c, f'=COUNTIFS(CVEs!$A$2:$A${CN},$A{k},CVEs!$D$2:$D${CN},$B{k},'
                          f'CVEs!$E$2:$E${CN},$C{k},CVEs!$C$2:$C${CN},"{sev}")').font = F
        fp.cell(k, 10, len(g["images"])).font = F
        fp.cell(k, 11, ", ".join(sorted(g["images"]))).font = F
        inputs(fp, k, (12, 13), dv3, 13)
    FN = max(len(items) + 1, 2)
    sevfmt(fp, "D", FN)
    fp.auto_filter.ref = f"A1:M{FN}"

    # Summary: one row per stream, all formulas
    sm = wb.create_sheet("Summary", 0)
    header(sm, ["Stream", "Images", "Images with findings", "Images at grade A",
                "Unique CVEs: Critical", "Important", "Moderate", "Low", "Unique CVEs total",
                "Image–CVE pairs", "Packages to bump"],
           [22, 9, 12, 12, 12, 11, 11, 9, 12, 12, 12])
    sm.freeze_panes = "B2"
    for k, st in enumerate(streams, 2):
        sm.cell(k, 1, st).font = B
        sm.cell(k, 2, f"=COUNTIF(Images!$A$2:$A${SN},A{k})").font = F
        sm.cell(k, 3, f'=COUNTIFS(Images!$A$2:$A${SN},A{k},Images!$M$2:$M${SN},">0")').font = F
        sm.cell(k, 4, f'=COUNTIFS(Images!$A$2:$A${SN},A{k},Images!$F$2:$F${SN},"A")').font = F
        for c, sev in zip(range(5, 9), SEVS):
            sm.cell(k, c, f'=COUNTIFS(CVEs!$A$2:$A${CN},$A{k},CVEs!$C$2:$C${CN},"{sev}")').font = F
        sm.cell(k, 9, f"=SUM(E{k}:H{k})").font = B
        sm.cell(k, 10, f"=COUNTIF({IX}$A$2:$A${PN},A{k})").font = F
        sm.cell(k, 11, f'=COUNTIF(\'Fix by package\'!$A$2:$A${FN},A{k})').font = F
    last = len(streams) + 1
    sm.cell(last + 2, 1, f"Pulled {d['generated']} from the Red Hat Ecosystem Catalog "
                         f"(Pyxis API), namespace {ns}/, arch {d['arch']}.").font = Font(name=A, size=9, italic=True)
    sm.cell(last + 3, 1, "Each stream uses the newest image tagged x.y.* in that stream. "
                         "'independent' rows are repos versioned on their own scheme, "
                         "shown with their newest image.").font = Font(name=A, size=9, italic=True)
    sm.cell(last + 4, 1, "Yellow cells on other tabs are inputs (owner, status, notes); "
                         "everything else is catalog data or formulas. Re-run the script to refresh.").font = Font(name=A, size=9, italic=True)

    wb.save(out)
    return len(rows), len(cves), len(items)


# ----------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--namespace", default="rhtas", help="catalog namespace (default: rhtas)")
    ap.add_argument("--streams", nargs="+", metavar="X.Y",
                    help="release streams to report, e.g. 1.3 1.4 1.5 (default: auto-detect)")
    ap.add_argument("--arch", default="amd64")
    ap.add_argument("--active-days", type=int, default=180,
                    help="auto-detect: a stream counts as active if built within this many days (default 180)")
    ap.add_argument("--min-repos", type=int, default=5,
                    help="auto-detect: minimum repos a stream must appear in (default 5)")
    ap.add_argument("--max-images", type=int, default=400,
                    help="newest images to scan per repo when looking for stream tags (default 400)")
    ap.add_argument("--no-independent", dest="include_independent", action="store_false",
                    help="omit repos with no image in any selected stream")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--save-json", help="write the raw pull to this file")
    ap.add_argument("--from-json", help="skip the API; build the workbook from a saved pull")
    ap.add_argument("--out", help="output .xlsx (default: <namespace>_cve_tracker_<date>.xlsx)")
    args = ap.parse_args()

    if args.from_json:
        with open(args.from_json) as fh:
            data = json.load(fh)
    else:
        data = pull(args)
        if args.save_json:
            with open(args.save_json, "w") as fh:
                json.dump(data, fh, indent=1)
    out = args.out or f"{data['namespace']}_cve_tracker_{data['generated'][:10]}.xlsx"
    n_img, n_cve, n_pkg = build_workbook(data, out)
    print(f"Wrote {out}: {n_img} image rows, {n_cve} stream×CVE rows, {n_pkg} package rows "
          f"across streams {', '.join(data['streams'])}.", file=sys.stderr)


if __name__ == "__main__":
    main()
