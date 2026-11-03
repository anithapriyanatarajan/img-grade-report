import datetime as dt
import importlib.util
import pathlib

import openpyxl

HERE = pathlib.Path(__file__).parent
spec = importlib.util.spec_from_file_location("tracker", HERE.parent / "rhtas_cve_tracker.py")
tracker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tracker)


def test_srpm_name():
    assert tracker.srpm_name("pcre2-0:10.40-7.el9_8.src") == "pcre2"
    assert tracker.srpm_name("ca-certificates-0:2026.2.92_v9.0.319-90.3.el9_8.src") == "ca-certificates"
    assert tracker.srpm_name("python3.12-3.12.5-2.el9.src") == "python3.12"


def test_stream_and_version():
    assert tracker.stream_and_version(["1.4.4", "1.4.4-1791535402", "1791535402", "latest"]) == ("1.4", "1.4.4")
    assert tracker.stream_and_version(["v1.5.0"]) == ("1.5", "v1.5.0")
    assert tracker.stream_and_version(["1.3.6", "1.3.7"]) == ("1.3", "1.3.7")
    assert tracker.stream_and_version(["sha-abc", "latest"]) == (None, None)


def test_grade_now():
    img = {"freshness_grades": [
        {"grade": "B", "start_date": "2026-10-24T02:43:13+00:00", "end_date": "2026-10-29T23:14:55+00:00"},
        {"grade": "C", "start_date": "2026-10-29T23:14:55+00:00", "end_date": "2026-11-21T23:14:55+00:00"},
        {"grade": "D", "start_date": "2026-11-21T23:14:55+00:00", "end_date": "2027-01-20T23:14:55+00:00"},
    ]}
    now = dt.datetime(2026, 11, 3, tzinfo=dt.timezone.utc)
    assert tracker.grade_now(img, now) == ("C", ("D", "2026-11-21"))


def test_build_workbook(tmp_path):
    import json
    data = json.loads((HERE / "fixture_pull.json").read_text())
    out = tmp_path / "t.xlsx"
    n_img, n_cve, n_pkg = tracker.build_workbook(data, out)
    assert (n_img, n_cve, n_pkg) == (5, 4, 4)
    wb = openpyxl.load_workbook(out)
    assert wb.sheetnames == ["Summary", "Images", "CVEs", "Fix by package", "Image×CVE"]
    summary_streams = [c.value for c in wb["Summary"]["A"][1:4]]
    assert summary_streams == ["1.3", "1.4", "independent (0.9)"]
    assert wb["Image×CVE"].max_row == 1 + 6  # 3 findings per stream
