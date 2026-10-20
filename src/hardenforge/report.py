"""Report export (HTML / CSV / JSON). All untrusted text is escaped; CSV cells are neutralised against formula injection."""
from __future__ import annotations

import csv
import html
import io
import json

SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _cell(v) -> str:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def to_csv(scan: dict) -> str:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["rule_id", "version", "outcome", "severity", "profile", "title", "source", "control_ref", "message", "evidence_sha256", "remediation"])
    for r in scan["results"]:
        p = r["provenance"]
        w.writerow([_cell(x) for x in (r["rule_id"], r["rule_version"], r["outcome"], r["severity"], r.get("profile"), r["title"],
                                       f'{p["kind"]}:{p["source"]} {p["version"]}', p.get("control_ref"), r["message"], r["evidence_sha256"], r.get("remediation"))])
    return out.getvalue()


def to_json(scan: dict) -> str:
    return json.dumps(scan, indent=2)


def to_html(scan: dict, profiles: dict) -> str:
    e, s = html.escape, scan["summary"]
    res = sorted(scan["results"], key=lambda r: (r["outcome"] not in ("FAIL", "ERROR"), SEV.get(r["severity"], 9), r["rule_id"]))
    rows = "".join(
        f'<tr><td class="o {e(r["outcome"])}">{e(r["outcome"])}</td><td>{e(r["severity"])}</td><td>{e(r.get("profile") or "-")}</td>'
        f'<td>{e(r["rule_id"])}</td><td>{e(r["title"])}</td><td>{e(r.get("remediation") or "")}</td>'
        f'<td><details><summary>evidence</summary><pre>{e(json.dumps(r["evidence"], indent=1))}</pre>{e(r["message"])}<br>sha256 {e(r["evidence_sha256"])}</details></td></tr>'
        for r in res)
    prof = " | ".join(f'{l}: score {p["score_percent"]}% coverage {p["coverage_percent"]}%' for l, p in profiles.items())
    counts = " | ".join(f"{k} {v}" for k, v in s["counts"].items())
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>HardenForge report #{scan["id"]}</title>
<style>body{{font:14px system-ui,sans-serif;max-width:1100px;margin:24px auto;padding:0 12px;color:#14213d}}table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid #dde2ea;padding:6px;text-align:left;vertical-align:top}}.o{{font-weight:600}}.PASS{{color:#1a7f4b}}.FAIL,.ERROR{{color:#c0392b}}
.big{{font-size:28px;font-weight:700}}pre{{background:#f4f6fa;padding:8px;overflow:auto}}</style></head><body>
<h1>Configuration audit report</h1>
<p>Host <b>{e(str(scan["host"]))}</b> · {e(str(scan["distro"] or scan["os_family"]))} {e(str(scan["version"] or ""))} · scanned {e(scan["ts"])} · source: {e(scan["source"])}</p>
<p><span class="big">{e(str(s["score_percent"]))}%</span> technical-compliance score &nbsp; <span class="big">{e(str(s["coverage_percent"]))}%</span> assessment coverage</p>
<p>{e(counts)}<br>{e(prof)}</p>
<table><tr><th>Outcome</th><th>Severity</th><th>Lvl</th><th>Rule</th><th>Title</th><th>Remediation (manual)</th><th>Evidence</th></tr>{rows}</table>
<h2>Limitations</h2><ul><li>Read-only audit; no changes were made. Remediation text is guidance and was not executed.</li>
<li>Score = PASS ÷ (PASS+FAIL); NOT_APPLICABLE excluded; ERROR, NOT_CHECKED and MANUAL_REVIEW are not counted as compliant.</li>
<li>Rules are community examples unless their source says otherwise. This is an internal score, not an official CIS result.</li>
<li>Only the checks listed above were run; results do not describe overall security posture.</li></ul></body></html>"""
