"""
FR-VOC-04: Vulnerability Reports by Severity & Exploitability
Generates structured reports with filtering, sorting, and export.
"""

import json
import os
import datetime
from typing import List, Optional
from fr_voc_03_patch_tracking import load_patch_db, PatchRecord

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "data", "reports")

def generate_report(
    filter_severity: Optional[List[str]] = None,
    filter_status: Optional[List[str]] = None,
    sort_by: str = "cvss_score",
    include_applied: bool = False
) -> dict:
    """
    FR-VOC-04: Generate vulnerability report with filters.
    sort_by: 'cvss_score' | 'severity' | 'host_ip' | 'cve_id'
    """
    records = load_patch_db()

    # Filter
    if not include_applied:
        records = [r for r in records if r.status != "applied"]
    if filter_severity:
        records = [r for r in records if r.severity in filter_severity]
    if filter_status:
        records = [r for r in records if r.status in filter_status]

    # Sort
    reverse = sort_by in ("cvss_score",)
    records = sorted(records, key=lambda r: getattr(r, sort_by, 0), reverse=reverse)

    # Group by severity
    severity_order = ["Critical", "High", "Medium", "Low"]
    by_severity = {s: [] for s in severity_order}
    for r in records:
        sev = r.severity if r.severity in by_severity else "Low"
        by_severity[sev].append({
            "cve_id": r.cve_id,
            "host": f"{r.host_ip} ({r.hostname})",
            "package": r.package,
            "current_version": r.current_version,
            "fixed_version": r.fixed_version,
            "cvss_score": r.cvss_score,
            "status": r.status,
            "last_checked": r.last_checked
        })

    # Summary stats
    total = len(records)
    avg_cvss = round(sum(r.cvss_score for r in records) / total, 2) if total else 0
    exploitability_score = round(
        sum(r.cvss_score for r in records if r.status == "missing") /
        max(len([r for r in records if r.status == "missing"]), 1), 2
    )

    report = {
        "report_id": f"VOC-RPT-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "filters": {
            "severity": filter_severity or "all",
            "status": filter_status or "all",
            "include_applied": include_applied
        },
        "summary": {
            "total_vulnerabilities": total,
            "avg_cvss_score": avg_cvss,
            "avg_exploitability_missing": exploitability_score,
            "critical_count": len(by_severity["Critical"]),
            "high_count": len(by_severity["High"]),
            "medium_count": len(by_severity["Medium"]),
            "low_count": len(by_severity["Low"]),
        },
        "by_severity": by_severity
    }

    # Save report
    os.makedirs(REPORTS_DIR, exist_ok=True)
    report_path = os.path.join(REPORTS_DIR, f"{report['report_id']}.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[FR-VOC-04] Report generated: {report['report_id']} | {total} vulns | avg CVSS: {avg_cvss}")
    return report

def export_csv(report: dict) -> str:
    """Export report as CSV string."""
    lines = ["CVE ID,Host,Package,Current Version,Fixed Version,CVSS,Severity,Status"]
    for sev, vulns in report["by_severity"].items():
        for v in vulns:
            lines.append(
                f"{v['cve_id']},{v['host']},{v['package']},"
                f"{v['current_version']},{v['fixed_version'] or 'N/A'},"
                f"{v['cvss_score']},{sev},{v['status']}"
            )
    csv_content = "\n".join(lines)

    os.makedirs(REPORTS_DIR, exist_ok=True)
    csv_path = os.path.join(REPORTS_DIR, f"{report['report_id']}.csv")
    with open(csv_path, "w") as f:
        f.write(csv_content)
    return csv_content

def list_reports() -> List[dict]:
    """List all generated reports."""
    if not os.path.exists(REPORTS_DIR):
        return []
    reports = []
    for fname in sorted(os.listdir(REPORTS_DIR)):
        if fname.endswith(".json"):
            with open(os.path.join(REPORTS_DIR, fname)) as f:
                r = json.load(f)
            reports.append({
                "report_id": r["report_id"],
                "generated_at": r["generated_at"],
                "total_vulnerabilities": r["summary"]["total_vulnerabilities"]
            })
    return reports

if __name__ == "__main__":
    # Critical + High unpatched
    report = generate_report(filter_severity=["Critical", "High"])
    print(json.dumps(report["summary"], indent=2))
    csv = export_csv(report)
    print("\nCSV Preview:")
    print("\n".join(csv.split("\n")[:5]))
