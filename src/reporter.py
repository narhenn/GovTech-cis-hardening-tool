import json
import html
from datetime import datetime


# terminal colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


class Reporter:
    def __init__(self, scan_results):
        self.scan_results = scan_results

    def _stats(self, results):
        total = len(results)
        passed = sum(1 for r in results if r.status == "PASS")
        failed = sum(1 for r in results if r.status == "FAIL")
        errors = sum(1 for r in results if r.status == "ERROR")
        pct = (passed / total * 100) if total > 0 else 0
        return {"total": total, "passed": passed, "failed": failed, "errors": errors, "compliance_pct": round(pct, 1)}

    def print_terminal(self):
        colors = {"PASS": GREEN, "FAIL": RED, "ERROR": YELLOW}

        for host_data in self.scan_results:
            results = host_data["results"]
            stats = self._stats(results)

            print(f"\n{BOLD}{'=' * 70}{RESET}")
            print(f"{BOLD}Host: {host_data['hostname']}{RESET}")
            print(f"Scanned: {host_data['scan_time']}")
            print(f"{'=' * 70}")

            print(f"{'Rule ID':<12} {'Status':<10} {'Title'}")
            print(f"{'-'*12} {'-'*10} {'-'*45}")

            for r in results:
                c = colors.get(r.status, RESET)
                print(f"{r.rule_id:<12} {c}{r.status:<10}{RESET} {r.title[:45]}")

            print(f"\n{GREEN}Passed: {stats['passed']}{RESET} | {RED}Failed: {stats['failed']}{RESET} | Compliance: {stats['compliance_pct']}%")

            # show what failed so you know what to fix
            failed = [r for r in results if r.status == "FAIL"]
            if failed:
                print(f"\n{BOLD}Failed checks:{RESET}")
                for r in failed:
                    print(f"  {RED}[{r.rule_id}]{RESET} {r.title}")
                    if r.remediation:
                        print(f"    fix: {r.remediation}")

    def to_json(self):
        output = {"report_time": datetime.now().isoformat(), "hosts": []}
        for host_data in self.scan_results:
            results = host_data["results"]
            output["hosts"].append({
                "hostname": host_data["hostname"],
                "scan_time": host_data["scan_time"],
                "summary": self._stats(results),
                "results": [r.to_dict() for r in results]
            })
        return json.dumps(output, indent=2)

    def to_html(self):
        lines = [
            "<!DOCTYPE html><html><head><meta charset='utf-8'>",
            "<title>CIS Compliance Report</title>",
            "<style>",
            "body { font-family: Arial, sans-serif; margin: 30px; }",
            "table { border-collapse: collapse; width: 100%; margin: 15px 0; }",
            "th, td { padding: 8px 12px; text-align: left; border: 1px solid #ddd; }",
            "th { background: #333; color: white; }",
            ".pass { color: green; font-weight: bold; }",
            ".fail { color: red; font-weight: bold; }",
            ".error { color: orange; font-weight: bold; }",
            "</style></head><body>",
            "<h1>CIS Benchmark Compliance Report</h1>",
            f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>",
        ]

        for host_data in self.scan_results:
            results = host_data["results"]
            stats = self._stats(results)

            lines.append(f"<h2>{html.escape(host_data['hostname'])}</h2>")
            lines.append(f"<p>Passed: {stats['passed']}/{stats['total']} ({stats['compliance_pct']}%)</p>")

            lines.append("<table><tr><th>Rule</th><th>Status</th><th>Title</th><th>Category</th></tr>")
            for r in results:
                cls = r.status.lower()
                rem = ""
                if r.status == "FAIL" and r.remediation:
                    rem = f"<br><small>fix: {html.escape(r.remediation)}</small>"
                lines.append(
                    f"<tr><td>{html.escape(r.rule_id)}</td>"
                    f"<td class='{cls}'>{r.status}</td>"
                    f"<td>{html.escape(r.title)}{rem}</td>"
                    f"<td>{html.escape(r.category)}</td></tr>"
                )
            lines.append("</table>")

        lines.append("</body></html>")
        return "\n".join(lines)

    def save(self, filepath, fmt="json"):
        content = self.to_json() if fmt == "json" else self.to_html()
        with open(filepath, "w") as f:
            f.write(content)
