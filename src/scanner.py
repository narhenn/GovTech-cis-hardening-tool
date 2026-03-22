import re
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.utils import create_ssh_client, run_command, close_ssh_client

logger = logging.getLogger(__name__)


class ScanResult:
    def __init__(self, rule_id, title, category, status, actual_output, expected, remediation=None):
        self.rule_id = rule_id
        self.title = title
        self.category = category
        self.status = status  # PASS / FAIL / ERROR
        self.actual_output = actual_output
        self.expected = expected
        self.remediation = remediation

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category,
            "status": self.status,
            "actual_output": self.actual_output,
            "expected": self.expected,
            "remediation": self.remediation
        }


class CISScanner:
    def __init__(self, rules, username, key_path=None, password=None, port=22):
        self.rules = rules
        self.username = username
        self.key_path = key_path
        self.password = password
        self.port = port

    def scan_host(self, hostname):
        """connect to a host and run all the CIS checks against it"""
        results = []
        client = None

        try:
            client = create_ssh_client(
                hostname, self.username,
                key_path=self.key_path,
                password=self.password,
                port=self.port
            )
            for rule in self.rules:
                results.append(self._evaluate_rule(client, rule))

        except Exception as e:
            logger.error("Failed to connect to %s: %s", hostname, e)
            for rule in self.rules:
                results.append(ScanResult(
                    rule["id"], rule["title"], rule["category"],
                    "ERROR", f"Connection failed: {e}",
                    rule["expected"], rule.get("remediation")
                ))
        finally:
            close_ssh_client(client)

        return {
            "hostname": hostname,
            "scan_time": datetime.now().isoformat(),
            "results": results
        }

    def scan_hosts(self, hostnames, max_workers=4):
        """scan multiple hosts at the same time using threads"""
        all_results = []
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(self.scan_host, h): h for h in hostnames}
            for future in as_completed(futures):
                host = futures[future]
                try:
                    all_results.append(future.result())
                except Exception as e:
                    logger.error("Error scanning %s: %s", host, e)
                    all_results.append({
                        "hostname": host,
                        "scan_time": datetime.now().isoformat(),
                        "results": [],
                        "error": str(e)
                    })
        return all_results

    def _evaluate_rule(self, client, rule):
        stdout, stderr, exit_code = run_command(client, rule["command"])
        match_type = rule["match_type"]
        expected = rule["expected"]

        try:
            if match_type == "exact":
                passed = stdout.strip() == expected.strip()
            elif match_type == "contains":
                passed = expected in stdout
            elif match_type == "absent":
                passed = stdout.strip() == ""
            elif match_type == "regex":
                passed = bool(re.search(expected, stdout))
            else:
                passed = False
        except Exception as e:
            logger.error("Error evaluating rule %s: %s", rule["id"], e)
            return ScanResult(
                rule["id"], rule["title"], rule["category"],
                "ERROR", f"Evaluation error: {e}",
                expected, rule.get("remediation")
            )

        return ScanResult(
            rule["id"], rule["title"], rule["category"],
            "PASS" if passed else "FAIL", stdout,
            expected, rule.get("remediation")
        )
