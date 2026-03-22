#!/usr/bin/env python3

import argparse
import getpass
import logging
import sys
from pathlib import Path

from src.rules_loader import RulesLoader
from src.scanner import CISScanner
from src.reporter import Reporter

DEFAULT_RULES = Path(__file__).parent / "config" / "cis_rules.yaml"


def main():
    parser = argparse.ArgumentParser(description="CIS Benchmark checker for RHEL")
    parser.add_argument("--hosts", required=True, help="comma-separated target hosts")
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--key", default=None, help="path to SSH private key")
    parser.add_argument("--password", action="store_true", help="use password auth instead of key")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--rules", default=str(DEFAULT_RULES), help="path to rules yaml")
    parser.add_argument("--category", default=None, help="filter by category (ssh, filesystem, etc)")
    parser.add_argument("--format", choices=["terminal", "json", "html"], default="terminal")
    parser.add_argument("--output", default=None, help="output file path for json/html")
    parser.add_argument("--workers", type=int, default=4, help="max concurrent connections")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

    # load rules
    loader = RulesLoader(args.rules)
    try:
        rules = loader.load()
    except (FileNotFoundError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.category:
        rules = loader.get_rules_by_category(args.category)
        if not rules:
            print(f"No rules for category '{args.category}'. Available: {', '.join(loader.get_categories())}", file=sys.stderr)
            sys.exit(1)

    print(f"Loaded {len(rules)} rules")

    # parse hosts
    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]

    # auth
    pw = None
    if args.password:
        pw = getpass.getpass("SSH Password: ")

    scanner = CISScanner(rules=rules, username=args.user, key_path=args.key, password=pw, port=args.port)

    print(f"Scanning {len(hosts)} host(s)...")
    if len(hosts) == 1:
        results = [scanner.scan_host(hosts[0])]
    else:
        results = scanner.scan_hosts(hosts, max_workers=args.workers)

    reporter = Reporter(results)

    if args.format == "terminal":
        reporter.print_terminal()
    elif args.output:
        reporter.save(args.output, fmt=args.format)
        print(f"Report saved to {args.output}")
    else:
        print(reporter.to_json() if args.format == "json" else reporter.to_html())


if __name__ == "__main__":
    main()
