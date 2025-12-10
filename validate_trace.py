#!/usr/bin/env python
"""Validate a trace JSON file has expected structure and content."""

import argparse
import json
import re
import sys
from collections import Counter


def parse_expect(value):
    """Parse expect argument: 'pattern' or 'pattern:count'"""
    if ":" in value:
        # Find last colon that's followed by digits only
        match = re.match(r"^(.+):(\d+)$", value)
        if match:
            return match.group(1), int(match.group(2))
    return value, 1


def main():
    parser = argparse.ArgumentParser(
        description="Validate a trace JSON file",
        epilog="Example: %(prog)s trace.json -e cmake -e 'cl|clang|gcc|cc':2",
    )
    parser.add_argument("trace_file", help="Trace JSON file to validate")
    parser.add_argument(
        "-e",
        "--expect",
        action="append",
        metavar="REGEX[:COUNT]",
        help="Expect at least COUNT (default 1) processes matching REGEX (case-insensitive)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v: show process counts, -vv: show all matches)",
    )
    args = parser.parse_args()

    with open(args.trace_file) as f:
        data = json.load(f)

    procs = data.get("processes", [])
    edges = data.get("edges", [])

    print(f"Processes: {len(procs)}")
    print(f"Edges: {len(edges)}")

    if args.verbose >= 1:
        counts = Counter(p.get("name") for p in procs if p.get("name"))
        print("\nProcess counts:")
        for name, count in sorted(counts.items()):
            print(f"  {name}: {count}")
        print()

    errors = []

    # Basic validation
    if len(procs) == 0:
        errors.append("No processes captured")
    if len(edges) == 0:
        errors.append("No edges captured")

    # Check required fields
    required_fields = [
        "pid",
        "name",
        "cmdline",
        "start_time",
        "end_time",
        "duration_s",
        "cpu_user_s",
    ]
    for p in procs:
        for field in required_fields:
            if field not in p:
                errors.append(f"Process {p.get('pid', '?')} missing field: {field}")

    # Check expected processes
    if args.expect:
        for expect in args.expect:
            pattern, min_count = parse_expect(expect)
            try:
                regex = re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                errors.append(f"Invalid regex '{pattern}': {e}")
                continue

            matching = [p for p in procs if regex.search(p.get("name") or "")]
            if len(matching) < min_count:
                all_names = sorted(set(p.get("name") for p in procs if p.get("name")))
                errors.append(
                    f"Expected at least {min_count} process(es) matching /{pattern}/, "
                    f"found {len(matching)}. All names: {all_names}"
                )
            else:
                print(f"Found {len(matching)} process(es) matching /{pattern}/")
                if args.verbose >= 2:
                    # Group by process name
                    by_name = {}
                    for p in matching:
                        name = p.get("name") or "?"
                        if name not in by_name:
                            by_name[name] = []
                        by_name[name].append(p)
                    
                    for name in sorted(by_name.keys()):
                        procs_list = by_name[name]
                        print(f"  {name} ({len(procs_list)}):")
                        for p in procs_list:
                            dur = p.get("duration_s")
                            dur_str = f"{dur:.3f}s" if dur else "?"
                            print(f"    - PID {p.get('pid')}, {dur_str}")

    if errors:
        print("\nValidation FAILED:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("\nValidation passed!")


if __name__ == "__main__":
    main()
