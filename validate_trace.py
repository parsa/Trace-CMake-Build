#!/usr/bin/env python
"""Validate a trace JSON file has expected structure and content."""

import argparse
import json
import sys


def parse_expect(value):
    """Parse expect argument: 'name' or 'name:count'"""
    if ":" in value:
        name, count = value.rsplit(":", 1)
        return name, int(count)
    return value, 1


def main():
    parser = argparse.ArgumentParser(
        description="Validate a trace JSON file",
        epilog="Example: %(prog)s trace.json -e cmake -e clang:2",
    )
    parser.add_argument("trace_file", help="Trace JSON file to validate")
    parser.add_argument(
        "-e",
        "--expect",
        action="append",
        metavar="NAME[:COUNT]",
        help="Expect at least COUNT (default 1) processes matching NAME (case-insensitive substring)",
    )
    args = parser.parse_args()

    with open(args.trace_file) as f:
        data = json.load(f)

    procs = data.get("processes", [])
    edges = data.get("edges", [])

    print(f"Processes: {len(procs)}")
    print(f"Edges: {len(edges)}")

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
                errors.append(
                    f"Process {p.get('pid', '?')} missing field: {field}"
                )

    # Check expected processes
    if args.expect:
        for expect in args.expect:
            name, min_count = parse_expect(expect)
            matching = [
                p
                for p in procs
                if name.lower() in (p.get("name") or "").lower()
            ]
            if len(matching) < min_count:
                all_names = sorted(
                    set(p.get("name") for p in procs if p.get("name"))
                )
                errors.append(
                    f"Expected at least {min_count} '{name}' process(es), "
                    f"found {len(matching)}. All names: {all_names}"
                )
            else:
                print(f"Found {len(matching)} '{name}' process(es)")

    if errors:
        print("\nValidation FAILED:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("\nValidation passed!")


if __name__ == "__main__":
    main()
