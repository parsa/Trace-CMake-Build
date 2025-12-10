#!/usr/bin/env python
"""Merge multiple trace JSON files into one."""

import argparse
import json


def main():
    parser = argparse.ArgumentParser(
        description="Merge multiple trace JSON files"
    )
    parser.add_argument("inputs", nargs="+", help="Input trace JSON files")
    parser.add_argument(
        "-o", "--output", required=True, help="Output merged JSON file"
    )
    args = parser.parse_args()

    merged = {"processes": [], "edges": []}

    for input_file in args.inputs:
        with open(input_file) as f:
            data = json.load(f)
        merged["processes"].extend(data.get("processes", []))
        merged["edges"].extend(data.get("edges", []))

    with open(args.output, "w") as f:
        json.dump(merged, f, indent=2)

    print(
        f"Merged {len(args.inputs)} files -> {len(merged['processes'])} processes, {len(merged['edges'])} edges"
    )


if __name__ == "__main__":
    main()
