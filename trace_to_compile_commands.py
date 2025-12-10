#!/usr/bin/env python
"""
Convert a process trace JSON (from trace_cmake_build.py) to compile_commands.json.

Extracts cl.exe invocations and their response file contents, parses compiler flags,
and generates a compile_commands.json suitable for clangd/IDE use.

Usage:
    python tools/trace_to_compile_commands.py bld.json -o compile_commands.json
"""

import argparse
import json
import re
import shlex
from pathlib import Path
from typing import Any


def parse_msvc_args(rsp_content: str) -> list[str]:
    """Parse MSVC response file content into a list of arguments.

    Handles:
    - Quoted paths with spaces
    - Forward and backslash paths
    - MSVC-style flags (/flag, -flag)
    """
    # MSVC uses space-separated args, with quoted strings for paths with spaces
    # We need to handle both "path" and unquoted paths
    args = []
    current = ""
    in_quote = False

    for char in rsp_content:
        if char == '"':
            in_quote = not in_quote
            current += char
        elif char in (" ", "\t", "\r", "\n") and not in_quote:
            if current.strip():
                # Remove surrounding quotes if present
                arg = current.strip()
                if arg.startswith('"') and arg.endswith('"'):
                    arg = arg[1:-1]
                args.append(arg)
            current = ""
        else:
            current += char

    # Don't forget the last argument
    if current.strip():
        arg = current.strip()
        if arg.startswith('"') and arg.endswith('"'):
            arg = arg[1:-1]
        args.append(arg)

    return args


def normalize_flag(arg: str) -> str:
    """Normalize MSVC flags for clangd compatibility.

    Handles:
    - /Ipath and /I"path" -> -I with clean path
    - /Dname -> -D name
    - /external:I -> -isystem
    - Removes embedded quotes from paths
    """
    # Handle /I"path" or /Ipath (include directories)
    if arg.startswith("/I") or arg.startswith("-I"):
        path = arg[2:]
        # Remove surrounding quotes
        if path.startswith('"') and path.endswith('"'):
            path = path[1:-1]
        # Normalize to forward slashes
        path = path.replace("\\", "/")
        return f"-I{path}"

    # Handle /external:I "path" (system includes) - just the flag part
    if arg == "/external:I":
        return "-isystem"

    # Handle /D defines
    if arg.startswith("/D"):
        define = arg[2:]
        if define.startswith('"') and define.endswith('"'):
            define = define[1:-1]
        return f"-D{define}"

    # Pass through other flags, normalizing quotes
    if arg.startswith('"') and arg.endswith('"'):
        return arg[1:-1]

    return arg


def is_source_file(arg: str) -> bool:
    """Check if an argument looks like a C/C++ source file."""
    lower = arg.lower()
    return any(
        lower.endswith(ext) for ext in [".cpp", ".cc", ".cxx", ".c", ".c++"]
    )


def extract_compile_commands(
    trace: dict[str, Any], build_dir: str | None = None
) -> list[dict]:
    """Extract compile commands from a process trace."""
    compile_commands = []
    seen_files: set[str] = set()  # Avoid duplicates

    for proc in trace.get("processes", []):
        name = (proc.get("name") or "").lower()

        # Only process cl.exe invocations
        if name != "cl.exe":
            continue

        response_files = proc.get("response_files", {})
        if not response_files:
            continue

        # Process each response file
        for rsp_path, rsp_content in response_files.items():
            if not rsp_content:
                continue

            args = parse_msvc_args(rsp_content)
            if not args:
                continue

            # Separate flags from source files
            flags = []
            sources = []

            i = 0
            while i < len(args):
                arg = args[i]

                # Skip /c (compile only) - clangd infers this
                if arg == "/c":
                    i += 1
                    continue

                # Handle /Fo, /Fd, /Fe - output flags we can skip
                if (
                    arg.startswith("/Fo")
                    or arg.startswith("/Fd")
                    or arg.startswith("/Fe")
                ):
                    i += 1
                    continue

                # Skip errorReport and other MSVC-specific flags clangd doesn't understand
                if arg.startswith("/errorReport") or arg.startswith(
                    "/external:W"
                ):
                    i += 1
                    continue

                # Handle /external:I followed by path (next arg is the path)
                if arg == "/external:I":
                    if i + 1 < len(args):
                        path = args[i + 1].replace("\\", "/")
                        if path.startswith('"') and path.endswith('"'):
                            path = path[1:-1]
                        flags.append("-isystem")
                        flags.append(path)
                        i += 2
                        continue
                    i += 1
                    continue

                # Source files
                if is_source_file(arg):
                    # Normalize path
                    src = arg.replace("\\", "/")
                    sources.append(src)
                else:
                    # Normalize and keep as flag
                    normalized = normalize_flag(arg)
                    if normalized:  # Skip empty
                        flags.append(normalized)

                i += 1

            # Create an entry for each source file
            for src in sources:
                src_normalized = Path(src).as_posix()

                # Skip if we've already seen this file
                if src_normalized in seen_files:
                    continue
                seen_files.add(src_normalized)

                # Determine directory - use build dir or derive from source
                if build_dir:
                    directory = build_dir
                else:
                    # Try to find project root by looking for common patterns
                    src_path = Path(src)
                    # Walk up to find a reasonable root
                    directory = str(src_path.parent)
                    for parent in src_path.parents:
                        if (parent / "CMakeLists.txt").exists() or (
                            parent / "build"
                        ).exists():
                            directory = str(parent)
                            break

                compile_commands.append(
                    {
                        "directory": directory.replace("\\", "/"),
                        "arguments": ["cl.exe"] + flags + [src_normalized],
                        "file": src_normalized,
                    }
                )

    return compile_commands


def main():
    ap = argparse.ArgumentParser(
        description="Convert process trace JSON to compile_commands.json"
    )
    ap.add_argument(
        "trace_json", help="Input trace JSON file (from trace_cmake_build.py)"
    )
    ap.add_argument(
        "-o",
        "--output",
        default="compile_commands.json",
        help="Output compile_commands.json file",
    )
    ap.add_argument(
        "--build-dir",
        default=None,
        help="Build directory to use for all entries (auto-detected if not specified)",
    )
    ap.add_argument(
        "--merge",
        action="store_true",
        help="Merge with existing compile_commands.json instead of overwriting",
    )
    args = ap.parse_args()

    # Load trace
    with open(args.trace_json, "r", encoding="utf-8") as f:
        trace = json.load(f)

    # Extract compile commands
    commands = extract_compile_commands(trace, args.build_dir)

    if not commands:
        print(f"Warning: No cl.exe compile commands found in {args.trace_json}")
        return

    # Merge with existing if requested
    if args.merge and Path(args.output).exists():
        with open(args.output, "r", encoding="utf-8") as f:
            existing = json.load(f)

        # Index existing by file
        existing_files = {entry["file"]: entry for entry in existing}

        # Add/update with new commands
        for cmd in commands:
            existing_files[cmd["file"]] = cmd

        commands = list(existing_files.values())

    # Sort by file path for stable output
    commands.sort(key=lambda x: x["file"])

    # Write output
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(commands, f, indent=2)

    print(f"Wrote {len(commands)} compile commands to {args.output}")

    # Summary
    unique_dirs = set(cmd["directory"] for cmd in commands)
    print(f"  Directories: {len(unique_dirs)}")
    print(f"  Source files: {len(commands)}")


if __name__ == "__main__":
    main()
