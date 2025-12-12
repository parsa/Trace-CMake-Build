#!/usr/bin/env python
"""
Convert a process trace JSON (from trace_cmake_build.py) to compile_commands.json.

Understands MSVC (cl.exe/clang-cl) as well as common Unix-style drivers
(gcc/g++, clang/clang++, cc/c++, gfortran/flang/ifort, nvcc/nvfortran,
icx/icpx, MPI compiler wrappers, etc.) on Linux and macOS.

Usage:
    python tools/trace_to_compile_commands.py trace.json -o compile_commands.json
"""

import argparse
import json
import re
from pathlib import Path
from typing import Any, NamedTuple


WRAPPER_BINARIES = {
    "ccache",
    "sccache",
    "distcc",
    "icecc",
    "gomacc",
}

GNU_SKIP_WITH_VALUE = {"-o", "-MF", "-MT", "-MQ"}
GNU_COMPILE_FLAG_MARKERS = {"-c", "-S"}
SOURCE_EXTENSIONS = [
    ".c",
    ".cc",
    ".cp",
    ".cpp",
    ".cxx",
    ".c++",
    ".m",
    ".mm",
    ".ixx",
    ".mpp",
    ".cppm",
    ".cu",
    ".s",
    ".sx",
    ".asm",
    ".f",
    ".for",
    ".ftn",
    ".f77",
    ".f90",
    ".f95",
    ".f03",
    ".f08",
    ".f18",
    ".fpp",
]

GNU_LIKE_COMPILERS = {
    "gcc",
    "g++",
    "clang",
    "clang++",
    "cc",
    "c++",
    "nvcc",
    "icx",
    "icpx",
    "icc",
    "icpc",
    "emcc",
    "em++",
    "nvc",
    "nvc++",
    "pgcc",
    "pgc++",
    "hipcc",
    "dpcpp",
}

FORTRAN_COMPILERS = {
    "gfortran",
    "flang",
    "flang-new",
    "ifort",
    "ifx",
    "nvfortran",
    "pgfortran",
    "pgf90",
    "pgf95",
    "nagfor",
    "lfortran",
    "ftn",
}

HPC_DRIVER_COMPILERS = {
    "mpicc",
    "mpic++",
    "mpicxx",
    "mpiicc",
    "mpiicpc",
    "mpiicx",
    "mpiicpx",
    "mpif77",
    "mpif90",
    "mpif95",
    "mpifc",
    "mpifort",
    "mpiifort",
    "mpiifx",
}


class CompilerMatch(NamedTuple):
    kind: str  # "msvc" or "gnu"
    compiler: str
    args_start: int | None


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


_VERSION_SUFFIX_RE = re.compile(r"(-\d+(?:\.\d+)*)+$")


def _to_posix(path: str | Path | None) -> str:
    if path is None:
        return "."
    text = str(path)
    if not text:
        return "."
    return text.replace("\\", "/")


def normalize_executable_name(token: str) -> str:
    if not token:
        return ""
    token_str = str(token).strip('"')
    base = Path(token_str).name.lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base


def strip_version_suffix(name: str) -> str:
    without_suffix = _VERSION_SUFFIX_RE.sub("", name)
    return re.sub(r"(\d+)$", "", without_suffix)


def classify_compiler_name(name: str) -> str | None:
    base = strip_version_suffix(name)
    if base in {"cl", "clang-cl"} or base.endswith("clang-cl"):
        return "msvc"
    if (
        base in GNU_LIKE_COMPILERS
        or base in FORTRAN_COMPILERS
        or base in HPC_DRIVER_COMPILERS
    ):
        return "gnu"
    if base.endswith(
        (
            "gcc",
            "g++",
            "clang",
            "clang++",
            "cc",
            "c++",
            "fortran",
            "ftn",
            "ifort",
            "ifx",
        )
    ):
        return "gnu"
    return None


def detect_compiler(proc: dict[str, Any]) -> CompilerMatch | None:
    cmdline: list[str] = proc.get("cmdline") or []
    for idx, token in enumerate(cmdline):
        normalized = normalize_executable_name(token)
        if normalized in WRAPPER_BINARIES:
            continue
        kind = classify_compiler_name(normalized)
        if kind:
            return CompilerMatch(kind=kind, compiler=token, args_start=idx + 1)

    fallback = proc.get("name")
    if isinstance(fallback, str):
        norm = normalize_executable_name(fallback)
        kind = classify_compiler_name(norm)
        if kind:
            compiler_token = proc.get("exe") or fallback
            return CompilerMatch(kind=kind, compiler=compiler_token, args_start=None)
    return None


def normalize_msvc_flag(arg: str) -> str:
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
    return any(lower.endswith(ext) for ext in SOURCE_EXTENSIONS)


def gather_msvc_invocations(
    proc: dict[str, Any], match: CompilerMatch
) -> list[list[str]]:
    """Expand MSVC response files and cmdline arguments into argument lists."""
    response_files: dict[str, str] = proc.get("response_files") or {}
    cmdline: list[str] = proc.get("cmdline") or []
    invocations: list[list[str]] = []

    if match.args_start is not None and match.args_start <= len(cmdline):
        expanded: list[str] = []
        for token in cmdline[match.args_start:]:
            if isinstance(token, str) and token.startswith("@"):
                rsp_path = token[1:]
                rsp_content = response_files.get(rsp_path)
                if rsp_content:
                    expanded.extend(parse_msvc_args(rsp_content))
                else:
                    expanded.append(token)
            else:
                expanded.append(token)
        if expanded:
            invocations.append(expanded)

    if not invocations and response_files:
        for rsp_content in response_files.values():
            parsed = parse_msvc_args(rsp_content)
            if parsed:
                invocations.append(parsed)

    return invocations


def parse_msvc_arguments(args: list[str]) -> tuple[list[str], list[str]]:
    """Split MSVC-style arguments into flags and source files."""
    flags: list[str] = []
    sources: list[str] = []

    i = 0
    while i < len(args):
        arg = args[i]
        if not isinstance(arg, str):
            i += 1
            continue

        if arg.lower() == "/c":
            i += 1
            continue

        if arg.startswith("/Fo") or arg.startswith("/Fd") or arg.startswith("/Fe"):
            i += 1
            continue

        if arg.startswith("/errorReport") or arg.startswith("/external:W"):
            i += 1
            continue

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

        if is_source_file(arg):
            sources.append(arg.replace("\\", "/"))
        else:
            normalized = normalize_msvc_flag(arg)
            if normalized:
                flags.append(normalized)

        i += 1

    return flags, sources


def parse_gnu_like_arguments(args: list[str]) -> tuple[list[str], list[str]]:
    """Split GCC/Clang-style arguments into flags and source files."""
    flags: list[str] = []
    sources: list[str] = []
    has_compile_flag = False
    after_double_dash = False

    i = 0
    while i < len(args):
        arg = args[i]
        if not isinstance(arg, str):
            i += 1
            continue

        if arg == "--":
            flags.append(arg)
            after_double_dash = True
            i += 1
            continue

        if after_double_dash:
            sources.append(arg)
            i += 1
            continue

        if arg in GNU_COMPILE_FLAG_MARKERS or arg.startswith("-emit-"):
            has_compile_flag = True

        if is_source_file(arg):
            sources.append(arg)
            i += 1
            continue

        if arg in GNU_SKIP_WITH_VALUE:
            i += 2 if i + 1 < len(args) else 1
            continue

        skip_by_prefix = False
        for prefix in GNU_SKIP_WITH_VALUE:
            if arg.startswith(prefix) and len(arg) > len(prefix):
                skip_by_prefix = True
                break
        if skip_by_prefix:
            i += 1
            continue

        flags.append(arg)
        i += 1

    if not sources or not has_compile_flag:
        return [], []

    return flags, sources


def determine_directory(
    proc: dict[str, Any], src_path: Path, build_dir: str | None
) -> str:
    """Choose a working directory for a compile command entry."""
    if build_dir:
        return _to_posix(build_dir)

    cwd = proc.get("cwd")
    if isinstance(cwd, str) and cwd:
        return _to_posix(cwd)

    directory = _to_posix(src_path.parent)
    for parent in src_path.parents:
        if (parent / "CMakeLists.txt").exists() or (parent / "build").exists():
            directory = _to_posix(parent)
            break

    return directory


def extract_compile_commands(
    trace: dict[str, Any], build_dir: str | None = None
) -> list[dict]:
    """Extract compile commands from a process trace."""
    compile_commands = []
    seen_files: set[str] = set()  # Avoid duplicates

    for proc in trace.get("processes", []):
        if not isinstance(proc, dict):
            continue

        match = detect_compiler(proc)
        if not match:
            continue

        compiler_display = match.compiler or (
            "cl.exe" if match.kind == "msvc" else "cc"
        )
        compiler_token = _to_posix(compiler_display)

        if match.kind == "msvc":
            arg_lists = gather_msvc_invocations(proc, match)
            parser = parse_msvc_arguments
        else:
            cmdline: list[str] = proc.get("cmdline") or []
            if match.args_start is None or match.args_start > len(cmdline):
                continue
            invocation_args = cmdline[match.args_start :]
            if not invocation_args:
                continue
            arg_lists = [invocation_args]
            parser = parse_gnu_like_arguments

        for arg_list in arg_lists:
            if not arg_list:
                continue

            flags, sources = parser(arg_list)
            if not sources:
                continue

            for src in sources:
                src_normalized = Path(src).as_posix()
                if src_normalized in seen_files:
                    continue
                seen_files.add(src_normalized)

                directory = determine_directory(
                    proc, Path(src_normalized), build_dir
                )

                compile_commands.append(
                    {
                        "directory": directory,
                        "arguments": [compiler_token] + flags + [src_normalized],
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
        print(
            f"Warning: No supported compiler invocations found in {args.trace_json}"
        )
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
