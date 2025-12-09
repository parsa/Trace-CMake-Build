#!/usr/bin/env python
"""
Convert process trace JSON to Google Trace Event Format.

Output can be loaded in:
- chrome://tracing
- https://ui.perfetto.dev/

Usage:
  python tools/trace_to_chromium.py bld.json -o bld_trace.json
  python tools/trace_to_chromium.py cfg.json bld.json -o combined_trace.json
"""
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


def parse_iso(ts: str | None) -> float | None:
    """Parse ISO timestamp to Unix epoch seconds."""
    if not ts:
        return None
    try:
        # Handle various ISO formats
        ts = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts)
        return dt.timestamp()
    except Exception:
        return None


def to_trace_events(data: dict, label: str = "") -> list[dict[str, Any]]:
    """Convert process trace to Trace Event Format."""
    events: list[dict[str, Any]] = []
    
    processes = data.get("processes", [])
    if not processes:
        return events
    
    # Find the earliest start time to use as base
    min_ts = None
    for p in processes:
        ts = parse_iso(p.get("start_time"))
        if ts and (min_ts is None or ts < min_ts):
            min_ts = ts
    
    if min_ts is None:
        return events
    
    # Build PID to process name mapping for metadata
    pid_names: dict[int, str] = {}
    for p in processes:
        pid = p.get("pid")
        name = p.get("name") or "unknown"
        if pid:
            pid_names[pid] = name
    
    # Add process metadata events
    for pid, name in pid_names.items():
        events.append({
            "name": "process_name",
            "ph": "M",  # Metadata
            "pid": pid,
            "tid": 0,
            "args": {"name": f"{name} ({pid})"}
        })
    
    # Add thread name metadata (we use tid=0 for main, tid=1 for child info)
    for pid in pid_names:
        events.append({
            "name": "thread_name",
            "ph": "M",
            "pid": pid,
            "tid": 0,
            "args": {"name": "main"}
        })
    
    # Convert each process to a complete event
    for p in processes:
        pid = p.get("pid")
        ppid = p.get("ppid")
        name = p.get("name") or "unknown"
        
        start_ts = parse_iso(p.get("start_time"))
        end_ts = parse_iso(p.get("end_time"))
        
        if start_ts is None:
            continue
        
        # Calculate timestamps in microseconds relative to min_ts
        ts_us = (start_ts - min_ts) * 1_000_000
        
        # Duration in microseconds
        if end_ts:
            dur_us = (end_ts - start_ts) * 1_000_000
        else:
            dur_us = 0
        
        # Build args with all interesting data
        args: dict[str, Any] = {
            "pid": pid,
            "ppid": ppid,
        }
        
        # Add command line (truncated for display)
        cmdline = p.get("cmdline")
        if cmdline:
            cmd_str = " ".join(cmdline) if isinstance(cmdline, list) else str(cmdline)
            args["cmdline"] = cmd_str[:500] + ("..." if len(cmd_str) > 500 else "")
        
        # Add exe path
        if p.get("exe"):
            args["exe"] = p["exe"]
        
        # Add resource usage
        if p.get("cpu_user_s") is not None:
            args["cpu_user_s"] = round(p["cpu_user_s"], 3)
        if p.get("cpu_system_s") is not None:
            args["cpu_system_s"] = round(p["cpu_system_s"], 3)
        if p.get("io_read_bytes") is not None:
            args["io_read_MB"] = round(p["io_read_bytes"] / 1_048_576, 2)
        if p.get("io_write_bytes") is not None:
            args["io_write_MB"] = round(p["io_write_bytes"] / 1_048_576, 2)
        if p.get("working_set_bytes") is not None:
            args["working_set_MB"] = round(p["working_set_bytes"] / 1_048_576, 2)
        
        # Add response files content (if any)
        rsp = p.get("response_files")
        if rsp:
            # Summarize: extract source files from response
            for rsp_path, content in rsp.items():
                # Extract just the source files (end of .rsp content)
                if content:
                    # Find .cpp/.cc files
                    sources = [w for w in content.split() if w.endswith(('.cpp', '.cc', '.c'))]
                    if sources:
                        args["source_files"] = [Path(s).name for s in sources]
                    args["response_file"] = Path(rsp_path).name
        
        # Determine category based on process type
        name_lower = name.lower()
        if "cl.exe" in name_lower:
            cat = "compile"
        elif "link.exe" in name_lower or "lib.exe" in name_lower:
            cat = "link"
        elif "cmake" in name_lower:
            cat = "cmake"
        elif "msbuild" in name_lower:
            cat = "msbuild"
        elif "tracker" in name_lower:
            cat = "tracker"
        elif "cmd.exe" in name_lower:
            cat = "script"
        else:
            cat = "other"
        
        # Create display name
        display_name = name
        if args.get("source_files"):
            display_name = f"{name}: {', '.join(args['source_files'][:3])}"
            if len(args["source_files"]) > 3:
                display_name += f" +{len(args['source_files']) - 3} more"
        
        # Complete event (X) - shows duration
        events.append({
            "name": display_name,
            "cat": cat,
            "ph": "X",  # Complete event
            "ts": ts_us,
            "dur": dur_us,
            "pid": ppid if ppid else pid,  # Show under parent for hierarchy
            "tid": pid,  # Use PID as thread ID for unique lanes
            "args": args,
        })
        
        # Add counter events for CPU and I/O at end of process
        if end_ts and p.get("cpu_user_s"):
            cpu_total = (p.get("cpu_user_s") or 0) + (p.get("cpu_system_s") or 0)
            events.append({
                "name": "CPU Time",
                "cat": "resource",
                "ph": "C",  # Counter
                "ts": ts_us + dur_us,
                "pid": pid,
                "tid": 0,
                "args": {"seconds": round(cpu_total, 2)}
            })
    
    return events


def main():
    ap = argparse.ArgumentParser(
        description="Convert process trace JSON to Google Trace Event Format"
    )
    ap.add_argument(
        "inputs",
        nargs="+",
        help="Input JSON files from trace_cmake_build.py"
    )
    ap.add_argument(
        "-o", "--output",
        default="trace.json",
        help="Output trace file (default: trace.json)"
    )
    args = ap.parse_args()
    
    all_events: list[dict[str, Any]] = []
    
    for i, input_path in enumerate(args.inputs):
        try:
            with open(input_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"Error reading {input_path}: {e}", file=sys.stderr)
            continue
        
        label = Path(input_path).stem
        events = to_trace_events(data, label=label)
        all_events.extend(events)
        print(f"[trace] {input_path}: {len(events)} events")
    
    if not all_events:
        print("No events generated!", file=sys.stderr)
        raise SystemExit(1)
    
    # Output in Trace Event Format
    output = {
        "traceEvents": all_events,
        "displayTimeUnit": "ms",
        "metadata": {
            "source": "trace_cmake_build.py → trace_to_chromium.py"
        }
    }
    
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    
    print(f"[trace] wrote {args.output} ({len(all_events)} events)")
    print(f"[trace] Open in: chrome://tracing or https://ui.perfetto.dev/")


if __name__ == "__main__":
    main()

