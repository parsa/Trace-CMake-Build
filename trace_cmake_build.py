#!/usr/bin/env python
"""
Trace any command and emit a process graph JSON.

Works on Windows, macOS, and Linux (via psutil).

Usage:
  python trace_cmake_build.py --output trace.json -- cmake --build . --config Release
"""
import argparse
import datetime as dt
import json
import os
import sys
import time
import subprocess
from typing import Dict, Any, Set, Tuple, Optional

import psutil  # type: ignore

try:
    import win32api  # type: ignore
except ImportError:
    win32api = None  # optional; only for description/company


def iso(ts: float | None) -> str | None:
    return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).isoformat() if ts else None


def read_response_file(path: str) -> str | None:
    """Read an MSVC response file (@file.rsp) if it exists.
    
    MSVC writes .rsp files in UTF-16 LE with BOM, so we detect by BOM first.
    """
    try:
        # Read raw bytes to detect encoding
        with open(path, "rb") as f:
            raw = f.read()
        
        if not raw:
            return None
        
        # Check for BOM (Byte Order Mark)
        if raw.startswith(b'\xff\xfe'):
            # UTF-16 LE with BOM
            return raw.decode("utf-16-le", errors="replace").lstrip('\ufeff')
        elif raw.startswith(b'\xfe\xff'):
            # UTF-16 BE with BOM
            return raw.decode("utf-16-be", errors="replace").lstrip('\ufeff')
        elif raw.startswith(b'\xef\xbb\xbf'):
            # UTF-8 with BOM
            return raw[3:].decode("utf-8", errors="replace")
        else:
            # No BOM - check if it looks like UTF-16 (lots of null bytes)
            if b'\x00' in raw[:100]:
                # Likely UTF-16 LE without BOM
                return raw.decode("utf-16-le", errors="replace")
            else:
                # Assume UTF-8 / ASCII
                return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def extract_response_files(cmdline: list[str] | None) -> Dict[str, str]:
    """Extract and read any @response.rsp files or temp .cmd scripts from command line."""
    if not cmdline:
        return {}
    result = {}
    for arg in cmdline:
        # MSVC response files: @file.rsp
        if arg.startswith("@") and arg.endswith(".rsp"):
            rsp_path = arg[1:]  # Remove @ prefix
            content = read_response_file(rsp_path)
            if content:
                result[rsp_path] = content
        # MSBuild temp batch scripts: .../MSBuildTemp/tmp*.cmd
        elif "MSBuildTemp" in arg and arg.endswith(".cmd"):
            content = read_response_file(arg)
            if content:
                result[arg] = content
    return result


def get_file_strings(exe_path: str) -> Dict[str, str | None]:
    if not exe_path or not win32api:
        return {"description": None, "company": None}
    try:
        info = win32api.GetFileVersionInfo(exe_path, "\\")
        trans = info["VarFileInfo"]["Translation"][0]
        lang, codepage = trans

        def read_str(name: str) -> str | None:
            try:
                key = f"\\StringFileInfo\\{lang:04X}{codepage:04X}\\{name}"
                return win32api.GetFileVersionInfo(exe_path, key)
            except Exception:
                return None

        return {"description": read_str("FileDescription"), "company": read_str("CompanyName")}
    except Exception:
        return {"description": None, "company": None}


class ProcessTracer:
    def __init__(self, poll_interval: float = 0.01, post_exit_timeout: float = 5.0):
        self.poll_interval = poll_interval
        self.post_exit_timeout = post_exit_timeout  # max time to wait after root exits
        self.processes: Dict[int, Dict[str, Any]] = {}
        self.edges: Set[Tuple[int, int]] = set()
        self.trace_start: float = 0.0
        self.root_pid: int = 0

    def _is_descendant_of_root(self, pid: int) -> bool:
        """Walk up parent chain to check if pid is a descendant of root_pid."""
        try:
            proc = psutil.Process(pid)
            visited: Set[int] = set()
            while proc is not None:
                if proc.pid == self.root_pid:
                    return True
                if proc.pid in visited:
                    break  # cycle detected
                visited.add(proc.pid)
                try:
                    parent = proc.parent()
                    if parent is None:
                        break
                    proc = parent
                except psutil.NoSuchProcess:
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return False

    def _snapshot_process(self, proc: psutil.Process, force: bool = False) -> bool:
        """Snapshot a process. Returns True if it was added/updated."""
        pid = proc.pid
        try:
            pinfo = proc.as_dict(attrs=["ppid", "name", "cmdline", "create_time", "exe"])
            create_time = pinfo.get("create_time") or 0
            
            # Skip processes created before trace started (with 1s buffer for clock skew)
            if not force and create_time < self.trace_start - 1.0:
                return False
            
            # Skip if not a descendant of root (unless it IS root or force)
            if not force and pid != self.root_pid and not self._is_descendant_of_root(pid):
                return False

            cpu = proc.cpu_times()
            
            # memory_full_info may fail or have different fields on different OSes
            try:
                mem = proc.memory_full_info()
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                try:
                    mem = proc.memory_info()  # fallback to basic memory info
                except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                    mem = None
            
            # io_counters() may not be available on all platforms (e.g. macOS without root)
            try:
                io = proc.io_counters()
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError, AttributeError):
                io = None
            
            # Get cwd and environ (can fail on some processes)
            try:
                cwd = proc.cwd()
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                cwd = None
            
            try:
                environ = dict(proc.environ())
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                environ = None
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

        # Extract memory stats (fields vary by OS)
        if mem is not None:
            private_bytes = getattr(mem, "private", None)
            working_set_bytes = getattr(mem, "rss", None)
            peak_working_set_bytes = getattr(mem, "peak_wset", None)  # Windows-specific
            num_page_faults = getattr(mem, "num_page_faults", None)  # Windows-specific
            # Windows doesn't have peak_private directly; use peak_pagefile as approximation
            peak_private_bytes = getattr(mem, "peak_pagefile", None)  # Windows-specific
        else:
            private_bytes = working_set_bytes = peak_working_set_bytes = None
            num_page_faults = peak_private_bytes = None
        
        # Extract I/O stats (may not be available on all platforms)
        if io is not None:
            io_read_bytes = io.read_bytes
            io_write_bytes = io.write_bytes
        else:
            io_read_bytes = io_write_bytes = None

        if pid not in self.processes:
            meta = get_file_strings(pinfo.get("exe") or "")
            cmdline = pinfo.get("cmdline")
            # Capture response files (e.g., @file.rsp used by MSVC)
            response_files = extract_response_files(cmdline)
            self.processes[pid] = {
                "pid": pid,
                "ppid": pinfo.get("ppid"),
                "name": pinfo.get("name"),
                "cmdline": cmdline,
                "exe": pinfo.get("exe"),
                "cwd": cwd,
                "environ": environ,
                "description": meta["description"],
                "company": meta["company"],
                "start_time": create_time,
                "end_time": None,
                "cpu_user_s": cpu.user,
                "cpu_system_s": cpu.system,
                "io_read_bytes": io_read_bytes,
                "io_write_bytes": io_write_bytes,
                "private_bytes": private_bytes,
                "peak_private_bytes": peak_private_bytes,
                "working_set_bytes": working_set_bytes,
                "peak_working_set_bytes": peak_working_set_bytes,
                "num_page_faults": num_page_faults,
                "last_seen": time.time(),
                "response_files": response_files if response_files else None,
            }
            # Record edge
            ppid = pinfo.get("ppid")
            if ppid and ppid != pid:
                self.edges.add((ppid, pid))
        else:
            rec = self.processes[pid]
            if not rec.get("exe") and pinfo.get("exe"):
                rec["exe"] = pinfo.get("exe")
            if not rec.get("name") and pinfo.get("name"):
                rec["name"] = pinfo.get("name")
            if not rec.get("cwd") and cwd:
                rec["cwd"] = cwd
            if not rec.get("environ") and environ:
                rec["environ"] = environ
            rec["cpu_user_s"] = cpu.user
            rec["cpu_system_s"] = cpu.system
            if io_read_bytes is not None:
                rec["io_read_bytes"] = io_read_bytes
            if io_write_bytes is not None:
                rec["io_write_bytes"] = io_write_bytes
            if private_bytes is not None:
                rec["private_bytes"] = private_bytes
            if working_set_bytes is not None:
                rec["working_set_bytes"] = working_set_bytes
            # Update peak values (keep the max seen)
            if peak_private_bytes is not None:
                rec["peak_private_bytes"] = max(
                    peak_private_bytes, rec.get("peak_private_bytes") or 0
                )
            if peak_working_set_bytes is not None:
                rec["peak_working_set_bytes"] = max(
                    peak_working_set_bytes, rec.get("peak_working_set_bytes") or 0
                )
            if num_page_faults is not None:
                rec["num_page_faults"] = num_page_faults  # This is cumulative from OS
            rec["last_seen"] = time.time()
        return True

    def _mark_dead(self, pid: int):
        rec = self.processes.get(pid)
        if rec and rec.get("end_time") is None:
            rec["end_time"] = rec.get("last_seen", time.time())

    def _poll_all_descendants(self) -> Set[int]:
        """Poll all tracked processes and any new descendants. Returns set of alive PIDs."""
        alive_now: Set[int] = set()
        
        # First, scan process_iter for any processes that might be descendants
        for p in psutil.process_iter(attrs=["pid", "ppid", "create_time"]):
            try:
                pid = p.info["pid"]
                create_time = p.info.get("create_time") or 0
                
                # Quick filter: skip if created before trace started
                if create_time < self.trace_start - 1.0:
                    continue
                
                # If already tracked, update it
                if pid in self.processes:
                    if self._snapshot_process(p):
                        alive_now.add(pid)
                    continue
                
                # Check if it's the root or a descendant
                if pid == self.root_pid or self._is_descendant_of_root(pid):
                    if self._snapshot_process(p):
                        alive_now.add(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return alive_now

    def trace_command(self, cmd: list[str], label: str):
        print(f"[trace] starting {label}: {' '.join(cmd)}", flush=True)
        
        self.trace_start = time.time()
        proc = subprocess.Popen(cmd)
        self.root_pid = proc.pid
        
        # Initialize root process record
        try:
            root_ps = psutil.Process(self.root_pid)
            root_ppid = root_ps.ppid()
            self._snapshot_process(root_ps, force=True)
            self.processes[self.root_pid]["label"] = label
        except psutil.NoSuchProcess:
            root_ppid = None
            self.processes[self.root_pid] = {
                "pid": self.root_pid,
                "ppid": root_ppid,
                "name": os.path.basename(cmd[0]),
                "cmdline": cmd,
                "exe": None,
                "description": None,
                "company": None,
                "start_time": self.trace_start,
                "end_time": None,
                "cpu_user_s": 0.0,
                "cpu_system_s": 0.0,
                "io_read_bytes": 0,
                "io_write_bytes": 0,
                "private_bytes": None,
                "working_set_bytes": None,
                "last_seen": self.trace_start,
                "label": label,
            }

        root_exited_at: Optional[float] = None
        
        while True:
            alive_now = self._poll_all_descendants()
            
            # Mark dead any tracked process no longer alive
            for pid in list(self.processes.keys()):
                if pid not in alive_now and self.processes[pid].get("end_time") is None:
                    self._mark_dead(pid)

            # Check if root process has exited
            if proc.poll() is not None:
                if root_exited_at is None:
                    root_exited_at = time.time()
                    self._mark_dead(self.root_pid)
                
                # Check if all tracked processes are done
                all_done = all(
                    rec.get("end_time") is not None
                    for rec in self.processes.values()
                )
                
                if all_done:
                    break
                
                # Timeout: don't wait forever for orphaned processes
                if time.time() - root_exited_at > self.post_exit_timeout:
                    # Mark remaining as dead
                    for pid, rec in self.processes.items():
                        if rec.get("end_time") is None:
                            self._mark_dead(pid)
                    break
            
            time.sleep(self.poll_interval)

        print(f"[trace] finished {label} (exit {proc.returncode})", flush=True)
        if proc.returncode:
            raise SystemExit(proc.returncode)

    def to_json(self) -> Dict[str, Any]:
        out = []
        for rec in self.processes.values():
            start = rec.get("start_time")
            end = rec.get("end_time")
            entry = {
                **{k: rec.get(k) for k in ["pid", "ppid", "name", "cmdline", "exe", "cwd", "description", "company"]},
                "start_time": iso(start),
                "end_time": iso(end),
                "duration_s": (end - start) if start and end else None,
                "cpu_user_s": rec.get("cpu_user_s"),
                "cpu_system_s": rec.get("cpu_system_s"),
                "io_read_bytes": rec.get("io_read_bytes"),
                "io_write_bytes": rec.get("io_write_bytes"),
                "private_bytes": rec.get("private_bytes"),
                "peak_private_bytes": rec.get("peak_private_bytes"),
                "working_set_bytes": rec.get("working_set_bytes"),
                "peak_working_set_bytes": rec.get("peak_working_set_bytes"),
                "num_page_faults": rec.get("num_page_faults"),
                "label": rec.get("label"),
            }
            # Include response files if captured
            if rec.get("response_files"):
                entry["response_files"] = rec["response_files"]
            # Include environment if captured
            if rec.get("environ"):
                entry["environ"] = rec["environ"]
            out.append(entry)
        return {"processes": out, "edges": [{"parent": p, "child": c} for p, c in self.edges]}


def main():
    ap = argparse.ArgumentParser(description="Trace any command's process tree (cross-platform).")
    ap.add_argument("--output", default="processes.json", help="Output JSON file")
    ap.add_argument("--poll-interval", type=float, default=0.01, help="Polling interval seconds")
    ap.add_argument("--post-exit-timeout", type=float, default=5.0,
                    help="Max seconds to wait for children after root exits")
    ap.add_argument(
        "--label",
        default=None,
        help="Optional label for the root command in the output graph",
    )
    ap.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command to run; prefix with -- to stop option parsing",
    )
    args = ap.parse_args()

    cmd = args.command
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]

    if not cmd:
        print("No command provided. Example:", file=sys.stderr)
        print("  python tools/trace_cmake_build.py --output trace.json -- cmake --build . --config Release", file=sys.stderr)
        raise SystemExit(1)

    tracer = ProcessTracer(poll_interval=args.poll_interval, post_exit_timeout=args.post_exit_timeout)

    tracer.trace_command(cmd, label=args.label or "wrapped-command")

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(tracer.to_json(), f, indent=2)
    print(f"[trace] wrote {args.output}")


if __name__ == "__main__":
    main()
