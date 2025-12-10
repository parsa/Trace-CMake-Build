# Trace CMake Build

A cross-platform toolkit for tracing and visualizing process trees. Captures detailed metrics about every process spawned during a command—CPU time, I/O, memory, command lines—then lets you explore the data in multiple formats.

Originally designed for CMake/MSBuild builds, but works with any command that spawns child processes.

## Features

- **Cross-platform** — Works on Windows, macOS, and Linux
- **Process tracing** — Monitor all processes spawned by a command with high-frequency polling
- **Rich metrics** — CPU time, I/O bytes, working set, private bytes (availability varies by platform)
- **Response file capture** — Automatically reads MSVC `.rsp` files and MSBuild temp scripts (Windows)
- **Multiple visualizations:**
  - Interactive HTML flamegraph (timeline view)
  - Process dependency graph (Sankey/Tree/Radial layouts)
  - Chrome Trace Event format (for `chrome://tracing` or [Perfetto](https://ui.perfetto.dev))
  - `compile_commands.json` for clangd/IDE integration

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

### 1. Trace a build

```
python trace_cmake_build.py --output build_trace.json -- cmake --build . --config Release
```

This runs your command while capturing the entire process tree.

### 2. Interactive flamegraph

Open `flamegraph.html` in a browser, then drag & drop your JSON trace file onto the page.

Features:
- Timeline view of all processes
- Color by process type, CPU time, or I/O activity
- Hover for quick stats, click for full details
- Save as self-contained HTML

### 3. Process dependency graph

Open `process_graph.html` in a browser, then drag & drop your JSON trace file.

Features:
- **Sankey Diagram** — Horizontal flow layout (default)
- **Tree Layout** — Hierarchical top-down view
- **Radial Layout** — Circular layout for compact viewing
- Pan, zoom, and click nodes to explore
- Highlights parent/child connections

### 4. View in Chrome/Perfetto

Convert to Chrome Trace Event format:

```
python trace_to_chromium.py build_trace.json -o build_trace_chrome.json
```

Open `build_trace_chrome.json` in:
- `chrome://tracing` (paste URL in Chrome)
- https://ui.perfetto.dev (drag & drop)

### 5. Generate compile_commands.json

Extract compiler invocations for clangd/IDE support:

```
python trace_to_compile_commands.py build_trace.json -o compile_commands.json
```

## Usage

### trace_cmake_build.py

```
python trace_cmake_build.py [OPTIONS] -- COMMAND [ARGS...]

Options:
  --output FILE           Output JSON file (default: processes.json)
  --poll-interval SECS    Polling interval in seconds (default: 0.01)
  --post-exit-timeout S   Max seconds to wait for children after root exits (default: 5.0)
  --label TEXT            Label for the root command in output
```

**Example:**

```powershell
# Trace CMake configuration
python trace_cmake_build.py --output cfg.json --label "cmake-configure" -- cmake -B build -G "Visual Studio 17 2022"

# Trace CMake build
python trace_cmake_build.py --output bld.json --label "cmake-build" -- cmake --build build --config Release
```

### trace_to_chromium.py

```
python trace_to_chromium.py INPUT_JSON [INPUT_JSON...] -o OUTPUT_JSON

Combine multiple traces:
  python trace_to_chromium.py cfg.json bld.json -o combined_trace.json
```

### trace_to_compile_commands.py

```
python trace_to_compile_commands.py TRACE_JSON -o compile_commands.json

Options:
  --build-dir DIR    Build directory for all entries (auto-detected if omitted)
  --merge            Merge with existing compile_commands.json instead of overwriting
```

### merge_traces.py

```
python merge_traces.py TRACE1.json TRACE2.json ... -o merged.json
```

Combines multiple trace files into one (e.g., separate configure and build traces).

### validate_trace.py

```
python validate_trace.py TRACE.json [-e REGEX[:COUNT]] ...

Options:
  -e, --expect REGEX[:COUNT]    Expect at least COUNT (default 1) processes matching REGEX
```

Validates trace structure and optionally checks for expected processes (case-insensitive regex):

```
python validate_trace.py trace.json -e cmake -e "cl|clang|gcc|cc":2
```

## Output Format

The trace JSON contains:

```json
{
  "processes": [
    {
      "pid": 1234,
      "ppid": 5678,
      "name": "cl.exe",
      "cmdline": ["cl.exe", "/c", "..."],
      "exe": "C:\\Program Files\\...\\cl.exe",
      "cwd": "C:\\project\\build",
      "start_time": "2024-01-15T10:30:00.000+00:00",
      "end_time": "2024-01-15T10:30:05.123+00:00",
      "duration_s": 5.123,
      "cpu_user_s": 4.5,
      "cpu_system_s": 0.3,
      "io_read_bytes": 10485760,
      "io_write_bytes": 524288,
      "working_set_bytes": 67108864,
      "peak_working_set_bytes": 134217728,
      "private_bytes": 52428800,
      "response_files": {
        "C:\\...\\tmp1234.rsp": "/I\"include\" /DNDEBUG ..."
      }
    }
  ],
  "edges": [
    {"parent": 5678, "child": 1234}
  ]
}
```

### Platform-specific fields

| Field | Windows | macOS | Linux |
|-------|---------|-------|-------|
| `cpu_user_s`, `cpu_system_s` | Yes | Yes | Yes |
| `working_set_bytes` (RSS) | Yes | Yes | Yes |
| `io_read_bytes`, `io_write_bytes` | Yes | No (needs root) | Yes |
| `peak_working_set_bytes` | Yes | No | No |
| `private_bytes` | Yes | No | Yes |
| `response_files` | Yes (MSVC) | No | No |

Unavailable fields are `null` in the JSON output (not `0`).

## Requirements

- **Python 3.10+** (uses modern type hints)
- **psutil** (cross-platform process monitoring)
- **pywin32** (optional, Windows-only, for PE file metadata)

## License

[Boost Software License 1.0](LICENSE)
