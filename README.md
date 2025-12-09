# Trace CMake Build

A toolkit for tracing and visualizing CMake/MSBuild process trees on Windows. Captures detailed metrics about every process spawned during a build—CPU time, I/O, memory, command lines, and MSVC response files—then lets you explore the data in multiple formats.

## Features

- **Process tracing** — Monitor all processes spawned by a command with high-frequency polling
- **Rich metrics** — CPU time, I/O bytes, working set, private bytes, page faults
- **Response file capture** — Automatically reads MSVC `.rsp` files and MSBuild temp scripts
- **Multiple output formats:**
  - JSON process graph
  - Chrome Trace Event format (for `chrome://tracing` or [Perfetto](https://ui.perfetto.dev))
  - `compile_commands.json` for clangd/IDE integration
  - Interactive HTML flamegraph

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

### 1. Trace a build

```powershell
python trace_cmake_build.py --output build_trace.json -- cmake --build . --config Release
```

This runs your CMake build while capturing the entire process tree.

### 2. View in Chrome/Perfetto

Convert to Chrome Trace Event format:

```powershell
python trace_to_chromium.py build_trace.json -o build_trace_chrome.json
```

Open `build_trace_chrome.json` in:
- `chrome://tracing` (paste URL in Chrome)
- https://ui.perfetto.dev (drag & drop)

### 3. Generate compile_commands.json

Extract compiler invocations for clangd/IDE support:

```powershell
python trace_to_compile_commands.py build_trace.json -o compile_commands.json
```

### 4. Interactive flamegraph

Open `flamegraph.html` in a browser, then either:
- Drag & drop your JSON file onto the page
- Enter the path to your JSON file and click Load

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

## Requirements

- **Windows** (uses Windows-specific APIs for process monitoring)
- **Python 3.10+** (uses modern type hints)
- **psutil**
- **pywin32**

## License

[Boost Software License 1.0](LICENSE)

