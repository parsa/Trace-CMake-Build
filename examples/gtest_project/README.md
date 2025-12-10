# Google Test Example Project

A minimal CMake project that fetches and builds Google Test, used for testing the process tracer.

## Usage

```bash
# From the repository root
mkdir -p examples/gtest_project/build
cd examples/gtest_project/build

# Trace the configure step
python ../../../trace_cmake_build.py --output trace_configure.json --label "cmake-configure" -- cmake ..

# Trace the build step
python ../../../trace_cmake_build.py --output trace_build.json --label "cmake-build" -- cmake --build . --config Release

# Run the tests
ctest --output-on-failure -C Release
```

## Visualize

Open `flamegraph.html` or `process_graph.html` in a browser and drag-drop the trace JSON files to visualize the build process.

