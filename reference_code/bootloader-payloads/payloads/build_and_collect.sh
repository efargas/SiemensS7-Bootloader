#!/bin/bash
set -e

# Enhanced build script that collects all compiled payloads in one location
OUTPUT_DIR="compiled_output"

echo "Building all payloads and collecting outputs..."

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Build payloads with Makefiles
for D in dump_mem hello_loop tic_tac_toe; do
    echo "Building $D..."
    (cd "$D" && make)
    
    # Copy compiled outputs
    echo "Collecting $D outputs..."
    mkdir -p "$OUTPUT_DIR/$D"
    cp "$D/build/$D.bin" "$OUTPUT_DIR/$D/" 2>/dev/null || echo "Warning: $D.bin not found"
    cp "$D/build/$D.ihex" "$OUTPUT_DIR/$D/" 2>/dev/null || echo "Warning: $D.ihex not found"
    cp "$D/build/$D" "$OUTPUT_DIR/$D/" 2>/dev/null || echo "Warning: $D executable not found"
done

# Build payloads with build.sh
for D in hello_world stager; do
    echo "Building $D..."
    (cd "$D" && sh build.sh)
    
    # Copy compiled outputs
    echo "Collecting $D outputs..."
    mkdir -p "$OUTPUT_DIR/$D"
    cp "$D/$D.bin" "$OUTPUT_DIR/$D/" 2>/dev/null || echo "Warning: $D.bin not found"
done

echo "All payloads built and collected in $OUTPUT_DIR/"
echo "Contents:"
find "$OUTPUT_DIR" -type f | sort