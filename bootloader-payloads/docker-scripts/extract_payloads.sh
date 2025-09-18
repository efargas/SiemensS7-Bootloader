#!/bin/bash

# Alternative script using Docker volumes for payload extraction
# Usage: ./extract_payloads_volume.sh [output_directory]

set -e

# Default output directory
OUTPUT_DIR="${1:-../../src/Resources/payloads}"
IMAGE_NAME="siemens-s7-payloads-enhanced"

echo "=== SiemensS7-Bootloader Payload Extraction (Volume Method) ==="
echo "Output directory: $OUTPUT_DIR"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Build the Docker image
echo "Building Docker image..."
cd ../payloads
docker build -t "$IMAGE_NAME" .
cd ../docker-scripts

# Run container with volume mount to extract payloads
echo "Running container and extracting payloads via volume mount..."
# Convert relative path to absolute path for Docker volume mount
ABS_OUTPUT_DIR=$(realpath "$OUTPUT_DIR")
echo "Absolute output path: $ABS_OUTPUT_DIR"
docker run --rm -v "$ABS_OUTPUT_DIR:/host_output" "$IMAGE_NAME" \
    sh -c "cp -r /app/compiled_output/* /host_output/ && echo 'Payloads copied to host successfully!'"

# Create a summary file
echo "Creating payload summary..."
cat > "$OUTPUT_DIR/README.md" << EOF
# Compiled SiemensS7-Bootloader Payloads

This directory contains the compiled payloads extracted from the Docker build process.

## Payload Descriptions

### dump_mem/
- **dump_mem.bin**: Binary payload for memory dumping
- **dump_mem.ihex**: Intel HEX format
- **dump_mem**: ELF executable

### hello_loop/
- **hello_loop.bin**: Binary payload for hello loop demonstration
- **hello_loop.ihex**: Intel HEX format  
- **hello_loop**: ELF executable

### tic_tac_toe/
- **tic_tac_toe.bin**: Binary payload for tic-tac-toe game
- **tic_tac_toe.ihex**: Intel HEX format
- **tic_tac_toe**: ELF executable

### hello_world/
- **hello_world.bin**: Simple hello world binary payload

### stager/
- **stager.bin**: Stager payload binary

## Usage
These compiled payloads can be used with the SiemensS7-Bootloader for exploitation and testing purposes.

Generated on: $(date)
Extraction method: Docker volume mount
EOF

echo ""
echo "=== Extraction Complete ==="
echo "Compiled payloads extracted to: $OUTPUT_DIR"
echo "Summary file created: $OUTPUT_DIR/README.md"
echo ""
echo "Payload files:"
find "$OUTPUT_DIR" -name "*.bin" -o -name "*.ihex" -o -name "dump_mem" -o -name "hello_loop" -o -name "tic_tac_toe" | sort