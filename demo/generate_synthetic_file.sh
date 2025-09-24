#!/bin/bash
# This script generates a 256 MB synthetic file for testing the Hex Viewer.
# A smaller size is chosen to keep the generation time reasonable.

echo "Generating 256 MB synthetic file (synthetic_large_file.bin)..."
dd if=/dev/urandom of=synthetic_large_file.bin bs=1M count=256
echo "Done."
