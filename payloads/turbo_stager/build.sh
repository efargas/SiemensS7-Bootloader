#!/bin/sh
# Build script for turbo_stager, consistent with the original stager build process.
# This creates a position-independent binary.

set -e

CROSS_COMPILE=arm-none-eabi-

# Assemble and create an ELF file. The -EB flag ensures Big Endian output.
${CROSS_COMPILE}as -o turbo_stager.elf turbo_stager.s

# Extract the raw binary from the .text section.
${CROSS_COMPILE}objcopy -O binary -j .text turbo_stager.elf turbo_stager.bin

# Clean up intermediate files.
rm turbo_stager.elf
