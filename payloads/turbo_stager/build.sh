#!/bin/sh
# Build script for turbo_stager

set -e

# Define toolchain prefix
CROSS_COMPILE=arm-none-eabi-

# Assemble
${CROSS_COMPILE}as -o turbo_stager.o turbo_stager.s

# Link
${CROSS_COMPILE}ld -T linker_turbo.ld -o turbo_stager.elf turbo_stager.o

# Extract binary
${CROSS_COMPILE}objcopy -O binary turbo_stager.elf turbo_stager.bin

# Clean up intermediate files
rm turbo_stager.o turbo_stager.elf
