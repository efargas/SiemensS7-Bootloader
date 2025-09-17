# SiemensS7-Bootloader Payloads

This directory contains the ARM payloads and Docker build system for the SiemensS7-Bootloader project.

## Directory Structure

```
bootloader-payloads/
├── payloads/                    # ARM payload source code
│   ├── dump_mem/               # Memory dumping payload
│   ├── hello_loop/             # Hello loop demonstration
│   ├── hello_world/            # Simple hello world payload
│   ├── stager/                 # Stager payload
│   ├── tic_tac_toe/           # Tic-tac-toe game payload
│   ├── lib/                   # Shared library code
│   ├── makeinc/               # Build configuration
│   ├── build_and_collect.sh   # Build and collect script
│   └── Dockerfile             # Docker build configuration
└── docker-scripts/            # Docker extraction scripts
    ├── extract_payloads.sh    # Extract payloads using volume mount
    ├── cleanup_docker.sh      # Clean up Docker resources
    └── DOCKER_CLEANUP_COMMANDS.md  # Manual cleanup guide
```

## Quick Start

### Build and Extract Payloads

```bash
cd docker-scripts
./extract_payloads.sh [output_directory]
```

### Clean Up Docker Resources

```bash
cd docker-scripts
./cleanup_docker.sh
```

## Payload Descriptions

- **dump_mem**: Memory dumping functionality for extracting firmware/memory contents
- **hello_loop**: Simple loop demonstration payload for testing
- **hello_world**: Basic "hello world" payload for verification
- **stager**: Staging payload for multi-stage exploitation
- **tic_tac_toe**: Interactive tic-tac-toe game payload

## Build Requirements

The Docker build process automatically installs:
- Ubuntu 18.04 base system
- ARM GCC toolchain (gcc-arm-none-eabi-7-2018-q2-update)
- Build tools (make, clang, etc.)

## Output Files

Each payload generates:
- `.bin` - Raw binary file for direct loading
- `.ihex` - Intel HEX format (for Makefile-based payloads)
- ELF executable (for Makefile-based payloads)

## Usage with SiemensS7-Bootloader

The compiled `.bin` files can be used with the main SiemensS7-Bootloader application for:
- Firmware exploitation
- Memory analysis
- Interactive payload execution
- Multi-stage attacks