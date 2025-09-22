# AGENTS.md

This file provides guidance for AI agents working with the Siemens S7 Bootloader Utility repository.

## Repository Overview

This repository contains a C# cross-platform utility for gaining non-invasive arbitrary code execution on Siemens S7 PLCs using an undocumented bootloader protocol over UART. It's a C# rewrite and enhancement of the original Python-based tool targeting the vulnerability SSA-686531 (CVE-2019-13945).

**Repository URL**: https://github.com/efargas/SiemensS7-Bootloader.git

## Project Structure

```
SiemensS7-Bootloader/
├── src/                           # Main C# application source code
│   ├── S7_Csharp_Utility/        # Main GUI application (Avalonia UI)
│   ├── S7_Csharp_Core/           # Core libraries
│   │   ├── S7.Net/               # PLC communication protocol
│   │   └── S7.Utils/             # Utility functions
│   └── Resources/                # Application resources and payloads
├── bootloader-payloads/          # ARM payload source code and build system
│   ├── payloads/                 # ARM payload implementations
│   │   ├── dump_mem/             # Memory dumping payload
│   │   ├── hello_loop/           # Demo loop payload
│   │   ├── hello_world/          # Basic test payload
│   │   ├── stager/               # Initial staging payload
│   │   ├── tic_tac_toe/          # Interactive game payload
│   │   └── lib/                  # Shared ARM libraries
│   └── docker-scripts/           # Docker build automation
├── Legacy/                       # Original Python implementation
├── pics/                         # Documentation images
└── README.md                     # Main documentation
```

## Technology Stack

### Main Application
- **Framework**: .NET 8 with Avalonia UI (cross-platform GUI)
- **Language**: C# with nullable reference types enabled
- **Architecture**: MVVM pattern with ViewModels and Services
- **Dependencies**:
  - Avalonia 11.3.2 (UI framework)
  - NModbus 3.0.81 (Modbus communication)
  - DiffPlex 1.9.0 (File comparison)
  - System.IO.Ports 9.0.9 (Serial communication)

### ARM Payloads
- **Language**: C and ARM Assembly
- **Toolchain**: ARM GCC (gcc-arm-none-eabi)
- **Build System**: Docker-based with Make
- **Target**: ARM Cortex-R4 (ARMv7-R architecture)

## Key Components

### Core Functionality
1. **PLC Communication** (`S7.Net`): Implements the undocumented bootloader protocol
2. **Power Management**: Modbus/TCP controlled power cycling
3. **Memory Operations**: Arbitrary memory read/write capabilities
4. **Payload Management**: ARM payload compilation and deployment
5. **File Analysis**: Hex viewer and binary comparison tools

### GUI Application Features
- **Connection Management**: Serial-to-TCP proxy configuration
- **Profile Management**: Device memory layout profiles
- **Memory Dumping**: Interactive memory extraction with progress tracking
- **File Comparison**: Binary diff and hash-based duplicate detection
- **Hex Viewer**: Binary file analysis with data inspector

## Development Guidelines

### Code Style
- Follow C# naming conventions (PascalCase for public members, camelCase for private)
- Use nullable reference types (`#nullable enable`)
- Implement proper async/await patterns for I/O operations
- Use MVVM pattern for UI components

### Architecture Patterns
- **Services**: Dependency injection for cross-cutting concerns
- **Commands**: RelayCommand/AsyncRelayCommand for UI actions
- **ViewModels**: Business logic and data binding
- **Models**: Data structures and configuration

### Error Handling
- Use structured exception handling with user-friendly messages
- Log errors to the integrated logging system
- Provide meaningful feedback for network and hardware failures

## Common Tasks

### Building the Application
```bash
# Build the main application
dotnet build src/S7_Csharp_Utility/S7_Csharp_Utility.csproj --configuration Release

# Build ARM payloads (requires Docker)
cd bootloader-payloads/docker-scripts
./extract_payloads.sh
```

### Adding New Payloads
1. Create payload directory in `bootloader-payloads/payloads/`
2. Implement ARM code with proper memory layout
3. Add Makefile or build script
4. Update Docker build process if needed

### Extending GUI Features
1. Create ViewModel in `S7_Csharp_Utility/ViewModels/`
2. Implement corresponding View in `Views/`
3. Add services in `Services/` for business logic
4. Update MainWindow bindings as needed

## Security Considerations

### Responsible Disclosure
This tool is for authorized security research and testing only. The vulnerability (CVE-2019-13945) has been disclosed to Siemens and affects:
- Siemens S7-1200 (all variants including SIPLUS)
- Siemens S7-200 Smart

### Usage Guidelines
- Only use on systems you own or have explicit permission to test
- Follow responsible disclosure practices for any new vulnerabilities
- Respect industrial control system safety requirements
- Document and report any safety-critical findings appropriately

## Hardware Requirements

### Target Devices
- Siemens S7-1200 CPU 1212C DC/DC/DC (6ES7 212-1AE40-0XB0)
- ARM Cortex-R4 based SoC (Renesas 811005)
- UART interface access required

### Test Setup
- TTL 3.3V serial adapter
- Modbus/TCP controlled power supply
- Serial-to-TCP proxy (socat recommended)

## Troubleshooting

### Common Issues
1. **Browse buttons disabled**: Check DialogService implementation and command bindings
2. **Hex viewer not loading**: Verify file paths and DataContext bindings
3. **Serial connection failures**: Confirm socat proxy and port configuration
4. **Power cycling issues**: Validate Modbus/TCP settings and network connectivity

### Debug Features
- Integrated logging system with multiple categories
- Real-time progress tracking for memory operations
- Detailed error messages with stack traces
- Debug output for protocol communication

## Testing

### Unit Testing
- Focus on core protocol implementation
- Test payload management and file operations
- Validate configuration serialization/deserialization

### Integration Testing
- Test with actual hardware when available
- Validate serial communication protocols
- Verify power management integration

### UI Testing
- Test all browse dialogs and file operations
- Validate data binding and command execution
- Ensure proper error handling and user feedback

## Contributing

### Code Contributions
1. Follow existing code style and patterns
2. Add appropriate error handling and logging
3. Update documentation for new features
4. Test with both Windows and Linux platforms

### Documentation
- Update README.md for user-facing changes
- Add inline code documentation for complex logic
- Include examples for new API features

### Security Research
- Follow responsible disclosure practices
- Document findings thoroughly
- Consider safety implications for industrial systems

## Resources

### Documentation
- [Main README](README.md): User guide and setup instructions
- [Payload README](bootloader-payloads/README.md): ARM payload development
- [.NET 8 Documentation](https://docs.microsoft.com/en-us/dotnet/)
- [Avalonia UI Documentation](https://docs.avaloniaui.net/)

### Research Papers
- Black Hat Europe 2019: "Doors of Durin: The Veiled Gate to Siemens S7 Silicon"
- 36C3 2019: "A Deep Dive Into Unconstrained Code Execution on Siemens S7 PLCs"
- S4 2020: "Special Access Features on PLC's"

### External Dependencies
- [socat](http://www.dest-unreach.org/socat/): Serial-to-TCP proxy
- [ARM GCC Toolchain](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm): ARM cross-compilation
- [Docker](https://www.docker.com/): Payload build environment

---

*This file follows the [agents.md](https://agents.md/) specification for AI agent guidance.*