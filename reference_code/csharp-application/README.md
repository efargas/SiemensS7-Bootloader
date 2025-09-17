# SiemensS7-Bootloader C# Application

This directory contains the C# application components for the SiemensS7-Bootloader project.

## Projects

### PLCSploit.Core
Core library containing the main functionality:
- PLC client communication
- Power supply control
- Socat service management
- Logging utilities

### PLCSploit.Cli
Command-line interface for the bootloader:
- Console-based interaction
- Scripting support
- Batch operations

### PLCSploit.Gui
Graphical user interface built with Avalonia:
- Cross-platform GUI (Windows, Linux, macOS)
- Interactive exploitation interface
- Real-time monitoring
- Visual payload management

## Building

### Prerequisites
- .NET 6.0 or later
- Visual Studio 2022 or VS Code with C# extension

### Build Commands

```bash
# Build all projects
dotnet build SiemensS7-Bootloader.sln

# Build specific project
dotnet build PLCSploit.Cli/PLCSploit.Cli.csproj
dotnet build PLCSploit.Gui/PLCSploit.Gui.csproj

# Run CLI application
dotnet run --project PLCSploit.Cli

# Run GUI application
dotnet run --project PLCSploit.Gui
```

### Publishing

```bash
# Publish CLI for Linux x64
dotnet publish PLCSploit.Cli/PLCSploit.Cli.csproj -c Release -r linux-x64 --self-contained

# Publish GUI for Windows x64
dotnet publish PLCSploit.Gui/PLCSploit.Gui.csproj -c Release -r win-x64 --self-contained
```

## Usage

The C# application works in conjunction with the compiled payloads from the `../bootloader-payloads/` directory. Make sure to build and extract the payloads first before using the C# application.

## Architecture

```
PLCSploit.Core (Library)
├── PLCSploit.Cli (Console App)
└── PLCSploit.Gui (Avalonia GUI App)
```

The core library provides shared functionality that both the CLI and GUI applications can use.