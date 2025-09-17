# PLCSploit Usage Examples

This document provides examples of how to use the `PLCSploit` tool to run different payloads on the target PLC. Thanks to the new default configuration, the commands are simplified.

## Prerequisites

- The .NET 6.0 SDK must be installed.
- The `socat` utility must be running and forwarding the PLC's serial port to a local TCP port (e.g., 1238).
- The Modbus TCP power supply must be available at the default IP address `192.168.1.18`.

## Building the Payloads

The payloads can be built using the provided Dockerfile.

```sh
cd payloads
docker build -t plc-payload-builder .
```

This will create a Docker image with the compiled payloads. The `PLCSploit` tool expects the payloads to be in the `payloads` directory.

## Running PLCSploit

To run the tool, use the `dotnet run` command from the `PLCSploit` directory, followed by the desired action and its parameters. The `--` is used to separate the arguments for `dotnet run` from the arguments for the application.

### Test Payload

This payload sends a "TEST" string back to the client to confirm that code execution was successful.

```sh
cd PLCSploit
dotnet run -- -P 1238 test
```

### Hello Loop Payload

This payload sends the string "Gretings from PLC" in an infinite loop.

```sh
cd PLCSploit
dotnet run -- -P 1238 hello_loop
```

### Tic-Tac-Toe Payload

This payload runs an interactive game of Tic-Tac-Toe on the PLC.

```sh
cd PLCSploit
dotnet run -- -P 1238 tictactoe
```

### Dump Memory Payload

This payload dumps a specified region of the PLC's memory.

- `-a, --address`: The starting address to dump (e.g., `0x691E28`).
- `-l, --length`: The number of bytes to dump (e.g., `256`).

```sh
cd PLCSploit
dotnet run -- -P 1238 dump -a 0x691E28 -l 256
```
