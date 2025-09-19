# Legacy Tools

This directory contains various utility tools used for testing and development with the Siemens S7 Bootloader project.

## Available Tools

### modbus_server.py
A simple Modbus TCP server for testing Modbus communication.

**Usage:**
```bash
python3 modbus_server.py
```

The server listens on all interfaces (0.0.0.0) on port 1502 and provides:
- 100 discrete inputs
- 100 coils  
- 100 holding registers
- 100 input registers

Supports slave IDs 0-255.

### powersupply/
Directory containing power supply control utilities:

- `switch_power.py` - Python script to control power supply
- `turn_off_and_on.sh` - Shell script for power cycling

## Dependencies

For `modbus_server.py`:
```bash
pip install pymodbus
```

## Notes

These are legacy tools that may require updates for compatibility with newer versions of their dependencies.