#!/usr/bin/env python3
"""
Modbus TCP Server for testing purposes.

This script creates a simple Modbus TCP server that can be used for testing
Modbus communication with the Siemens S7 bootloader project.

Usage:
    python3 modbus_server.py

The server will listen on all interfaces (0.0.0.0) on port 1502.
"""

from pymodbus.datastore import ModbusServerContext, ModbusSequentialDataBlock, ModbusDeviceContext
from pymodbus.server import StartTcpServer

# Create data store with 100 registers for each type
store = ModbusDeviceContext(
    di=ModbusSequentialDataBlock(0, [0]*100),  # Discrete Inputs
    co=ModbusSequentialDataBlock(0, [0]*100),  # Coils
    hr=ModbusSequentialDataBlock(0, [0]*100),  # Holding Registers
    ir=ModbusSequentialDataBlock(0, [0]*100),  # Input Registers
)

# Create devices (slave IDs 0-255)
devices = {i: store for i in range(0, 256)}
context = ModbusServerContext(devices=devices, single=False)

print("Starting Modbus TCP Server on 0.0.0.0:1502")
print("Press Ctrl+C to stop the server")

try:
    StartTcpServer(context, address=("0.0.0.0", 1502))
except KeyboardInterrupt:
    print("\nServer stopped by user")