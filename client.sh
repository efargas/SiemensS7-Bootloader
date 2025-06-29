#!/bin/bash

# Default values for Modbus
DEFAULT_MODBUS_IP=192.168.1.18
DEFAULT_MODBUS_PORT=502
DEFAULT_MODBUS_OUTPUT=0
DEFAULT_PORT=1238

# Allow override from args
MODBUS_IP="$DEFAULT_MODBUS_IP"
MODBUS_PORT="$DEFAULT_MODBUS_PORT"
MODBUS_OUTPUT="$DEFAULT_MODBUS_OUTPUT"

for arg in "$@"; do
    case $arg in
        --modbus-ip=*) MODBUS_IP="${arg#*=}" ;;
        --modbus-port=*) MODBUS_PORT="${arg#*=}" ;;
        --modbus-output=*) MODBUS_OUTPUT="${arg#*=}" ;;
    esac
done

echo "[client.sh] Using MODBUS method (ip=$MODBUS_IP, port=$MODBUS_PORT, output=$MODBUS_OUTPUT)"
python client.py --modbus-ip="$MODBUS_IP" --modbus-port="$MODBUS_PORT" --modbus-output="$MODBUS_OUTPUT" --port="$DEFAULT_PORT" "$@"
