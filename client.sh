#!/bin/bash

# Example configuration for power supply
# Set USE_PS_TYPE to "http" or "mitsubishi_modbus"

USE_PS_TYPE="http" # or "mitsubishi_modbus"

# Common arguments for client.py
CLIENT_ARGS="" # Add other client.py general args here if needed

# Power switch arguments (conditionally added)
POWER_SWITCH_FLAG="--switch-power" # Uncomment to enable power switching
# POWER_SWITCH_FLAG="" # Uncomment to disable power switching

POWERSUPPLY_DELAY="--powersupply-delay=5" # Example delay

# --- HTTP Power Supply Configuration ---
PS_HTTP_ARGS=""
if [ "$USE_PS_TYPE" == "http" ]; then
    PS_HTTP_ARGS="--ps-type http \
--powersupply-host 192.168.0.100 \
--powersupply-port 80"
    # Note: The original client.sh used port 1238.
    # The default for the HTTP device is typically 80.
    # Adjust --powersupply-port as needed for your HTTP device.
fi

# --- Mitsubishi Modbus TCP Power Supply Configuration ---
PS_MODBUS_ARGS=""
if [ "$USE_PS_TYPE" == "mitsubishi_modbus" ]; then
    PS_MODBUS_ARGS="--ps-type mitsubishi_modbus \
--ps-modbus-host 192.168.1.10 \
--ps-modbus-port 502 \
--ps-modbus-coil 0"
fi

# Combine arguments
ALL_ARGS="$CLIENT_ARGS"
if [ -n "$POWER_SWITCH_FLAG" ]; then
  ALL_ARGS="$ALL_ARGS $POWER_SWITCH_FLAG $POWERSUPPLY_DELAY"
  if [ "$USE_PS_TYPE" == "http" ]; then
      ALL_ARGS="$ALL_ARGS $PS_HTTP_ARGS"
  elif [ "$USE_PS_TYPE" == "mitsubishi_modbus" ]; then
      ALL_ARGS="$ALL_ARGS $PS_MODBUS_ARGS"
  fi
fi

echo "Executing client.py with power supply type: $USE_PS_TYPE (if --switch-power is enabled)"
echo "Full arguments for client.py: $ALL_ARGS $@"
echo "---"

# It's generally safer to pass "$@" at the end to correctly handle spaces in user arguments
# However, to avoid issues if ALL_ARGS is empty and "$@" starts with a dash,
# we can conditionally add it or ensure client.py handles it well.
# For simplicity here, assuming client.py's argparse handles further arguments from "$@" correctly.

if [ -z "$ALL_ARGS" ]; then
    python client.py "$@"
else
    # The subshell $(echo $ALL_ARGS) is used to force word splitting if ALL_ARGS contains multiple options
    python client.py $(echo $ALL_ARGS) "$@"
fi
