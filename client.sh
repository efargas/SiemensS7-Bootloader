#!/bin/bash

# Default values for Modbus
DEFAULT_MODBUS_IP=192.168.1.18
DEFAULT_MODBUS_PORT=502
DEFAULT_MODBUS_OUTPUT=0 # Default output, user should specify if using --switch-power
DEFAULT_CLIENT_PORT=1238 # Default TCP port for client.py to connect to

# Initialize variables with defaults
MODBUS_IP="$DEFAULT_MODBUS_IP"
MODBUS_PORT="$DEFAULT_MODBUS_PORT"
MODBUS_OUTPUT_SPECIFIED=false # Flag to check if user provided --modbus-output
MODBUS_OUTPUT_VALUE=""        # Value for --modbus-output if specified
CLIENT_PORT="$DEFAULT_CLIENT_PORT"
SWITCH_POWER_SPECIFIED=false

# Array to hold arguments for client.py, excluding those processed by client.sh
CLIENT_PY_ARGS=()

# Parse arguments for client.sh to handle
# and pass the rest to client.py
while [[ $# -gt 0 ]]; do
    case "$1" in
        --modbus-ip=*)
            MODBUS_IP="${1#*=}"
            CLIENT_PY_ARGS+=("$1") # Pass to client.py as well
            shift
            ;;
        --modbus-port=*)
            MODBUS_PORT="${1#*=}"
            CLIENT_PY_ARGS+=("$1") # Pass to client.py
            shift
            ;;
        --modbus-output=*)
            MODBUS_OUTPUT_VALUE="${1#*=}"
            MODBUS_OUTPUT_SPECIFIED=true
            CLIENT_PY_ARGS+=("$1") # Pass to client.py
            shift
            ;;
        --port=*) # Port for client.py to connect to socat
            CLIENT_PORT="${1#*=}"
            # This arg is for client.py, so ensure it's passed if specified here
            # If not specified here, client.py will use its own default or require it
            # For client.py, this is -P or --port. We'll add it explicitly later.
            shift
            ;;
        --switch-power)
            SWITCH_POWER_SPECIFIED=true
            CLIENT_PY_ARGS+=("$1") # Pass to client.py
            shift
            ;;
        *)
            CLIENT_PY_ARGS+=("$1") # Pass unknown args to client.py
            shift
            ;;
    esac
done

# Add the determined port for client.py
# client.py expects --port or -P for its connection port.
# The $CLIENT_PORT variable holds what was parsed from client.sh's --port, or the default.
FINAL_CLIENT_PY_ARGS=("--port=$CLIENT_PORT")

# Add other processed arguments for client.py
# Modbus args are passed through CLIENT_PY_ARGS if they were given to client.sh
# If --switch-power was given, and --modbus-output was not, client.py will handle the error.

# Filter out --port from CLIENT_PY_ARGS if it was duplicated, as we add it explicitly
TEMP_ARGS=()
for arg in "${CLIENT_PY_ARGS[@]}"; do
    if [[ ! "$arg" == --port=* ]]; then
        TEMP_ARGS+=("$arg")
    fi
done
CLIENT_PY_ARGS=("${TEMP_ARGS[@]}")


echo "[client.sh] Forwarding to client.py with effective port: $CLIENT_PORT"
echo "[client.sh] Modbus settings (passed to client.py): IP=$MODBUS_IP, Port=$MODBUS_PORT, Output (if specified by user)=${MODBUS_OUTPUT_VALUE:-N/A}"

# Execute client.py with the processed and remaining arguments
# Ensure that arguments like --modbus-ip, --modbus-port, --modbus-output are passed if they were set by user
# and are present in CLIENT_PY_ARGS.
# The FINAL_CLIENT_PY_ARGS already contains the correct --port.
# The rest of CLIENT_PY_ARGS contains other flags and the action (dump, invoke, etc.)
set -x # print command
python3 client.py "${FINAL_CLIENT_PY_ARGS[@]}" "${CLIENT_PY_ARGS[@]}"
set +x
