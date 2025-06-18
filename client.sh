# This script simply forwards all its arguments to client.py.
# Default values for power supply or PLC can be set here if desired,
# but client.py already has its own defaults.

# Example of setting a default power supply IP if not overridden:
# POWERSUPPLY_HOST_DEFAULT="192.168.0.100"
# PORT_DEFAULT="1238"

# Construct arguments, allowing overrides from command line
# ARGS_TO_PASS=""
# if [[ "$@" != *"--powersupply-host"* ]]; then
# ARGS_TO_PASS="$ARGS_TO_PASS --powersupply-host $POWERSUPPLY_HOST_DEFAULT"
# fi
# if [[ "$@" != *"--port"* ]]; then
# ARGS_TO_PASS="$ARGS_TO_PASS --port $PORT_DEFAULT"
# fi

echo "Executing client.py with arguments: $@"
python client.py "$@"
