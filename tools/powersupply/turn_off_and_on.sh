#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

# Store the sleep duration (first argument)
SLEEP_DURATION=$1
# Shift the arguments so that $@ now contains the rest of the arguments
shift

# Call switch_power.py with 'off' and the rest of the arguments
"$DIR/switch_power.py" off "$@"
# Sleep for the specified duration
sleep "$SLEEP_DURATION"
# Call switch_power.py with 'on' and the rest of the arguments
"$DIR/switch_power.py" on "$@"