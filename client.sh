# Default values for both methods
DEFAULT_MODBUS_IP=192.168.1.18
DEFAULT_MODBUS_PORT=502
DEFAULT_MODBUS_OUTPUT=0
DEFAULT_POWERSUPPLY_HOST=powersupply
DEFAULT_POWERSUPPLY_PORT=80
DEFAULT_PORT=1238

# Default method is modbus
METHOD=modbus

# Parse method from arguments if provided
for arg in "$@"; do
    case $arg in
        --powersupply-method=allnet)
            METHOD=allnet
            ;;
        --powersupply-method=modbus)
            METHOD=modbus
            ;;
    esac
done

if [ "$METHOD" = "modbus" ]; then
    # Set modbus defaults, allow override from args
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
    python client.py --powersupply-method=modbus --modbus-ip="$MODBUS_IP" --modbus-port="$MODBUS_PORT" --modbus-output="$MODBUS_OUTPUT" --port="$DEFAULT_PORT" "$@"
else
    # Set allnet defaults, allow override from args
    POWERSUPPLY_HOST="$DEFAULT_POWERSUPPLY_HOST"
    POWERSUPPLY_PORT="$DEFAULT_POWERSUPPLY_PORT"
    for arg in "$@"; do
        case $arg in
            --powersupply-host=*) POWERSUPPLY_HOST="${arg#*=}" ;;
            --powersupply-port=*) POWERSUPPLY_PORT="${arg#*=}" ;;
        esac
    done
    echo "[client.sh] Using ALLNET method (host=$POWERSUPPLY_HOST, port=$POWERSUPPLY_PORT)"
    python client.py --powersupply-method=allnet --powersupply-host="$POWERSUPPLY_HOST" --powersupply-port="$POWERSUPPLY_PORT" --port="$DEFAULT_PORT" "$@"
fi
