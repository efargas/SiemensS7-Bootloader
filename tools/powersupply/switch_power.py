#!/usr/bin/env python2

import argparse
import re
import sys

# Attempt to import requests for HTTP mode
try:
    from requests import Session
except ImportError:
    # This will allow the script to be parsed and show help for modbus even if requests is not installed,
    # but it will fail at runtime if http mode is selected.
    Session = None

# Attempt to import pymodbus for Modbus mode
try:
    from pymodbus.client.sync import ModbusTcpClient
except ImportError:
    # Allow script to be parsed and show help for http even if pymodbus is not installed.
    ModbusTcpClient = None

def control_http_power(host, port, mode):
    if not Session:
        print "Error: 'requests' library is not installed, but required for HTTP power control."
        sys.exit(1)

    http_host_url = "http://{}:{:d}".format(host, port)
    toggle = 1 if mode == "on" else 0

    s = Session()
    try:
        r = s.get(http_host_url, timeout=5)
        r.raise_for_status()
        regex = re.compile('<meta name="X-Request-Token" content="([a-f0-9]+)">')
        match = regex.findall(r.text)
        if not match:
            print "Error: Could not find X-Request-Token on HTTP power supply page."
            sys.exit(1)
        request_token = match[0]

        headers = {
            "X-Request-Token": request_token
        }

        r_post = s.post(http_host_url + "/ajax/rw_actor.php", data={"rw": 1, "actor_nr": 1, "on_off": toggle, "ts": 1536062812}, headers=headers, timeout=5)
        r_post.raise_for_status()
        print "HTTP Power supply {} command sent successfully to {}.".format(mode.upper(), http_host_url)
    except Exception as e:
        print "Error controlling HTTP power supply {}: {}".format(http_host_url, e)
        sys.exit(1)

def control_mitsubishi_modbus_power(modbus_host, modbus_port, modbus_coil, mode):
    if not ModbusTcpClient:
        print "Error: 'pymodbus' library is not installed, but required for Mitsubishi Modbus power control."
        sys.exit(1)

    client = ModbusTcpClient(modbus_host, port=modbus_port)
    try:
        print "Connecting to Mitsubishi PLC at {}:{}...".format(modbus_host, modbus_port)
        if not client.connect():
            print "Error: Could not connect to Mitsubishi PLC."
            sys.exit(1)

        action_value = True if mode == "on" else False
        print "Sending command to coil {} to turn {}...".format(modbus_coil, mode)
        result = client.write_coil(modbus_coil, action_value)

        if result.isError():
            print "Error: Modbus error when writing to coil: {}".format(result)
            sys.exit(1)
        else:
            print "Successfully turned {} coil {} on Mitsubishi PLC.".format(mode, modbus_coil)

    except Exception as e:
        print "Error controlling Mitsubishi Modbus power: {}".format(e)
        sys.exit(1)
    finally:
        if client:
            client.close()

def main():
    parser = argparse.ArgumentParser(description='Switch power on a remote power supply.')
    parser.add_argument('mode', choices=['on', 'off'], help="The power state to set ('on' or 'off').")

    parser.add_argument('--ps-type', dest='ps_type', choices=['http', 'mitsubishi_modbus'], default='http',
                        help='Type of power supply to control (default: http).')

    # HTTP arguments
    http_group = parser.add_argument_group('HTTP Power Supply (default type)')
    http_group.add_argument('--host', dest='http_host', default="powersupply",
                        help='Hostname or IP for the HTTP power supply (default: powersupply).')
    http_group.add_argument('--port', dest='http_port', default=80, type=int,
                        help='Port for the HTTP power supply (default: 80).')

    # Mitsubishi Modbus arguments
    modbus_group = parser.add_argument_group('Mitsubishi Modbus TCP Power Supply')
    modbus_group.add_argument('--modbus-host', dest='modbus_host',
                        help='Hostname or IP for the Mitsubishi PLC Modbus TCP server.')
    modbus_group.add_argument('--modbus-port', dest='modbus_port', default=502, type=int,
                        help='Port for the Mitsubishi PLC Modbus TCP server (default: 502).')
    modbus_group.add_argument('--modbus-coil', dest='modbus_coil', default=0, type=int,
                        help='Modbus coil address (0-indexed) to control (e.g., 0 for Y0, default: 0).')

    args = parser.parse_args()

    if args.ps_type == 'http':
        if not args.http_host:
            parser.error("Argument --host is required for ps-type 'http'")
        control_http_power(args.http_host, args.http_port, args.mode)
    elif args.ps_type == 'mitsubishi_modbus':
        if not args.modbus_host:
            parser.error("Argument --modbus-host is required for ps-type 'mitsubishi_modbus'")
        control_mitsubishi_modbus_power(args.modbus_host, args.modbus_port, args.modbus_coil, args.mode)
    else:
        # Should not happen due to choices in argparse
        print "Error: Unknown power supply type."
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()