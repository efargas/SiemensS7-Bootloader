#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from sys import argv, exit
import argparse
import re
import time

# Import requests and ModbusTcpClient conditionally to avoid errors if not used/installed
try:
    from requests import Session
except ImportError:
    Session = None

try:
    from pymodbus.client.sync import ModbusTcpClient
except ImportError:
    ModbusTcpClient = None

def power_control_allnet(host_ip, port, mode_on):
    """Controls power using the ALLNET method."""
    if Session is None:
        print("[!] 'requests' library not installed. Please install with: pip install requests")
        return False

    host_url = "http://{}:{:d}".format(host_ip, port)
    toggle = 1 if mode_on else 0
    s = Session()
    try:
        r = s.get(host_url, timeout=5)
        r.raise_for_status()
    except Exception as e:
        print("[!] Could not connect to ALLNET device at {}: {}".format(host_url, e))
        return False

    regex = re.compile('<meta name="X-Request-Token" content="([a-f0-9]+)">')
    match = regex.search(r.text)
    if not match:
        print("[!] Could not find X-Request-Token in response from {}".format(host_url))
        return False

    request_token = match.group(1)
    headers = {"X-Request-Token": request_token}

    try:
        r = s.post(host_url+"/ajax/rw_actor.php", data={"rw":1, "actor_nr": 1, "on_off":toggle,"ts":int(time.time())}, headers=headers, timeout=5)
        r.raise_for_status()
        print("[+] ALLNET: Successfully set power to {} on {}:{}".format("on" if mode_on else "off", host_ip, port))
        return True
    except Exception as e:
        print("[!] ALLNET: Failed to set power to {} on {}:{}: {}".format("on" if mode_on else "off", host_ip, port, e))
        return False

def power_control_modbus(ip, port, output_coil, mode_on):
    """Controls power using the Modbus TCP method."""
    if ModbusTcpClient is None:
        print("[!] 'pymodbus' library not installed. Please install with: pip install pymodbus==2.5.3")
        return False

    toggle = True if mode_on else False
    client = ModbusTcpClient(ip, port=port)
    if not client.connect():
        print("[!] Could not connect to Modbus TCP device at {}:{}".format(ip, port))
        return False

    rr = client.write_coil(output_coil, toggle)
    client.close() # Ensure client is closed whether write succeeds or fails

    if rr.isError():
        print("[!] Modbus write_coil failed for coil {} at {}:{}: {}".format(output_coil, ip, port, rr))
        return False

    print("[+] Modbus coil {} set to {} (Modbus TCP at {}:{})".format(output_coil, "on" if mode_on else "off", ip, port))
    return True

def main():
    parser = argparse.ArgumentParser(description='Switch power on the remote power supply')
    parser.add_argument('--method', dest='method', default='allnet', choices=['allnet', 'modbus'], help='Control method: allnet (default) or modbus (Modbus TCP)')

    # ALLNET arguments
    parser.add_argument('-p', '--port', dest='port', default=80, type=lambda x: int(x, 0), help='the port to use (may be changed away from 80 for local port forwarding)')
    parser.add_argument('-H', '--host', dest='host', default="powersupply", help='the host to connect to (may be changed away from powersupply for local port forwarding)')

    # Modbus TCP arguments (generic)
    parser.add_argument('--modbus-ip', dest='modbus_ip', help='IP address of the Modbus TCP device. Required if method is modbus.')
    parser.add_argument('--modbus-port', dest='modbus_port', default=502, type=int, help='Port for Modbus TCP communication (default: 502).')
    parser.add_argument('--modbus-output', dest='modbus_output', type=int, help='Modbus coil address (integer) to control (e.g., 0, 1). Required if method is modbus.')

    parser.add_argument('mode', choices=['on', 'off'], help="Power mode: 'on' or 'off'")
    args = parser.parse_args()

    success = False
    if args.method == 'allnet':
        success = power_control_allnet(args.host, args.port, args.mode == "on")
    elif args.method == 'modbus':
        if args.modbus_ip is None or args.modbus_output is None:
            parser.error("--modbus-ip and --modbus-output are required when --method is modbus")
        success = power_control_modbus(args.modbus_ip, args.modbus_port, args.modbus_output, args.mode == "on")
    else:
        print("[!] Unknown method: {}".format(args.method))
        exit(1)

    if success:
        exit(0)
    else:
        exit(1) # Generic error exit code for failure

if __name__ == '__main__':
    main()