#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from sys import argv
import argparse
import re

parser = argparse.ArgumentParser(description='Switch power on the remote power supply')
parser.add_argument('--method', dest='method', default='allnet', choices=['allnet', 'modbus'], help='Control method: allnet (default) or modbus (Modbus TCP)')

# ALLNET arguments
parser.add_argument('-p', '--port', dest='port', default=80, type=lambda x: int(x, 0), help='the port to use (may be changed away from 80 for local port forwarding)')
parser.add_argument('-H', '--host', dest='host', default="powersupply", help='the host to connect to (may be changed away from powersupply for local port forwarding)')

# Modbus TCP arguments (generic)
parser.add_argument('--modbus-ip', dest='modbus_ip', help='IP address of the Modbus TCP device. Required if method is modbus.')
parser.add_argument('--modbus-port', dest='modbus_port', default=502, type=int, help='Port for Modbus TCP communication (default: 502).')
parser.add_argument('--modbus-output', dest='modbus_output', type=int, help='Modbus coil address (integer) to control (e.g., 0, 1). Required if method is modbus.')

parser.add_argument('mode', choices=['on', 'off'])
args = parser.parse_args()

if args.method == 'allnet':
    from requests import Session
    host = "http://{}:{:d}".format(args.host, args.port)
    toggle = 1 if args.mode == "on" else 0
    s = Session()
    r = s.get(host)
    regex = re.compile('<meta name="X-Request-Token" content="([a-f0-9]+)">')
    match = regex.search(r.text)
    if not match:
        print("[!] Could not find X-Request-Token in response from {}".format(host))
        exit(1)
    request_token = match.group(1)
    headers = {"X-Request-Token": request_token}
    import time  # Added to generate current timestamp
    r = s.post(host+"/ajax/rw_actor.php", data={"rw":1, "actor_nr": 1, "on_off":toggle,"ts":int(time.time())}, headers=headers)
    exit(0)

elif args.method == 'modbus':
    if (args.modbus_ip is None) or (args.modbus_output is None):
        parser.error("--modbus-ip and --modbus-output are required when --method is modbus")
    try:
        from pymodbus.client.sync import ModbusTcpClient
    except ImportError:
        print("[!] pymodbus not installed. Please install with: pip install pymodbus==2.5.3")
        exit(1)
    toggle = True if args.mode == "on" else False
    client = ModbusTcpClient(args.modbus_ip, port=args.modbus_port)
    if not client.connect():
        print("[!] Could not connect to Modbus TCP device at {}:{}".format(args.modbus_ip, args.modbus_port))
        exit(2)
    rr = client.write_coil(args.modbus_output, toggle)
    if rr.isError():
        print("[!] Modbus write_coil failed: {}".format(rr))
        client.close()
        exit(3)
    client.close()
    print("[+] Modbus coil {} set to {} (Modbus TCP at {}:{})".format(args.modbus_output, toggle, args.modbus_ip, args.modbus_port))
    exit(0)

else:
    print("[!] Unknown method: {}".format(args.method))
    exit(1)