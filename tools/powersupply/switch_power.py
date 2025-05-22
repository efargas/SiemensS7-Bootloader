#!/usr/bin/env python2

from sys import argv, exit
import argparse
import re

# Import requests only if needed for web method
# Import serial only if needed for arduino method

parser = argparse.ArgumentParser(description='Switch power on the remote power supply')
parser.add_argument('-p', '--port', dest='port', default=80, type=lambda x: int(x, 0),
                        help='the port to use (may be changed away from 80 for local port forwarding for web method)')
parser.add_argument('-H', '--host', dest='host', default="powersupply",
                        help='the host to connect to (may be changed away from powersupply for local port forwarding for web method)')
parser.add_argument('mode', choices=['on', 'off'], help='Whether to turn the power on or off')
parser.add_argument('--method', dest='method', default='web', choices=['web', 'arduino'],
                        help='The method to use for switching power (web or arduino)')
parser.add_argument('--arduino-port', dest='arduino_port',
                        help='The serial port for the Arduino (e.g., /dev/ttyUSB0 or COM3). Required if method is arduino.')
parser.add_argument('--baud-rate', dest='baud_rate', default=9600, type=int,
                        help='The baud rate for serial communication. Default is 9600. Relevant only if method is arduino.')

args = parser.parse_args()

if args.method == 'web':
    from requests import Session # Import requests here
    host = "http://{}:{:d}".format(args.host, args.port)
    toggle = 1 if args.mode == "on" else 0

    try:
        s = Session()
        r = s.get(host, timeout=5) # Added timeout
        r.raise_for_status() # Check for HTTP errors
        regex = re.compile('<meta name="X-Request-Token" content="([a-f0-9]+)">')
        match = regex.search(r.text) # Use search instead of findall
        if not match:
            print "Error: Could not find X-Request-Token on the page."
            exit(1)
        request_token = match.group(1)

        headers = {
        	"X-Request-Token": request_token
        }

        r_post = s.post(host+"/ajax/rw_actor.php", data={"rw":1, "actor_nr": 1, "on_off":toggle,"ts":1536062812}, headers=headers, timeout=5) # Added timeout
        r_post.raise_for_status() # Check for HTTP errors
        print "Successfully sent {} command via web.".format(args.mode)
        exit(0)
    except Exception as e:
        print "Error during web request: {}".format(e)
        exit(1)

elif args.method == 'arduino':
    if not args.arduino_port:
        parser.error("--arduino-port is required when --method is arduino")
    
    try:
        import serial # Import serial here
    except ImportError:
        print "Error: pyserial library is not installed. Please install it (e.g., pip install pyserial)"
        exit(1)

    command_to_send = "ON\n" if args.mode == "on" else "OFF\n" # Add newline

    try:
        print "Attempting to connect to Arduino on port {} at {} baud...".format(args.arduino_port, args.baud_rate)
        # Ensure port is not None before attempting to open
        if args.arduino_port is None:
            print "Error: Arduino port not specified."
            exit(1)

        ser = serial.Serial(args.arduino_port, args.baud_rate, timeout=2) # Added timeout
        print "Connected to Arduino."
        ser.write(command_to_send.encode()) # Encode string to bytes
        print "Sent '{}' command to Arduino.".format(args.mode.upper())
        ser.close()
        exit(0)
    except serial.SerialException as e:
        print "Serial Error: {}. Check port and permissions.".format(e)
        exit(1)
    except Exception as e:
        print "An unexpected error occurred with Arduino communication: {}".format(e)
        exit(1)
else:
    # Should not happen due to choices in argparse
    print "Invalid method selected."
    exit(1)