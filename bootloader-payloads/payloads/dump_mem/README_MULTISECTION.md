# Multi-Section Memory Dump Payload

## Overview

This enhanced version of the dump_mem payload supports dumping multiple memory sections sequentially with client acknowledgment between each section. This allows the client application to save each section to disk before the payload proceeds to dump the next section.

## Features

- **Multi-section support**: Dump up to 16 memory sections in a single payload execution
- **Client acknowledgment**: Wait for client confirmation before proceeding to next section
- **Backward compatibility**: Supports legacy single-section mode
- **Error handling**: Validates section parameters and handles protocol errors
- **Section notifications**: Clear protocol messages for section start/end

## Protocol Specification

### Multi-Section Mode

#### Request Format (Client → Payload)

The payload receives data through the `read_buf` parameter with the following structure:

```
Offset  Size  Description
------  ----  -----------
0-3     4     Reserved/unused
4-7     4     Magic value (0xDEADBEEF) to indicate multi-section mode
8-11    4     Number of sections (uint32, 1-16)

For each section (up to 16):
12+i*8  4     Section address (uint32 pointer)
16+i*8  4     Section length (uint32, max 1MB per section)
```

#### Response Protocol (Payload → Client)

The payload sends the following sequence for each section:

1. **Initial Greeting** (on first start only)
   - Message: `"Ok\0"`

2. **For each section:**
   - **Section Start Notification**
     - Message: `"SECTION_START\0"`
   
   - **Memory Data**
     - Format: Chunked using `UART_protocol_send_many()`
     - Chunk size: 32 bytes
     - Final empty packet signals end of data
   
   - **Section Done Notification**
     - Message: `"SECTION_DONE\0"`
   
   - **Wait for Client ACK** (except after last section)
     - Expected: Single byte `0x00` (ACK)
     - Alternative: Single byte `0xFF` (NAK) - aborts operation

3. **All Sections Complete**
   - Message: `"ALL_DONE\0"`

### Legacy Single-Section Mode

For backward compatibility, if the magic value (offset 4) is NOT `0xDEADBEEF`, the payload operates in legacy mode:

```
Offset  Size  Description
------  ----  -----------
0-3     4     Reserved/unused
4-7     4     Target memory address (pointer)
8-11    4     Number of bytes to dump
```

Response is the same as original dump_mem.c (no section notifications or ACK waiting).

## Building

### Using Docker (Recommended)

```bash
cd bootloader-payloads
./docker-scripts/docker-build-payloads.sh
```

### Manual Build

```bash
cd bootloader-payloads/payloads/dump_mem
make -f Makefile.multisection
```

The compiled payload will be at: `build/dump_mem_multisection.bin`

## Usage Example

### C# Client Code (Conceptual)

```csharp
// Define multiple sections to dump
var sections = new[] {
    new MemorySection { Address = 0x00010000, Length = 0x1000, Name = "Bootloader" },
    new MemorySection { Address = 0x00100000, Length = 0x4000, Name = "Firmware" },
    new MemorySection { Address = 0x10000000, Length = 0x2000, Name = "SRAM" }
};

// Prepare request buffer
var requestBuffer = new byte[12 + sections.Length * 8];
BitConverter.GetBytes(0xDEADBEEF).CopyTo(requestBuffer, 4);  // Magic
BitConverter.GetBytes(sections.Length).CopyTo(requestBuffer, 8);  // Count

for (int i = 0; i < sections.Length; i++) {
    BitConverter.GetBytes(sections[i].Address).CopyTo(requestBuffer, 12 + i * 8);
    BitConverter.GetBytes(sections[i].Length).CopyTo(requestBuffer, 16 + i * 8);
}

// Send to payload...
// For each section:
//   1. Receive SECTION_START notification
//   2. Receive memory data chunks
//   3. Receive SECTION_DONE notification
//   4. Save section to file
//   5. Send ACK (0x00) to proceed to next section
//
// Finally receive ALL_DONE notification
```

## Error Codes

The payload sets `write_buf[0]` to indicate status:

- `0x00`: Success
- `0xFF`: Invalid section count (0 or > 16)
- `0xFE`: Invalid section size (0 or > 1MB)
- `0xFD`: Client ACK timeout or NAK received

## Limitations

- Maximum 16 sections per dump operation
- Maximum 1MB per individual section
- ACK timeout depends on client implementation
- Total dump time limited by UART baud rate

## Testing

### Test Plan

1. **Single Section Test**
   - Use legacy mode (no magic value)
   - Verify backward compatibility

2. **Multi-Section Test**
   - Send 3-5 sections of varying sizes
   - Verify each section is dumped completely
   - Verify ACK waiting between sections

3. **Error Handling Test**
   - Test with 0 sections (should fail)
   - Test with > 16 sections (should fail)
   - Test with invalid section size (should fail)
   - Test NAK response (should abort)

4. **Large Dump Test**
   - Dump 16 sections totaling several MB
   - Verify all sections complete successfully

## Security Considerations

- This payload allows arbitrary memory reads from the PLC
- Use only on authorized systems for legitimate security research
- Memory addresses are not validated - invalid addresses may crash the PLC
- Consider limiting section sizes in production use

## References

- Original dump_mem.c implementation
- UART protocol documentation (print.c, read.c)
- Siemens S7 bootloader research paper

## License

Same as parent project (see main repository LICENSE file)
