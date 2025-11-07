# Multi-Section Memory Dump Implementation Summary

## Overview

This implementation adds support for dumping multiple memory sections sequentially with client acknowledgment between sections. The changes are focused on the **payload source code** that runs on the PLC.

## Problem Statement

The original requirement was to modify the memory dump payload to:
1. Accept an array of different memory sections to dump
2. Inform the client when each section is processed
3. Wait for client acknowledgment before proceeding to the next section
4. Allow the client to save each dump before the next begins

## Solution

### Payload Changes (ARM Code)

**New File**: `bootloader-payloads/payloads/dump_mem/dump_mem_multisection.c`

This enhanced payload provides:

#### 1. Multi-Section Protocol
- Receives an array of memory sections from the client
- Supports up to 16 sections per dump operation
- Each section specifies: address and length

#### 2. Section Processing Loop
```c
For each section:
  1. Send SECTION_START notification
  2. Dump memory data (chunked via UART)
  3. Send SECTION_DONE notification  
  4. Wait for client ACK (0x00 byte)
  5. Proceed to next section (or abort on NAK 0xFF)
```

#### 3. Backward Compatibility
- Legacy single-section mode still supported
- Detected via magic value (0xDEADBEEF = multi-section, otherwise = single)
- Existing clients continue to work unchanged

#### 4. Error Handling
- Validates section count (1-16)
- Validates section sizes (max 1MB each)
- Returns error codes for invalid configurations
- Aborts on client NAK or timeout

### Protocol Specification

#### Request Format (Client → Payload)
```
Offset  Size  Field
------  ----  -----
0-3     4     Reserved
4-7     4     Magic (0xDEADBEEF for multi-section)
8-11    4     Number of sections
12+i*8  4     Section[i] address
16+i*8  4     Section[i] length
```

#### Response Protocol (Payload → Client)
```
1. "Ok\0" - Initial greeting
2. For each section:
   - "SECTION_START\0"
   - <memory data in 32-byte chunks>
   - <empty chunk to signal end>
   - "SECTION_DONE\0"
   - <wait for ACK byte 0x00>
3. "ALL_DONE\0" - All sections complete
```

## Files Created

1. **dump_mem_multisection.c** (179 lines)
   - Multi-section memory dump payload source code
   - Implements section iteration and ACK waiting
   - Maintains backward compatibility

2. **Makefile.multisection**
   - Build configuration for the new payload
   - Uses existing ARM toolchain setup

3. **README_MULTISECTION.md**
   - Complete protocol documentation
   - Usage examples
   - Error codes and limitations
   - Testing guidelines

## C# Client Integration (Partially Complete)

### Completed
✅ Added `MemorySection` record to represent individual sections
✅ Updated `MemoryDumpCommand` to accept `MemorySection[]` array
✅ Updated `MemoryDumpOptions` with section array support
✅ Added validation for multi-section configurations
✅ Added `SectionDumpResult` for tracking per-section results

### TODO (Next Steps)
- [ ] Update `MemoryDumpCommandHandler` to construct multi-section request buffer
- [ ] Implement protocol message parsing (SECTION_START, SECTION_DONE, ALL_DONE)
- [ ] Implement ACK sending (0x00 byte) after each section save
- [ ] Update progress reporting to show current section
- [ ] Add UI support for defining multiple sections
- [ ] Add tests for multi-section protocol

## Building the Payload

### Using Docker (Recommended)
```bash
cd bootloader-payloads/docker-scripts
./extract_payloads.sh
```

### Manual Build
```bash
cd bootloader-payloads/payloads/dump_mem
make -f Makefile.multisection
```

Output: `build/dump_mem_multisection.bin`

## Usage Example

### Defining Sections in C# (Conceptual)
```csharp
var sections = new[] {
    new MemorySection { 
        Name = "Bootloader", 
        Address = 0x00000000, 
        Length = 0x10000 
    },
    new MemorySection { 
        Name = "Firmware", 
        Address = 0x00100000, 
        Length = 0x40000 
    },
    new MemorySection { 
        Name = "SRAM", 
        Address = 0x10000000, 
        Length = 0x8000 
    }
};

var options = new MemoryDumpOptions {
    MemorySections = sections,
    PayloadPath = "payloads/dump_mem_multisection.bin",
    OutputPath = "./dumps"
};
```

### Execution Flow
1. Client uploads multisection payload to PLC
2. Client constructs request buffer with magic + sections
3. Payload receives request and validates sections
4. **For each section:**
   - Payload sends SECTION_START
   - Client receives notification
   - Payload sends memory data
   - Client receives and buffers data
   - Payload sends SECTION_DONE
   - Client saves section to file
   - **Client sends ACK (0x00)**
   - Payload proceeds to next section
5. Payload sends ALL_DONE
6. Client completes operation

## Benefits

1. **Reduced Memory Usage**: Client doesn't need to buffer all sections
2. **Progressive Saving**: Each section saved immediately after dumping
3. **Error Recovery**: Can resume from failed section in future versions
4. **Flexibility**: Dump non-contiguous memory regions efficiently
5. **Backward Compatible**: Existing single-section dumps still work

## Testing Strategy

### Unit Tests (Payload)
- Test section parsing from request buffer
- Test ACK waiting logic
- Test error code generation

### Integration Tests (C# + Payload)
- Single section dump (backward compatibility)
- Multi-section dump (3-5 sections)
- Large dump (16 sections, several MB total)
- Error scenarios (invalid count, invalid sizes, NAK)
- Timeout scenarios

### Manual Testing
1. Dump 3 sections from different memory regions
2. Verify each section saved to separate file
3. Verify sizes match expectations
4. Verify data integrity with checksums

## Security Considerations

⚠️ **Warning**: This payload allows arbitrary memory reads from the PLC
- Use only on authorized systems for security research
- Invalid memory addresses may crash the PLC
- Consider rate limiting or size limits for production use
- Memory contents may contain sensitive data

## References

- Original dump_mem.c implementation
- UART protocol (print.c, read.c library functions)
- Siemens S7 bootloader protocol documentation
- ARM Cortex-R4 architecture

## License

Same as parent SiemensS7-Bootloader project

---

**Status**: Payload implementation complete, C# client integration in progress
**Next Priority**: Update MemoryDumpCommandHandler to construct multi-section requests
