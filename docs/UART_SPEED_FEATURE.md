# UART Speed Reconfiguration Feature

## Overview

This feature enables dynamic reconfiguration of the Siemens S7 PLC's UART baud rate to significantly improve memory dump transfer speeds. By increasing the baud rate from the default 38400 to 115200 (or higher), memory dump operations can be accelerated by 3x to 12x.

## Performance Improvements

| Baud Rate | Speed Increase | 1MB Dump Time* | 128MB Dump Time* |
|-----------|----------------|----------------|------------------|
| 38400     | 1x (baseline)  | ~4.3 minutes   | ~9.2 hours       |
| 115200    | 3x             | ~1.4 minutes   | ~3.1 hours       |
| 230400    | 6x             | ~43 seconds    | ~1.5 hours       |
| 460800    | 12x            | ~22 seconds    | ~47 minutes      |

*Approximate times including protocol overhead

## Architecture

### Component Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    User Interface Layer                      │
│  (Future: ExploitSequenceFeatureViewModel + UI Controls)    │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
│                    PlcClient.cs                             │
│   SetUartSpeedAsync(baudRate, payload, cancellationToken)  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    Business Logic Layer                      │
│                   PlcMemoryManager.cs                       │
│  - Validates baud rate                                      │
│  - Installs payload via stager                              │
│  - Invokes payload with parameters                          │
│  - Parses response                                          │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   Communication Layer                        │
│              PlcStagerManager.cs + Protocol                 │
│  - Uploads payload to PLC memory                            │
│  - Executes payload via add_hook mechanism                  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                        PLC Layer                             │
│              set_uart_speed.bin (ARM Payload)               │
│  - Reconfigures PL011 UART registers                        │
│  - Sets baud rate divisors                                  │
│  - Returns confirmation                                     │
└─────────────────────────────────────────────────────────────┘
```

## Implementation Details

### ARM Payload (set_uart_speed.c)

**Location:** `bootloader-payloads/payloads/set_uart_speed/`

**Key Features:**
- Receives pre-calculated IBRD and FBRD divisors from host (no hardcoded clock frequency)
- Supports any baud rate supported by PL011 UART hardware
- Safe big-endian reading with `read_be32()` helper to avoid unaligned memory access
- Configures PL011 UART registers:
  - UARTIBRD: Integer baud rate divisor (0-65535)
  - UARTFBRD: Fractional baud rate divisor (0-63)
  - UARTLCR_H: Line control (8N1, FIFO enabled)
  - UARTCR: Control register (UART enable, TX/RX enable)
- Returns "UART_SPEED_OK" on success
- Returns "UART_SPEED_ERR" on failure
- Binary size: 880 bytes (optimized with safe endianness handling)

**Baud Rate Divisor Calculations (Host-Side):**

The C# host calculates divisors based on the UART clock frequency:

```
BaudRateDivisor = UARTCLK / (16 × BaudRate)
IBRD = integer(BaudRateDivisor)
FBRD = integer((BaudRateDivisor - IBRD) × 64 + 0.5)

Default UART_CLK = 14.7456 MHz (configurable for different hardware)

Examples (with default clock):
- 38400 baud: IBRD=24, FBRD=0
- 115200 baud: IBRD=8, FBRD=0
- 230400 baud: IBRD=4, FBRD=0
```

### C# API Integration

**PayloadManager Methods:**
```csharp
// Load UART speed reconfiguration payload
public async Task<byte[]> GetUartSpeedPayloadAsync(string payloadsBase)
```

**UartBaudRateCalculator (Helper Class):**
```csharp
// Calculate IBRD and FBRD divisors for any baud rate
public static (uint ibrd, uint fbrd) CalculateDivisors(
    uint baudRate, 
    uint uartClockHz = 14745600)

// Get pre-calculated divisors for common baud rates
public static (uint ibrd, uint fbrd) GetCommonBaudRateDivisors(uint baudRate)
```

**PlcMemoryManager Methods:**
```csharp
// Execute UART speed reconfiguration with optional callback and configurable UART clock
public async Task<bool> SetUartSpeedAsync(
    uint baudRate, 
    byte[] uartSpeedPayload, 
    PlcStagerManager stagerManager,
    uint uartClockHz = 14745600,
    Action<uint>? onSuccessCallback = null,
    CancellationToken cancellationToken = default)
```

**PlcClient Public API:**
```csharp
// User-facing API for UART speed configuration
public async Task<bool> SetUartSpeedAsync(
    uint baudRate, 
    byte[] uartSpeedPayload,
    uint uartClockHz = 14745600,
    Action<uint>? onSuccessCallback = null,
    CancellationToken cancellationToken = default)
```

**SocatService Methods:**
```csharp
// Restart socat with new baud rate (automatic reconfiguration)
public bool RestartWithNewBaudRate(int newBaudRate)

// Get current baud rate
public int CurrentBaudRate { get; }
```

## Usage Workflow

### Automatic Socat Reconfiguration (Recommended)

```csharp
// 1. Load UART speed payload
var payloadManager = new PayloadManager(baseDirectory);
var uartSpeedPayload = await payloadManager.GetUartSpeedPayloadAsync(payloadsBase);

// 2. Set UART speed with automatic socat restart (using default UART clock 14.7456 MHz)
bool success = await plcClient.SetUartSpeedAsync(115200, uartSpeedPayload, 
    uartClockHz: UartBaudRateCalculator.DefaultUartClockHz,
    onSuccessCallback: (newBaudRate) => 
    {
        // Automatically restart socat with new baud rate
        socatService.RestartWithNewBaudRate((int)newBaudRate);
    });

// Alternative: Override UART clock for different hardware variants
// bool success = await plcClient.SetUartSpeedAsync(115200, uartSpeedPayload, 
//     uartClockHz: 16000000, // 16 MHz for different hardware
//     onSuccessCallback: (newBaudRate) => socatService.RestartWithNewBaudRate((int)newBaudRate));

if (success)
{
    // 3. Continue with faster memory dumps
    var dumpPayload = await payloadManager.GetMemoryDumperPayloadAsync(payloadsBase);
    var data = await plcClient.DumpMemoryAsync(address, length, dumpPayload, progress);
}
```

### Manual Socat Reconfiguration

```csharp
// 1. Load UART speed payload
var payloadManager = new PayloadManager(baseDirectory);
var uartSpeedPayload = await payloadManager.GetUartSpeedPayloadAsync(payloadsBase);

// 2. Set UART speed (example: 115200 baud)
bool success = await plcClient.SetUartSpeedAsync(115200, uartSpeedPayload);

if (success)
{
    // 3. Reconfigure host serial connection (socat)
    // Stop current socat process
    // Restart with new baud rate:
    // socat TCP-LISTEN:10001,fork,reuseaddr /dev/ttyUSB0,raw,echo=0,b115200
    
    // 4. Continue with faster memory dumps
    var dumpPayload = await payloadManager.GetMemoryDumperPayloadAsync(payloadsBase);
    var data = await plcClient.DumpMemoryAsync(address, length, dumpPayload, progress);
}
```

### Manual Workflow

1. **Upload Stager** - Install bootloader stager first
2. **Set UART Speed** - Execute UART speed reconfiguration payload
3. **Wait for Confirmation** - Receive "UART_SPEED_OK" at old baud rate
4. **Reconfigure Host** - Update socat/serial connection to new baud rate:
   ```bash
   # Stop current socat
   killall socat
   
   # Restart with new baud rate (example: 115200)
   socat TCP-LISTEN:10001,fork,reuseaddr /dev/ttyUSB0,raw,echo=0,b115200
   ```
5. **Dump Memory** - Execute memory dumps at higher speed

## Important Considerations

### Host Reconfiguration Required

**Automatic (Recommended):** Use the `onSuccessCallback` parameter to automatically restart socat with the new baud rate:

```csharp
await plcClient.SetUartSpeedAsync(115200, uartSpeedPayload, 
    onSuccessCallback: (newBaudRate) => socatService.RestartWithNewBaudRate((int)newBaudRate));
```

**Manual (Fallback):** If automatic reconfiguration fails or is not used, the host serial connection (socat or direct serial) MUST be manually reconfigured to match. The confirmation message "UART_SPEED_OK" is sent at the OLD baud rate, after which the UART switches to the new speed.

**Timing:**
```
PLC sends "UART_SPEED_OK" → [still at old baud rate]
Callback invoked (if provided) → [socat restarts with new baud rate]
PLC switches UART to new speed → [immediately after sending]
Host ready at new baud rate → [automatic or manual reconfiguration complete]
```

### Power Cycle Behavior

**Automatic Reset:** UART speed automatically returns to default (38400 baud) after PLC power cycle. No manual reversion is needed - the bootloader hardware initializes the UART to default settings on each boot.

### Reliability Considerations

- **Cable Quality:** Higher baud rates are more sensitive to cable quality and length
- **Electrical Interference:** Industrial environments may have EMI affecting high-speed serial
- **Testing:** Start with 115200 baud and verify stability before trying higher rates
- **Error Detection:** Monitor for transmission errors and drop to lower speed if issues occur

## File Structure

```
SiemensS7-Bootloader/
├── bootloader-payloads/
│   └── payloads/
│       └── set_uart_speed/
│           ├── set_uart_speed.c       # ARM payload source
│           ├── Makefile               # Build configuration
│           ├── link.ld                # Linker script
│           └── README.md              # Payload documentation
├── src/
│   ├── S7_Csharp_Core/
│   │   └── S7.Net/
│   │       ├── PayloadManager.cs     # Payload loading (updated)
│   │       ├── PlcMemoryManager.cs   # UART speed execution (updated)
│   │       └── PlcClient.cs          # Public API (updated)
│   └── S7_Csharp_Utility/
│       └── Resources/
│           └── payloads/
│               └── set_uart_speed/
│                   └── set_uart_speed.bin  # Compiled payload (940 bytes)
└── README.md                          # Main documentation (updated)
```

## Testing and Validation

### Payload Validation

✅ **Build Verification:**
- Successfully compiles with Docker build system
- Binary size: 940 bytes
- No dependency on runtime division (__aeabi_uidiv)
- Pre-calculated divisors for all supported baud rates

✅ **C# API Validation:**
- PayloadManager successfully loads payload
- PlcMemoryManager validates baud rates correctly
- PlcClient public API exposed correctly
- All projects build without errors

### Recommended Testing Sequence

1. **Test at 115200 baud:**
   - Most compatible and reliable
   - 3x speed improvement
   - Suitable for most cable lengths and environments

2. **Test at 230400 baud (if 115200 is stable):**
   - 6x speed improvement
   - Requires good quality cables
   - Test with various cable lengths

3. **Test at 460800 baud (experimental):**
   - 12x speed improvement
   - May require very short cables
   - Monitor for errors carefully

4. **Measure actual performance:**
   - Time 1MB dumps at each baud rate
   - Compare with theoretical improvements
   - Verify data integrity with checksums

## Future Enhancements

### Planned Features

1. **UI Integration**
   - Add baud rate selection dropdown
   - Add "Set UART Speed" button
   - Display current baud rate status
   - Show speed improvement calculator

2. **Automatic Host Reconfiguration**
   - Detect socat process automatically
   - Restart socat with new baud rate
   - Verify new connection works
   - Fallback to old speed on failure

3. **Configuration Persistence**
   - Save preferred baud rate in settings
   - Auto-configure on startup
   - Remember last successful speed

4. **Advanced Features**
   - Auto-detect optimal baud rate
   - Speed test utility
   - Transmission error monitoring
   - Automatic fallback on errors

## References

### Technical Documentation

- **ARM PL011 UART**: Technical Reference Manual
- **Siemens S7-1200**: Hardware documentation
- **Baud Rate Theory**: Serial communication fundamentals

### Related Files

- `bootloader-payloads/payloads/set_uart_speed/README.md` - Detailed payload documentation
- `bootloader-payloads/README.md` - Payload system overview
- `README.md` - Main application documentation

## Troubleshooting

### Common Issues

**Issue:** "UART_SPEED_ERR" response
- **Cause:** Invalid baud rate parameter
- **Solution:** Use only supported rates (38400, 57600, 115200, 230400, 460800)

**Issue:** No response after UART speed change
- **Cause:** Host not reconfigured to new baud rate
- **Solution:** Restart socat with correct baud rate parameter

**Issue:** Garbled data after reconfiguration
- **Cause:** Baud rate mismatch between PLC and host
- **Solution:** Verify both PLC and host are using same baud rate

**Issue:** Transmission errors at high baud rates
- **Cause:** Cable quality or electrical interference
- **Solution:** Use shorter cable, better shielding, or lower baud rate

**Issue:** UART reverts to 38400 unexpectedly
- **Cause:** PLC power cycled
- **Solution:** Re-execute UART speed configuration after power cycle

## License and Attribution

This feature is part of the SiemensS7-Bootloader project and follows the same license terms.

**Original Bootloader Research:**
- Ali Abbasi, Tobias Scharnowski, Thorsten Holz
- Black Hat Europe 2019, 36C3 2019

**UART Speed Enhancement:**
- Implementation based on ARM PL011 UART specifications
- Integrated into C# utility application
- Designed for production use with Siemens S7 PLCs
