# UART Speed Reconfiguration Payload

## Overview

This payload reconfigures the PL011 UART baud rate on the Siemens S7 PLC to improve memory dump transfer speeds. By increasing the baud rate from the default 38400 to 115200 (or higher), memory dump operations can be significantly accelerated.

## Features

- Dynamically reconfigures UART baud rate using host-calculated divisors
- Supports any baud rate supported by the PL011 UART hardware
- Flexible UART clock frequency configuration from host
- Preserves UART configuration (8N1, FIFO enabled)
- Provides confirmation/error feedback
- Smaller binary size (788 bytes) through simplified logic

## Technical Details

### PL011 UART Configuration

The payload configures the ARM PL011 UART by:

1. Receiving pre-calculated integer (IBRD) and fractional (FBRD) baud rate divisors from the host
2. Validating the divisor values
3. Disabling the UART safely
4. Setting the new divisor values
5. Re-enabling the UART with the new baud rate

### Baud Rate Calculation (Host-Side)

The host calculates the divisors based on the UART clock frequency:

```
BaudRateDivisor = UARTCLK / (16 × BaudRate)
UARTIBRD = integer(BaudRateDivisor)
UARTFBRD = integer((BaudRateDivisor - UARTIBRD) × 64 + 0.5)
```

**Default UART Clock:** 14.7456 MHz (configurable for different hardware variants)

**Example Calculations:**
- 115200 baud: IBRD=8, FBRD=0
- 230400 baud: IBRD=4, FBRD=0

### Memory Layout

The payload expects IBRD and FBRD as 32-bit values in the read buffer:

```
read_buf[4:7] = IBRD (uint32_t, big-endian)
read_buf[8:11] = FBRD (uint32_t, big-endian)
```

## Usage

### Building

```bash
make
```

This produces:
- `build/set_uart_speed` - ELF executable
- `build/set_uart_speed.bin` - Raw binary for PLC upload
- `build/set_uart_speed.ihex` - Intel HEX format

### Integration Workflow

1. **Upload Stager** - Install the stager payload first
2. **Set UART Speed** - Upload and execute this payload with desired baud rate
3. **Confirm Response** - Wait for "UART_SPEED_OK" confirmation at old baud rate
4. **Switch Host** - Reconfigure host (socat/serial adapter) to new baud rate
5. **Dump Memory** - Execute memory dump at higher speed

### Example Baud Rates

- **38400** - Default speed (baseline)
- **115200** - 3x faster (recommended)
- **230400** - 6x faster (if supported by hardware)
- **460800** - 12x faster (experimental)

## Performance Impact

| Baud Rate | Speed Increase | 1MB Dump Time* |
|-----------|----------------|----------------|
| 38400     | 1x (baseline)  | ~4.3 minutes   |
| 115200    | 3x             | ~1.4 minutes   |
| 230400    | 6x             | ~43 seconds    |
| 460800    | 12x            | ~22 seconds    |

*Approximate times including protocol overhead

## Important Notes

1. **Host Must Match**: After reconfiguring PLC UART, the host serial connection (socat) must be reconfigured to the same baud rate
2. **Power Cycle Resets**: UART speed returns to default (38400) after PLC power cycle
3. **Confirmation Timing**: The "UART_SPEED_OK" message is sent at the OLD baud rate, then the UART switches to the new speed
4. **Error Handling**: If an invalid baud rate is requested, the payload sends "UART_SPEED_ERR" and does not change the speed

## Limitations

- UART clock frequency is assumed to be 14.745600 MHz (may need adjustment for specific hardware)
- Maximum baud rate is limited by hardware capabilities and cable quality
- Higher baud rates may be less reliable over longer cables or with electrical interference

## Testing

The payload can be tested with different baud rates to find the optimal speed for your specific setup:

```bash
# Start with moderate increase
Target: 115200 baud

# If stable, try higher
Target: 230400 baud

# Maximum (test carefully)
Target: 460800 baud
```

Monitor for transmission errors and adjust accordingly.
