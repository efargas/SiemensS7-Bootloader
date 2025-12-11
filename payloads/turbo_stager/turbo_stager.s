/*
 * turbo_stager.s
 *
 * Author: Jules
 *
 * Description:
 * This stager performs a handshake with the client to switch the UART baud rate
 * from 38400 to 115200, and then loads a secondary payload (dump_mem.bin)
 * at the higher speed.
 */

.syntax unified
.arm

.section .text
.global _start

_start:
    /* --- Handshake at 38400 baud --- */
    // Send 0xAA to client to initiate turbo mode
    mov r0, #0xAA
    bl uart_send_char

    // Wait for 0x5F from client to confirm
    bl uart_recv_char
    cmp r0, #0x5F
    bne _start // If handshake fails, retry

    /* --- Switch UART to 115200 baud --- */
    bl uart_set_baudrate_turbo

    /* --- Load payload at 115200 baud --- */
    // First, receive destination address (4 bytes, big-endian)
    bl uart_recv_u32_be
    mov r2, r0 // r2 = destination pointer

    // Second, receive payload size (4 bytes, big-endian)
    bl uart_recv_u32_be
    mov r1, r0 // r1 = size

    // Set up counter
    mov r3, #0         // r3 = counter

load_loop:
    cmp r3, r1 // if counter == size, we are done
    beq execute_payload

    // Receive one byte and store it
    bl uart_recv_char
    strb r0, [r2, r3]

    // Increment counter and loop
    add r3, r3, #1
    b load_loop

_start:
    /* ... (handshake and baud rate switch) ... */

    /* --- Load payload at 115200 baud --- */
    // First, receive destination address (4 bytes, big-endian)
    bl uart_recv_u32_be
    mov r4, r0 // r4 = destination pointer (use callee-saved register)

    // Second, receive payload size (4 bytes, big-endian)
    bl uart_recv_u32_be
    mov r1, r0 // r1 = size

    // Set up counter
    mov r3, #0         // r3 = counter

load_loop:
    cmp r3, r1 // if counter == size, we are done
    beq execute_payload

    // Receive one byte and store it
    bl uart_recv_char
    strb r0, [r4, r3]

    // Increment counter and loop
    add r3, r3, #1
    b load_loop

execute_payload:
    // Instead of jumping, install the loaded payload as an additional hook
    // Hook table address: 0x1003ABA0
    // Hook index: 0x1a (26), matches DEFAULT_SECOND_ADD_HOOK_IND in client.py
    ldr r0, =0x1003ABA0
    mov r1, #26
    mov r2, #8
    mul r3, r1, r2      // r3 = offset = 208
    add r0, r0, r3      // r0 = address of hook entry 0x1a

    // Write length field (0x000000ff for variable-length args)
    ldr r1, =0x000000ff
    str r1, [r0]

    // Write function pointer (address is in r4)
    str r4, [r0, #4]

    // Send 'D' for Done to signal completion to the client
    mov r0, #'D'
    bl uart_send_char

// Infinite loop to halt execution
end_loop:
    b end_loop


/* --- UART Functions --- */
/*
 * uart_send_char(char c)
 * Sends a single character over UART.
 * r0: character to send
 */
uart_send_char:
    ldr r1, =0xFFFB8000 // UART_BASE
    // Wait for TX buffer to be empty (TXFE flag)
tx_wait:
    ldr r2, [r1, #0x18] // UARTFR offset
    tst r2, #(1 << 7)   // Check TXFE bit
    beq tx_wait
    // Write character to data register
    str r0, [r1, #0x00] // UARTDR offset
    bx lr

/*
 * uart_recv_char()
 * Receives a single character from UART.
 * returns: character in r0
 */
uart_recv_char:
    ldr r1, =0xFFFB8000 // UART_BASE
    // Wait for RX buffer to have data (RXFE flag)
rx_wait:
    ldr r2, [r1, #0x18] // UARTFR offset
    tst r2, #(1 << 4)   // Check RXFE bit
    bne rx_wait
    // Read character from data register
    ldr r0, [r1, #0x00] // UARTDR offset
    bx lr

/*
 * uart_recv_u32_be()
 * Receives a 32-bit big-endian integer.
 * returns: integer in r0
 */
uart_recv_u32_be:
    // Receive 4 bytes and assemble them into a big-endian word
    bl uart_recv_char
    mov r1, r0
    bl uart_recv_char
    mov r2, r0
    bl uart_recv_char
    mov r3, r0
    bl uart_recv_char
    // r0 is the last byte received
    orr r0, r0, r3, lsl #8
    orr r0, r0, r2, lsl #16
    orr r0, r0, r1, lsl #24
    bx lr

/*
 * uart_set_baudrate_turbo()
 * Reconfigures the UART to 115200 baud.
 * Assumes a 24MHz UART clock.
 */
uart_set_baudrate_turbo:
    ldr r0, =0xFFFB8000 // UART_BASE

    // 1. Disable UART
    ldr r1, [r0, #0x30] // UARTCR offset
    bic r1, r1, #1      // Clear UARTEN bit
    str r1, [r0, #0x30]

    // 2. Set Baud Rate Divisors for 115200
    // IBRD = 13 (0x0D)
    mov r1, #13
    str r1, [r0, #0x24] // UARTIBRD offset
    // FBRD = 1 (0x01)
    mov r1, #1
    str r1, [r0, #0x28] // UARTFBRD offset

    // 3. Set Line Control Register (LCR_H) for 8N1
    // WLEN = 8 bits, FEN = 1 (enable FIFOs)
    mov r1, #0x70       // 0b01110000
    str r1, [r0, #0x2C] // UARTLCR_H offset

    // 4. Re-enable UART
    ldr r1, [r0, #0x30] // UARTCR offset
    orr r1, r1, #1      // Set UARTEN bit
    str r1, [r0, #0x30]

    bx lr
