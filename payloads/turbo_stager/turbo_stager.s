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

/* --- Hardware Constants --- */
.equ UART_BASE,         0xFFFB8000  /* UART base address */
.equ HOOK_TABLE_ADDR,   0x1003ABA0  /* Hook table start address */
.equ HOOK_INDEX,        26          /* Hook index 0x1a (matches DEFAULT_SECOND_ADD_HOOK_IND) */
.equ HOOK_ENTRY_SIZE,   8           /* Size of each hook table entry */

/* Timeout value for UART operations (~3 seconds at CPU speed) */
.equ TIMEOUT_COUNT,     0x100000

/* Maximum reasonable payload size (1MB) - prevents memory corruption */
.equ MAX_PAYLOAD_SIZE,  0x100000

/* Valid memory range for payload loading */
.equ MIN_VALID_ADDR,    0x10000000  /* Start of valid RAM */
.equ MAX_VALID_ADDR,    0x20000000  /* End of valid RAM */

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

    /* --- Verify communication at 115200 baud --- */
    /* Wait for 0xCC from client to verify speed with timeout */
    _verify_speed:
    ldr r4, =TIMEOUT_COUNT
    bl uart_recv_char_with_timeout
    cmp r0, #-1         /* Check if timeout occurred */
    beq end_loop        /* If timeout, halt execution */
    cmp r0, #0xCC
    bne _verify_speed   /* If not 0xCC, retry receiving */

    /* Send 0xDD to confirm we're at the same speed */
    mov r0, #0xDD
    bl uart_send_char

    /* --- Load payload at 115200 baud --- */
    // First, receive destination address (4 bytes, big-endian)
    bl uart_recv_u32_be
    mov r2, r0 // r2 = destination address where payload will be loaded
    
    // Validate destination address is in valid memory range
    ldr r4, =MIN_VALID_ADDR
    cmp r2, r4
    blo end_loop        /* Address too low, halt */
    ldr r4, =MAX_VALID_ADDR
    cmp r2, r4
    bhs end_loop        /* Address too high, halt */

    // Second, receive payload size (4 bytes, big-endian)
    bl uart_recv_u32_be
    mov r1, r0 // r1 = size
    
    // Validate size is reasonable (not zero, not too large)
    cmp r1, #0
    beq end_loop        /* Size is zero, halt */
    ldr r4, =MAX_PAYLOAD_SIZE
    cmp r1, r4
    bhi end_loop        /* Size too large, halt */

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

execute_payload:
    // Install the loaded payload as an additional hook in the hook table
    // The payload was loaded at the destination address originally stored in r2
    // We need to register it in the hook table so the client can invoke it
    
    // Save the payload destination address before we overwrite r2
    mov r5, r2          // r5 = payload destination address
    
    // Calculate hook table entry address
    ldr r0, =HOOK_TABLE_ADDR
    ldr r1, =HOOK_INDEX
    ldr r2, =HOOK_ENTRY_SIZE
    mul r3, r1, r2      // r3 = offset into hook table
    add r0, r0, r3      // r0 = address of hook entry

    // Write length field (0x000000ff for variable-length args)
    ldr r1, =0x000000ff
    str r1, [r0]

    // Write function pointer to hook entry (+4 offset is the function pointer field)
    // This is the address where we loaded the payload
    str r5, [r0, #4]

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
    ldr r1, =UART_BASE
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
    ldr r1, =UART_BASE
    // Wait for RX buffer to have data (RXFE flag)
rx_wait:
    ldr r2, [r1, #0x18] // UARTFR offset
    tst r2, #(1 << 4)   // Check RXFE bit
    bne rx_wait
    // Read character from data register
    ldr r0, [r1, #0x00] // UARTDR offset
    bx lr

/*
 * uart_recv_char_with_timeout()
 * Receives a single character from UART with timeout.
 * r4: timeout counter value
 * returns: character in r0, or -1 if timeout
 */
uart_recv_char_with_timeout:
    push {r5, r6}
    ldr r5, =UART_BASE
    mov r6, r4          // r6 = timeout counter
rx_wait_with_timeout:
    ldr r2, [r5, #0x18] // UARTFR offset
    tst r2, #(1 << 4)   // Check RXFE bit
    beq rx_data_ready   // Data is ready
    subs r6, r6, #1     // Decrement timeout counter
    bne rx_wait_with_timeout
    // Timeout occurred
    mvn r0, #0          // r0 = -1 (timeout indicator)
    pop {r5, r6}
    bx lr
rx_data_ready:
    // Read character from data register
    ldr r0, [r5, #0x00] // UARTDR offset
    pop {r5, r6}
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
 * 
 * Baud rate calculation:
 * Assumes 24MHz UART clock (UARTCLK)
 * Baud Rate Divisor = UARTCLK / (16 * Baud Rate)
 * For 115200: Divisor = 24000000 / (16 * 115200) = 13.02...
 * IBRD = integer part = 13
 * FBRD = fractional part * 64 = 0.02 * 64 ≈ 1
 * 
 * Actual baud rate: 24000000 / (16 * (13 + 1/64)) ≈ 115384 baud
 * Error: ~0.16% (within acceptable tolerance)
 */
uart_set_baudrate_turbo:
    ldr r0, =UART_BASE

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
