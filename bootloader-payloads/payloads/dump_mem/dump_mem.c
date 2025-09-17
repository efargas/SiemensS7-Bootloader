/**
 * @file dump_mem.c
 * @brief Memory dumping payload for Siemens S7 PLC
 * 
 * This payload reads arbitrary memory locations from the PLC and sends
 * the data back to the host via UART. It's used for firmware analysis
 * and reverse engineering of the PLC's memory layout.
 */

#include <stdbool.h>
#include <stdint.h>

#include "../lib/print.h"
#include "../lib/read.h"
//#include "../lib/stdlib.h"
//#include "../lib/string.h"
#include "memory.h"

char greeting[] = "Ok\0";

int (*read_flash_page_calc_crc)(unsigned short start_offset, unsigned int *fl_dw2_stored_crc_out, unsigned int *fl_dw_3_out_num_dwords, unsigned int *fl_dw_4_out, unsigned int *fl_dw_5_out, unsigned int *content_out, unsigned int *calc_crc_out, int use_inline_size, unsigned int *num_wait_cycles) = (int (*)(unsigned short start_offset, unsigned int *fl_dw2_stored_crc_out, unsigned int *fl_dw_3_out_num_dwords, unsigned int *fl_dw_4_out, unsigned int *fl_dw_5_out, unsigned int *content_out, unsigned int *calc_crc_out, int use_inline_size, unsigned int *num_wait_cycles)) 0x13A2C;

int doit(unsigned char *, unsigned char *) __attribute__((noinline));

/**
 * @brief Entry point for the memory dump payload
 * @param read_buf Buffer containing dump parameters from host
 * @param write_buf Buffer for writing response data
 * @return 0 on success
 * 
 * Preserves ARM registers and calls the main dump function.
 * This is the function that gets called by the bootloader's hook system.
 */
int _start(unsigned char *read_buf, unsigned char *write_buf) {
    __asm__("stmfd sp!, {r2-r12, lr}");
    __asm__("adr r9, _start");
    
    int res = doit(read_buf, write_buf);

    __asm("ldmfd sp!, {r2-r12, lr}");
    return res;
}

/**
 * @brief Main memory dumping function
 * @param read_buf Buffer containing target address and size parameters
 * @param write_buf Buffer for response (unused)
 * @return 0 on success
 * 
 * Extracts target address and size from read_buf, then sends the memory
 * contents back to the host via UART protocol. Format of read_buf:
 * - Offset 4: Target memory address (4 bytes)
 * - Offset 8: Number of bytes to dump (4 bytes)
 */
int doit(uint8_t *read_buf, unsigned char *write_buf) {
    uint32_t size = *((uint32_t *)(read_buf+8)); 
    char *tar_addr = *((char **)(read_buf+4));

    UART_protocol_send_single(greeting, sizeof(greeting));

    UART_protocol_send_many(tar_addr, size);

    //UART_protocol_send_single(greeting2, sizeof(greeting2));

    write_buf[0] = 0;
    return 0;
}