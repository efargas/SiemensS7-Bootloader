#include <stdbool.h>
#include <stdint.h>

#include "../lib/print.h"
#include "../lib/read.h"
#include "../lib/stdlib.h"
//#include "../lib/string.h"
#include "memory.h"

char greeting[] = "Greetings from PLC\n";

int doit(unsigned char *, unsigned char *) __attribute__((noinline));

int _start(unsigned char *read_buf, unsigned char *write_buf) {
    __asm__("stmfd sp!, {r2-r12, lr}");
    // Define a local label at the beginning of the function's code
    // and load its address (which is effectively the address of _start) into r9.
    __asm__(
        ".L_start_func_begin:\n"
        "adr r9, .L_start_func_begin"
    );
    
    int res = doit(read_buf, write_buf);

    __asm("ldmfd sp!, {r2-r12, lr}");
    return res;
}

int doit(unsigned char *read_buf, unsigned char *write_buf) {
    char buf[0x20];

    memset(buf, 0, 0x20);

    memcpy(buf, greeting, sizeof(greeting)-1);

    while(1) {
        // Busy loop for some time
        for (int count = 0; count < 0x6400000; ++count) {}
        UART_protocol_send_single(buf, sizeof(greeting) - 1);
    }
    

    write_buf[0] = 0;
    return 0;
}