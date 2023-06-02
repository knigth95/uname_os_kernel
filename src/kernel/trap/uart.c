#include "include/uart.h"
#include "include/log.h"
#include "include/riscv.h"

/*
 * 参考自
 * rvos：https://github.com/plctlab/riscv-operating-system-mooc/blob/main/code/os/01-helloRVOS/uart.c
 */

void uart_init() {
    /* disable interrupts. */
    uart_write_reg(IER, 0x00);
    //    uart_write_reg(FCR, 0x00);
    //    Info("%lx", uart_read_reg(IIR));

    /*
     * Setting baud rate. Just a demo here if we care about the divisor,
     * but for our purpose [QEMU-virt], this doesn't really do anything.
     *
     * Notice that the divisor register DLL (divisor latch least) and DLM (divisor
     * latch most) have the same base address as the receiver/transmitter and the
     * interrupt enable register. To change what the base address points to, we
     * open the "divisor latch" by writing 1 into the Divisor Latch Access Bit
     * (DLAB), which is bit index 7 of the Line Control Register (LCR).
     *
     * Regarding the baud rate value, see [1] "BAUD RATE GENERATOR PROGRAMMING
     * TABLE". We use 38.4K when 1.8432 MHZ crystal, so the corresponding value
     * is 3. And due to the divisor register is two bytes (16 bits), so we need to
     * split the value of 3(0x0003) into two bytes, DLL stores the low byte,
     * DLM stores the high byte.
     */
    uint8_t lcr = uart_read_reg(LCR);
    // enable dlab
    uart_write_reg(LCR, lcr | (1 << 7));
    uart_write_reg(DLL, 0x03);
    uart_write_reg(DLM, 0x00);
    // disable dlab
    uart_write_reg(LCR, lcr & ~(1 << 7));

    /*
     * Continue setting the asynchronous data communication format.
     * - number of the word length: 8 bits
     * - number of stop bits：1 bit when word length is 8 bits
     * - no parity
     * - no break control
     * - disabled baud latch
     */

    lcr = 0;
    uart_write_reg(LCR, lcr | (3 << 0));

    // enable input interrupt
    uint8_t ier = uart_read_reg(IER);
    uart_write_reg(IER, ier | 1);
}

int uart_putc(char ch) {
    while ((uart_read_reg(LSR) & LSR_TX_IDLE) == 0)
        ;
    return uart_write_reg(THR, ch);
}

void uart_puts(char *s) {
    while (*s) {
        uart_putc(*s++);
    }
}

int uart_getc(void) {
    Info("%lx", uart_read_reg(IIR));
    if (uart_read_reg(LSR) & LSR_RX_READY) {
        return uart_read_reg(RBR);
    } else {
        return -1;
    }
}

/*
 * handle a uart interrupt, raised because input has arrived, called from
 * trap.c.
 */
void uart_isr(void) {
    while (1) {
        int c = uart_getc();
        if (c == -1) {
            break;
        } else {
            uart_putc((char)c);
            uart_putc('\n');
        }
    }
}
