#ifndef __USAR_H__
#define __USAR_H__
#include "include/platform.h"
#include "include/type.h"
/*
 * Reference
 * [1]: TECHNICAL DATA ON 16550, http://byterunner.com/16550.html
 */

/*
 * UART control registers map. see [1] "PROGRAMMING TABLE"
 * note some are reused by multiple functions
 * 0 (write mode): THR/DLL
 * 1 (write mode): IER/DLM
 */
// #define RHR 0 // Receive Holding Register (read mode)
// #define THR 0 // Transmit Holding Register (write mode)
// #define DLL 0 // LSB of Divisor Latch (write mode)
//
// #define IER 1 // Interrupt Enable Register (write mode)
// #define DLM 1 // MSB of Divisor Latch (write mode)
// #define FCR 2 // FIFO Control Register (write mode)
// #define ISR 2 // Interrupt Status Register (read mode)
// #define LCR 3 // Line Control Register
// #define MCR 4 // Modem Control Register
// #define LSR 5 // Line Status Register
// #define MSR 6 // Modem Status Register
// #define SPR 7 // ScratchPad Register

// DLAB=0
#define RBR 0 // receive buffer reg R
#define THR 0 // transmitter holding W
#define IER 1 // interrupt enable RW
#define IIR 2 // interrupt identiffication R
#define FCR 2 // fifo control W
#define LCR 3 // line control RW
#define MCR 4 // modem control RW
#define LSR 5 // line status R
#define MSR 6 // modem status R
#define SCR 7 // scratch RW

// DLAB=1
#define DLL 0 // divisor latch
#define LSB 0 // divisor latch
#define DLM 1
#define DSM 1
#define IIR 2 // interrupt identiffication
#define FCR 2 // fifo control
#define LCR 3 // line control
#define MCR 4 // modem control
#define LSR 5 // line status
#define MSR 6 // modem status
#define SCR 7 // scratch

/*
 * POWER UP DEFAULTS
 * IER = 0: TX/RX holding register interrupts are both disabled
 * ISR = 1: no interrupt penting
 * LCR = 0
 * MCR = 0
 * LSR = 60 HEX
 * MSR = BITS 0-3 = 0, BITS 4-7 = inputs
 * FCR = 0
 * TX = High
 * OP1 = High
 * OP2 = High
 * RTS = High
 * DTR = High
 * RXRDY = High
 * TXRDY = Low
 * INT = Low
 */

/*
 * LINE STATUS REGISTER (LSR)
 * LSR BIT 0:
 * 0 = no data in receive holding register or FIFO.
 * 1 = data has been receive and saved in the receive holding register or FIFO.
 * ......
 * LSR BIT 5:
 * 0 = transmit holding register is full. 16550 will not accept any data for
 * transmission. 1 = transmitter hold register (or FIFO) is empty. CPU can load
 * the next character.
 * ......
 */

#define UART_REG(reg) ((volatile uint8_t *)(UART0_ADDRESS + reg))

#define LSR_RX_READY (1 << 0)
#define LSR_TX_IDLE (1 << 5)

#define uart_read_reg(reg) (*(UART_REG(reg)))
#define uart_write_reg(reg, v) (*(UART_REG(reg)) = (v))

void uart_isr(void);
void uart_init();
int uart_putc(char ch);
int uart_getc(void);
void uart_puts(char *s);
#endif
