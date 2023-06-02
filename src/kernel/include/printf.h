#ifndef __PRINTF_H__
#define __PRINTF_H__

// TODO:输出16进制有问题，没有按照正常的16进制无符号输出
void printf(char *, ...);
void console_putc(const char c);
void console_puts(const char *s);
#endif
