#include "../include/sbi.h"
#include "../include/spinlock.h"
#include "../include/type.h"
#include "stdarg.h"
#include "stddef.h"

static char digits[] = "0123456789abcdef";

static struct {
    struct spinlock lock;
    int locking;
} pr;

void console_putc(const char c) {
    sbi_console_putchar(c);
}

void console_puts(const char *s) {
    while (*s) {
        console_putc(*s++);
    }
}

void printint(int xx, int base, int sign) {
    char buf[16];
    int i;
    uint32_t x;

    // 按符号输出，并且数字小于0
    if (sign && (sign = (xx < 0))) {
        x = -xx;
    } else {
        x = xx;
    }

    // 顺序加入buf中
    i = 0;
    do {
        // 按进制转换先存入余数也就是数字低位，也就是不够进制的部分
        buf[i++] = digits[x % base];
        // 然后整除进制，取出高位，再重复，直到除尽
    } while ((x /= base) != 0);

    // 如果有符号，则加负号
    if (sign) {
        buf[i++] = '-';
    }
    // 从右向左输出
    while (--i >= 0) {
        console_putc(buf[i]);
    }
}

void printchar(char c) {
    console_putc(c);
}

void printlong(long xx, int base, int sign) {
    char buf[24];
    int i;
    uint64_t x;

    if (sign && (sign = xx < 0)) {
        x = -xx;
    } else {
        x = xx;
    }

    // 顺序加入buf中
    i = 0;
    do {
        // 按进制转换先存入余数也就是数字低位，也就是不够进制的部分
        buf[i++] = digits[x % base];
        // 然后整除进制，取出高位，再重复，直到除尽
    } while ((x /= base) != 0);

    // 如果有符号，则加负号
    if (sign) {
        buf[i++] = '-';
    }
    // 从右向左输出
    while (--i >= 0) {
        console_putc(buf[i]);
    }
}

static void printptr(uint64_t x) {
    int i;
    console_putc('0');
    console_putc('x');
    for (i = 0; i < (sizeof(uint64_t) * 2); i++, x <<= 4) {
        console_putc(digits[x >> (sizeof(uint64_t) * 8 - 4)]);
    }
}

void printf(char *fmt, ...) {
    va_list ap;
    int i, c;
    int locking;
    char *s;

    locking = pr.locking;
    if (locking) {
        // acquire lock;
    }

    if (fmt == 0) {
        // panic
    }

    va_start(ap, fmt);
    for (i = 0; (c = fmt[i] & 0xff) != '\0'; i++) {
        // 如果开头不是控制符号，则直接输出
        if (c != '%') {
            console_putc(c);
            continue;
        }
        // 如果是控制符则判断控制符分别输出
        c = fmt[++i] & 0xff;
        switch (c) {
        case 'd':
            printint(va_arg(ap, int), 10, 1);
            break;
        case 'l':
            c = fmt[++i] & 0xff;
            if (c == 'd')
                printlong(va_arg(ap, long), 10, 1);
            else if (c == 'x')
                printlong(va_arg(ap, long), 16, 0);
            break;
        case 'x':
            printint(va_arg(ap, int), 16, 0);
            break;
        case 'p':
            printptr(va_arg(ap, uint64_t));
            break;
        case 's':
            if ((s = va_arg(ap, char *)) == 0) {
                s = "(null)";
            }
            while (*s) {
                console_putc(*s++);
            }
            break;
        case 'c':
            printchar(va_arg(ap, int));
            break;
        case '%':
            console_putc('%');
            break;
        default:
            console_putc('%');
            console_putc(c);
            break;
        }
    }
}
