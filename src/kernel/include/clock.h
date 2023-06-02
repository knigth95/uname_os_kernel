#ifndef __CLOCK_H__
#define __CLOCK_H__

#include "type.h"

#define CLOCK_FREQ 12500000

/// The number of ticks per second
#define TICKS_PER_SEC 100
/// The number of milliseconds per second
#define MSEC_PER_SEC 1000

struct tms {
    uint64_t tms_utime;  /* user time  cpu time*/
    uint64_t tms_stime;  /* system time  all time */
    uint64_t tms_cutime; /* user time of children */
    uint64_t tms_cstime; /* system time of children */
};

typedef struct {
    uint64_t sec;  // 自 Unix 纪元起的秒数
    uint64_t usec; // 微秒数
} TimeVal;
//	sec = time / CLOCK_FREQ;
//	usec = (time % CLOCK_FREQ) * 1000000 / CLOCK_FREQ;

uint64_t get_time();
void init_clock();
void set_next_time_interrupt();
#endif
