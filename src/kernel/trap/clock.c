#include "include/clock.h"
#include "include/log.h"
#include "include/riscv.h"
#include "include/sbi.h"

uint64_t get_time() {
    uint64_t time;
    asm volatile("csrr %0, time" : "=r"(time));
    return time;
}

static inline uint64_t get_time_ms() {
    return get_time() / (CLOCK_FREQ / MSEC_PER_SEC);
}

void set_next_time_interrupt() {
    sbi_set_timer(get_time() + CLOCK_FREQ / TICKS_PER_SEC);
}

// static uint64_t timebase = 10000000;

// void set_next_time_interrupt() {
//     sbi_set_timer(get_time() + timebase);
// }

void init_clock() {
    set_next_time_interrupt();
    Info("clock init");
}
