#include "include/queue.h"
#include "include/log.h"
#include "include/type.h"

#define NPROC 512

void init_queue(struct queue *q) {
    q->front = q->tail = 0;
    q->empty = 1;
    q->avail_num = 0;
}

void push_queue(struct queue *q, uintptr_t value) {
    if (!q->empty && q->front == q->tail) {
        Error("queue shouldn't be overflow");
    }
    q->empty = 0;
    q->data[q->tail] = value;
    q->tail = (q->tail + 1) % NPROC;
    q->avail_num += 1;
}

uintptr_t pop_queue(struct queue *q) {
    if (q->empty)
        return NULL;
    uintptr_t value = q->data[q->front];
    q->data[q->front] = 0;
    q->front = (q->front + 1) % NPROC;
    q->avail_num -= 1;
    if (q->front == q->tail)
        q->empty = 1;
    return value;
}
