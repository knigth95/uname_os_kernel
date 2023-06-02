#ifndef __QUEUE_H__
#define __QUEUE_H__
#define QUEUE_SIZE (1024)

#include "include/type.h"

// TODO: change the queue to a priority queue sorted by priority

typedef struct queue {
    uintptr_t data[QUEUE_SIZE];
    int front;
    int tail;
    int empty;
} Queue_t;

void init_queue(struct queue *);
void push_queue(struct queue *, uintptr_t);
uintptr_t pop_queue(struct queue *);

#endif
