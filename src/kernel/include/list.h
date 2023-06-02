#ifndef __LIST_H__
#define __LIST_H__

#include "log.h"
#include "type.h"

static inline void panic() {
    while (1) {
    }
}

typedef struct list_head list_head_t;
typedef struct list_head {
    list_head_t *prev;
    list_head_t *next;
} list_head_t;

static inline void list_head_init(list_head_t *new_list) {
    new_list->next = new_list;
    new_list->prev = new_list;
}

static inline void list_add(list_head_t *new_node, list_head_t *head) {
    // TODO:
    // 判断地址是否为空
    new_node->next = head->next;
    new_node->prev = head;
    head->next->prev = new_node;
    head->next = new_node;
}

static inline void list_append(list_head_t *new_node, list_head_t *head) {
    list_head_t *tail = head->prev;
    return list_add(new_node, tail);
}

static inline void list_del(list_head_t *node) {
    node->prev->next = node->next;
    node->next->prev = node->prev;
}

// 1 is empty 0 is not empty
static inline char list_empty(list_head_t *head) {
    return (head->prev == head && head->next == head);
}

#endif
