#ifndef __MM_H__
#define __MM_H__

#include "include/buddy.h"
#include "include/type.h"

extern mem_pool_t global_mem;
void init_mm();

void mem_pool_info();

void buddy_page_alloc_test_control(mem_pool_t *mem, uint64_t page_num);
#endif
