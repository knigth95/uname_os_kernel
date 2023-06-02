#ifndef __ALLOC_H__
#define __ALLOC_H__
#include "include/type.h"

uintptr_t palloc(uint64_t size);

uintptr_t page4K_alloc();
uintptr_t page2M_alloc();
uintptr_t page1G_alloc();

void pfree(uintptr_t addr);

uintptr_t kalloc(uint64_t size);
uintptr_t vmalloc(uint64_t size, uintptr_t ptp);
#endif
