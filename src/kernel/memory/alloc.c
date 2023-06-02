#include "include/alloc.h"
#include "include/buddy.h"
#include "include/common.h"
#include "include/log.h"
#include "include/page_table.h"
#include "include/proc.h"
#include "include/string.h"
#include "include/type.h"
#include "include/vm.h"

extern mem_pool_t global_mem;

uintptr_t realloc(uintptr_t old_address, uint32_t new_length) {
    uintptr_t new_address = 0;
    new_address = kalloc(new_length);
    memmove((void *)new_address, (void *)old_address, new_length);
    pfree(old_address);
    return new_address;
}

// 分配页的同时做好等值映射
uintptr_t vmalloc(uint64_t size, uintptr_t ptp) {
    uintptr_t ptr = kalloc(size);
    vmap(ptp, ptr, ptr, size, FLAG_V | FLAG_R | FLAG_W | FLAG_X);
    return ptr;
}

// 内核分配不定size的内存，由于内核中使用的内存实际并不受限与内存管理系统，所以需要每次alloc都重置为0，否则可能会有无法预料的bug
uintptr_t inline kalloc(uint64_t size) {
    uintptr_t ptr = palloc(PALIGN_UP(size, 4096));
    memset((void *)ptr, 0, PALIGN_UP(size, 4096));

    return ptr;
}

uintptr_t palloc(uint64_t size) {
    uint64_t order = (size >> 12);
    order = powers(order);
    page_t *page = buddy_alloc_page(order, &global_mem);
    return buddy_page_to_paddr(page);
}

// 释放内存
void pfree(uintptr_t addr) {
    //    uintptr_t real_addr =
    //        va2pa((void *)get_current_process()->pcb.ptp_addr, addr);
    page_t *page = buddy_paddr_to_page(&global_mem, addr);
    buddy_free_page(page);
}

// 内核分配固定4K大小页
uintptr_t page4K_alloc() {
    uintptr_t addr = kalloc(4096);
    return addr;
}

// 内核分配2M页
uintptr_t page2M_alloc() {
    uintptr_t addr = kalloc(4096 * 512);
    return addr;
}

// 内核分配1G页
uintptr_t page1G_alloc() {
    uintptr_t addr = kalloc(4096 * 512 * 512);
    return addr;
}
