#include "include/mm.h"
#include "include/alloc.h"
#include "include/buddy.h"
#include "include/common.h"
#include "include/extern_symbol.h"
#include "include/log.h"

mem_pool_t global_mem;

void buddy_page_alloc_test(mem_pool_t *mem, uint64_t page_num,
                           uint64_t page_order) {
    Info("mem alloc test page num %d page prder %d", page_num, page_order);
    uintptr_t pages[page_num];
    int page_idx = 0;

    mem_freelist_info(mem);
    for (page_idx = 0; page_idx < page_num; page_idx++) {
        uintptr_t page = kalloc((1 << (12 + page_order)));
        //        void *page = buddy_alloc_page(page_order, mem);
        if (page != NULL) {
            pages[page_idx] = page;
            Info("page %d alloc addr %p", page_idx, pages[page_idx]);
        } else {
            Error("alloc failed page idx %d", page_idx);
            break;
        }
    }
    page_idx -= 1;
    mem_freelist_info(mem);
    Info("page free test %d", page_idx);
    for (; page_idx >= 0; page_idx--) {
        pfree(pages[page_idx]);
        //        buddy_free_page(mem, (page_t *)pages[page_idx]);
        Info("page free addr %p idx %d", pages[page_idx], page_idx);
    }
    mem_freelist_info(mem);
    Info("");
    Info("");
}

void buddy_page_alloc_test_control(mem_pool_t *mem, uint64_t page_num) {
    for (uint64_t i = 0; i < 11; i++) {
        buddy_page_alloc_test(mem, page_num / (1 << i), i);
    }
}

void mem_pool_init(uint64_t mem_start_addr, uint64_t mem_end_addr,
                   uint64_t page_size, mem_pool_t *mem, uint64_t *page_num) {
    uint64_t mem_size = mem_end_addr - mem_start_addr;
    uint64_t mem_page_num = mem_size / page_size;
    uint64_t page_meta_data_bytes = mem_page_num * sizeof(page_t);
    uint64_t page_meta_data_pagenum = page_meta_data_bytes % page_size == 0
                                      ? page_meta_data_bytes / page_size
                                      : page_meta_data_bytes / page_size + 1;
    page_meta_data_bytes = page_meta_data_pagenum * page_size;
    mem_page_num = (mem_size - page_meta_data_bytes) / page_size;
    if (page_num != NULL) {
        *page_num = mem_page_num;
    }
    init_mem_pool(mem, mem_start_addr, (void *)mem_start_addr,
                  page_meta_data_pagenum, mem_page_num, page_size);
}

void mem_pool_info() {
    Info("mem start %p", global_mem.mem_start);
    Info("data start %p", global_mem.data_start);
    Info("mem size %p", global_mem.mem_size);
    Info("meta data start %p", global_mem.meta_data_start);
    Info("meta data end %p", global_mem.meta_data_end);
    Info("meta data size %p", global_mem.meta_data_size);
    Info("meta data page size %p", global_mem.meta_data_page_size);
    Info("page num %p", global_mem.page_num);
    Info("page size %p", global_mem.page_size);
}

void init_mm() {
#define PAGE_SIZE 4096
    uint64_t mem_page_num = 0;
    mem_pool_init((uint64_t)s_memory, (uint64_t)e_memory, PAGE_SIZE, &global_mem,
                  &mem_page_num);
#undef DEBUG
#ifdef DEBUG
    mem_pool_info();
#endif
    // buddy_page_alloc_test_control(&global_mem, mem_page_num);
}
