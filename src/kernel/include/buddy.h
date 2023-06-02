#ifndef __BUDDY_H__
#define __BUDDY_H__

#include "list.h"
#include "type.h"

#define MAX_ORDER 12
#define BUDDY_PAGE_SIZE 0x1000

typedef struct mem_pool mem_pool_t;

typedef struct page {
    // 串起来伙伴页
    list_head_t node;
    // 伙伴页的秩
    uint32_t order;
    // 是否已分配
    uint8_t allocated;
    // 所属的物理内存池
    mem_pool_t *phys_mem_pool;
} page_t;

typedef struct free_list {
    list_head_t head;
    uint64_t free_page_num;
} free_list_t;

typedef struct mem_pool {
    // 池起始地址
    uint64_t mem_start;
    //    // 池结束地址
    //    uint64_t mem_end;
    // 池数据起始地址
    uint64_t data_start;
    // 池大小
    uint64_t mem_size;
    // 元数据起始地址
    page_t *meta_data_start;
    // 元数据结束地址，永不取到结束地址
    uint64_t meta_data_end;
    // 元数据大小
    uint64_t meta_data_size;
    // 元数据单页大小
    uint64_t meta_data_page_size;
    // 池0秩总页数
    uint64_t page_num;
    // 页大小
    uint64_t page_size;
    // 空闲链表
    free_list_t free_lists[MAX_ORDER];
} mem_pool_t;

void init_mem_pool(mem_pool_t *mem, uint64_t mem_start, page_t *meta_data_start,
                   uint64_t meta_data_page_num, uint64_t page_num,
                   uint64_t page_size);

page_t *buddy_alloc_page(int order, mem_pool_t *mem);

void buddy_free_page(page_t *page);

void buddy_merge_page(page_t *page);

page_t *buddy_split_page(page_t *page);

void page_add_inlist(page_t *new_page);

void page_del_from_list(page_t *page);

void mem_freelist_info(mem_pool_t *mem);

uintptr_t buddy_page_to_paddr(page_t *page);

page_t *buddy_paddr_to_page(mem_pool_t *mem, uintptr_t addr);
#endif
