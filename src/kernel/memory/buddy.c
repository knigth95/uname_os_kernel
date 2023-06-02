#include "include/buddy.h"
#include "include/list.h"
#include "include/log.h"
#include "include/macro.h"
#include "include/mm.h"
#include "include/type.h"

#undef DEBUG
//     TODO:
//     伙伴系统（尝试不按照4KB分页，可以按照4B分页，限制最大页）支持，slab支持
//
//     计算边界的时候，左边界可以等于，右边界不能等于，所有x<mem_end and
//     x>=mem_start，因为右边界等于之后，数据会以右边界为起始，写到右边界外
static page_t *buddy_get_buddy_chunk(page_t *page) {
    int order = page->order;
    mem_pool_t *mem = page->phys_mem_pool;
    page_t *buddy_page;

// page_t的大小是32字节，也就是1<<5 加上order的倍数
#define PAGE_METADATA_ORDER (5)
    // 找到对称的元数据
    buddy_page =
        (void *)(((uint64_t)page) ^ (1 << (PAGE_METADATA_ORDER + order)));

    // 利用mem pool限制metadata的数据范围，并且根据order判断是否为伙伴块
    if ((uint64_t)buddy_page >= mem->meta_data_end ||
            buddy_page < mem->meta_data_start || buddy_page->order != page->order) {
#ifdef DEBUG
        Debug("buddy page %p order %d page %p order %d", buddy_page,
              buddy_page->order, page, page->order);
#endif
        return NULL;
    }
    return buddy_page;
}

void init_mem_pool(mem_pool_t *mem, uint64_t mem_start, page_t *meta_data_start,
                   uint64_t meta_data_page_num, uint64_t page_num,
                   uint64_t page_size) {
    int page_idx = 0;
    page_t *page;

    // 设置可用内存总页数，单页大小
    mem->mem_start = mem_start;
    mem->page_num = page_num;
    mem->page_size = page_size;

    // 设置页元数据起始地址，单页元数据大小，页元数据总大小
    mem->meta_data_start = meta_data_start;
    mem->meta_data_page_size = sizeof(page_t);
    mem->meta_data_size = mem->page_num * mem->meta_data_page_size;
    // 用于判断是否到达元数据终点，因此必须严格按照metadata page size和pagenum计算
    mem->meta_data_end = mem->mem_start + mem->meta_data_size;

    // 设置可用内存大小以及可用内存起始地址
    mem->mem_size = mem->page_num * mem->page_size;
    mem->data_start = mem_start + meta_data_page_num * mem->page_size;

#ifdef DEBUG
    mem_pool_info();
#endif

    // 初始化头指针
    for (int i = 0; i < MAX_ORDER; i++) {
        list_head_init(&(mem->free_lists[i].head));
        mem->free_lists[i].free_page_num = 0;
    }

    // 初始化所有页元数据
    for (page_idx = 0; page_idx < page_num; page_idx++) {
        page = &mem->meta_data_start[page_idx];
        page->allocated = 1;
        page->order = 0;
        page->phys_mem_pool = mem;
    }

    // 合并所有页
    for (page_idx = 0; page_idx < page_num; page_idx++) {
        page = &mem->meta_data_start[page_idx];
#ifdef DEBUG
        Debug("page %d free page addr %p", page_idx, page);
#endif
        buddy_free_page(page);
    }
    mem_freelist_info(mem);
}

void mem_freelist_info(mem_pool_t *mem) {
    list_head_t *head;
    for (int order_idx = 0; order_idx < MAX_ORDER; order_idx++) {
        Info("order %d list have %d free pages, head page addr %p", order_idx,
             mem->free_lists[order_idx].free_page_num,
             &mem->free_lists[order_idx].head);
        for (head = mem->free_lists[order_idx].head.next;
                head != (void *)&mem->free_lists[order_idx].head; head = head->next) {
            Info("page %d addr %p page order -> %d", order_idx, head,
                 ((page_t *)head)->order);
        }
    }
}

// 除了内存初始化的环境，其他的环境下都需要对操作的指针判断是否为空
page_t *buddy_alloc_page(int order, mem_pool_t *mem) {
    //    mem_freelist_info(mem);
    int order_idx = 0;
    page_t *page;
    for (order_idx = 0; order_idx < MAX_ORDER; order_idx++) {
        if (mem->free_lists[order_idx].free_page_num == 0 || order_idx < order) {
            continue;
        } else {
            break;
        }
    }

#ifdef DEBUG
    Debug("order %d", order_idx);
#endif
    if (order_idx == MAX_ORDER) {
        Error("page idx full");
        return NULL;
        // TODO:error mem alloc error
    }

    // 暂时选中page
    page = (void *)mem->free_lists[order_idx].head.next;
    //    page = container_of(&mem->free_lists[order_idx].head.next, page_t,
    //    node);

    while (page != NULL) {
        if (page->order == order) {
            break;
        }
        page = buddy_split_page(page);
    }

    if (page == NULL) {
        Error("page split failed");
        // TODO:panic
        return NULL;
    }

    page->allocated = 1;
    page_del_from_list(page);

    return page;
}

void buddy_free_page(page_t *page) {
    mem_pool_t *mem = page->phys_mem_pool;

    // 没分配的块，或者是不属于元数据的块，不做free处理
    if (page->allocated == 0 || (uint64_t)page >= mem->meta_data_end ||
            page < mem->meta_data_start) {
#ifdef DEBUG
        Error("page free failed");
#endif
        return;
    }

    // 将所有子页都free
    uint64_t pages = (1 << page->order);
    for (uint64_t page_idx = 0; page_idx < pages; page_idx++) {
        page[page_idx].allocated = 0;
    }

    // 插入目前的链表
    page_add_inlist(page);
    // 合并块
    buddy_merge_page(page);
}

void buddy_merge_page(page_t *page) {
    if (page->order == MAX_ORDER - 1) {
        return;
    }
    page_t *buddy_page = buddy_get_buddy_chunk(page);

    // 递归终点，如果没有伙伴页或者伙伴页已分配不在链表中
    if (buddy_page == NULL || buddy_page->allocated == 1) {
        return;
    }

    // 从各自链表中摘下
    page_del_from_list(page);
    page_del_from_list(buddy_page);

    // 判断将两片中左边的一片作为头
    // 不应该改变伙伴块的order，因为伙伴块依然与原本的page的order为伙伴，现在的page块有了新的伙伴，因为order变化会导致伙伴的变化
    if (buddy_page > page) {
        page->order += 1;
        page_add_inlist(page);
#ifdef DEBUG
        Debug("merge page %p order %d", page, page->order);
#endif
        buddy_merge_page(page);
    } else {
        buddy_page->order += 1;
        page_add_inlist(buddy_page);
#ifdef DEBUG
        Debug("merge page %p order %d", buddy_page, buddy_page->order);
#endif
        buddy_merge_page(buddy_page);
    }
}

page_t *buddy_split_page(page_t *page) {
    if (page->allocated == 1 || page->order == 0) {
        return NULL;
    }
    // 从链表中取下page
    page_del_from_list(page);
    // 改变order，用于改变目标伙伴
    page->order -= 1;

    // 算出伙伴块地址
    page_t *buddy_page = buddy_get_buddy_chunk(page);
    if (buddy_page == NULL || buddy_page->allocated == 1) {
        // 如果allocated==1说明内存管理出错了，因为一个完整的块所处在一个确定秩的链表中，他分裂的伙伴块一定是空闲的
#ifdef DEBUG
        Info("buddy page %p allocated %d", buddy_page);
#endif
        // 如果出错就放回去
        page->order += 1;
        page_add_inlist(page);
        // 这里存在可能的bug，如果放回去，则返回了NULL，如果是NULL，并不意味者内存已满，只是split出错，虽然理论上将不会split出错，但是还是需要处理为NULL的情况，增加容错性
        return NULL;
    }

    // 没出错就放到新的order的链表中
    page_add_inlist(page);
    page_add_inlist(buddy_page);

    // TODO:这部分有待改进，正确的思路应该是当前空闲链表没有空闲，则order的空闲链表从表头摘下一块分开插入order链表中，如果order+1还不行就递归操作，现在只是单纯把页分一下可能会更严重的造成内存碎片
    if (buddy_page > page) {
        return page;
    } else {
        return buddy_page;
    }
    // 为什么要比较地址呢，是因为涉及到奇数块和偶数块的问题，为了方便，统一使用第一块，有空再做验证，统一使用两块伙伴块的左边块
}

void page_add_inlist(page_t *new_page) {
    mem_pool_t *mem = new_page->phys_mem_pool;
    list_head_t *list_head = &mem->free_lists[new_page->order].head;
    mem->free_lists[new_page->order].free_page_num += 1;
    list_add(&new_page->node, list_head);
}

void page_del_from_list(page_t *page) {
    mem_pool_t *mem = page->phys_mem_pool;
    mem->free_lists[page->order].free_page_num -= 1;
    list_del(&page->node);
}

// 根据元数据的偏移量和真实数据的偏移量计算实际内存地址
uintptr_t buddy_page_to_paddr(page_t *page) {
    mem_pool_t *mem = page->phys_mem_pool;
    uint64_t page_idx = ((uint64_t)page - (uint64_t)mem->meta_data_start) /
                        mem->meta_data_page_size;
    uintptr_t addr;
    addr = (uint64_t)mem->data_start + page_idx * mem->page_size;
    return addr;
}

page_t *buddy_paddr_to_page(mem_pool_t *mem, uintptr_t addr) {
    uint64_t addr_idx =
        ((uint64_t)addr - (uint64_t)mem->data_start) / mem->page_size;
    page_t *page = (void *)((uint64_t)mem->meta_data_start +
                            addr_idx * mem->meta_data_page_size);
    return page;
}
