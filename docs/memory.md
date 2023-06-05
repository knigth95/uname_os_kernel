# 内存管理

## 启动

对于每个 CPU 启动时，他们处在 M 级别。在将控制权交给操作系统时，转换为 S 级别。

在 `init_mm()` 中我们会对内核页表进行初始化，并建立虚拟地址与物理地址之间的映射。

我们会在 `init_mm()` 中调用 `mem_pool_init()、init_mem_pool()` 两个函数，在这两个函数中我们分映射别做：

- 初始化物理页控制块并设置物理页为4096字节。
- 构造物理页和物理地址之间的映射。

物理地址分配关系：在物理地址空间中，位于 0x8000_0000 下方的一些是专门用于与外设交互的内存。 OpenSBI 与 U-Boot 位于 0x8000_0000 处，即内存的开始位置。内核则位于 0x8020_0000 处，在启动时 U-Boot 会将内核加载到 0x8020_0000 这个物理地址处。

在 `kernelEnd` 到 `PHYSICAL_MEMORY_TOP` 之间的这一部分物理内存，则被用来分配给用户程序，或者申请作为页表等其它用处。

```c
PHYSICAL_MEMORY_TOP-> +----------------------------+----
                      |                            |     
                      |    Free Physical memory    |    
                      |                            |                         
   kernelEnd   -----> +----------------------------+----
                      |                            |                         
                      |          Kernel            |    
                      |                            |                           
 0x8020 0000   -----> +----------------------------+----
                      |                            |                           
                      |         Open SBI           |    
                      |                            |                 
 0x8000 0000  ----->  +----------------------------+----
                      |                            |                           
                      |                            |                           
                      |                            |                           
                      +----------------------------+---
                      |                            |                           
                      |           MMIO             |                
                      |                            |                           
                      +----------------------------+----
                      |                            |                           
                      |                            |                           
                      |                            |                           
                      +----------------------------+                           

```

### 物理页控制块

```c
// 物理页控制块
typedef struct page {
    // 串起来伙伴页
    list_head_t node;
    // 伙伴页的秩
    uint32_t order;
    // 是否已分配
    uint8_t allocated;
    // 所属的物理内存池
    mem_pool_t *phys_mem_pool;
} page_t;;
```

### 初始化物理页控制块

```c
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
```

### 维护空闲链表

空闲链表表我们采用双链表的形式，提供`page_add_inlist(...)`和`page_del_from_list(...)`用于操作特定块大的链接表。前者用于向链表表头部添加一个块，而后者用于从链表中删除一个块。`buddy_split_page(...)`用于将一个大的块拆成比order小的大的两半。

### 链表添加块
```c
void page_add_inlist(page_t *new_page) {
    mem_pool_t *mem = new_page->phys_mem_pool;
    list_head_t *list_head = &mem->free_lists[new_page->order].head;
    mem->free_lists[new_page->order].free_page_num += 1;
    list_add(&new_page->node, list_head);
}
```
### 链表删除块
```c
void page_del_from_list(page_t *page) {
    mem_pool_t *mem = page->phys_mem_pool;
    mem->free_lists[page->order].free_page_num -= 1;
    list_del(&page->node);
}
```
### 内核态地址空间

`mem_pool_init(...)`在系统启动期间在内核空间中初始化。函数`buddy_paddr_to_page(...)`获取页面的物理地址并返回页面结构的逻辑地址。该地址位于内存池的元数据部分，这是内核空间中用于管理内存分配和释放的保留区域。元数据部分由如下结构定义：
```c
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
```
我们采用逻辑页面结构并返回相应的物理地址。函数`buddy_page_to_paddr(...)`用于将页面结构的逻辑地址转换为其对应的物理地址，从而允许内核访问该页面的数据。

#### 根据元数据的偏移量和真实数据的偏移量计算实际内存地址
```c
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
```
#### 内核地址映射
```c
void kvmmap(uintptr_t ptp_addr) {
    vaddr va;
    paddr pa;
    uint64_t size;
    pte_flag_t flag;
    ptp_t *kptp = (void *)PADDR(ptp_addr).addr;

    // text r-x
    va.addr = (uint64_t)s_text;
    pa.addr = (uint64_t)s_text;
    size = (uint64_t)e_text - (uint64_t)s_text;
    flag.flag = FLAG_V | FLAG_X | FLAG_R;
    vmappage(kptp, va.addr, pa.addr, size, flag);
    Info("vmmap text seg start %p end %p size %d va %p -> pa %p", s_text, e_text,
         size, va.addr, va2pa(kptp, va.addr));

    // rodata r--
    va.addr = (uint64_t)s_rodata;
    pa.addr = (uint64_t)s_rodata;
    size = (uint64_t)e_rodata - (uint64_t)s_rodata;
    flag.flag = FLAG_V | FLAG_R;
    vmappage(kptp, va.addr, pa.addr, size, flag);
    Info("vmmap rodata seg start %p end %p size %d va %p -> pa %p", s_rodata,
         e_rodata, size, va.addr, va2pa(kptp, va.addr));

    // data rw-
    va.addr = (uint64_t)s_data;
    pa.addr = (uint64_t)s_data;
    size = (uint64_t)e_data - (uint64_t)s_data;
    flag.flag = FLAG_V | FLAG_R | FLAG_W;
    vmappage(kptp, va.addr, pa.addr, size, flag);
    Info("vmmap data seg start %p end %p size %d va %p -> pa %p", s_data, e_data,
         size, va.addr, va2pa(kptp, va.addr));

    // bss rw-
    va.addr = (uint64_t)e_data;
    pa.addr = (uint64_t)e_data;
    size = (uint64_t)e_bss - (uint64_t)e_data;
    flag.flag = FLAG_V | FLAG_R | FLAG_W;
    vmappage(kptp, va.addr, pa.addr, size, flag);
    Info("vmmap bss seg start %p end %p size %d va %p -> pa %p", e_data, e_bss,
         size, va.addr, va2pa(kptp, va.addr));
}
```

## 创建页表

对于每一个页表，我们调用`palloc(...)`函数分配内存页。该函数的参数是需要分配的字节数，会自动计算所需要的页数，以4KB来对齐。
```c
uintptr_t palloc(uint64_t size) {
    uint64_t order = (size >> 12);
    order = powers(order);
    page_t *page = buddy_alloc_page(order, &global_mem);
    return buddy_page_to_paddr(page);
}
```
在`palloc(...)`中，会根据数据页的大来计算对应的阶数，即使用`powers(...)`函数。该函数会根据给定的数值，返回最小的大等等于此数值的 2 的指数次幂，用来确定此页应位于伙伴系统中的哪一部分。
随后调用`buddy_alloc_page(...)`随机数根据计算的阶数，在伙伴系统中分配对应的页面。该随机数会在伙伴系统中寻找大的小符合要求的空余页，将其标记为已使用，并返回返回页的地址。
```c
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
```



