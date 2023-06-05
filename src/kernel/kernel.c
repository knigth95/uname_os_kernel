#include "include/alloc.h"
#include "include/bio.h"
#include "include/clock.h"
#include "include/dtb.h"
#include "include/elf.h"
#include "include/extern_symbol.h"
#include "include/fs.h"
#include "include/log.h"
#include "include/mm.h"
#include "include/page_table.h"
#include "include/plic.h"
#include "include/printf.h"
#include "include/proc.h"
#include "include/riscv.h"
#include "include/sbi.h"
#include "include/string.h"
#include "include/trap.h"
#include "include/type.h"
#include "include/uart.h"
#include "include/virtio.h"
#include "include/vm.h"

static inline void link_info() {
    Info("s_kernel -> e_kernel : %p -> %p", s_kernel, e_kernel);
    Info("s_text -> e_text : %p -> %p", s_text, e_text);
    Info("s_rodata -> e_rodata : %p -> %p", s_rodata, e_rodata);
    Info("s_data -> e_data : %p -> %p", s_data, e_data);
    Info("s_bss -> e_bss : %p -> %p", s_bss, e_bss);
    Info("boot_stack -> boot_stack_top : %p -> %p", boot_stack, boot_stack_top);
    Info("s_mempry -> e_memory : %p -> %p", s_memory, e_memory);
}

static inline void clear_bss() {
    memset(s_bss, 0, (uint64_t)e_bss - (uint64_t)s_bss);
}

static inline void shutdown() {
    sbi_shutdown();
    Info("it should not be here");
    while (1) {
    }
}

static inline uint64_t r_satp() {
    uint64_t x;
    asm volatile("csrr %0, satp" : "=r"(x));
    return x;
}

// char names[MAX_APP_NUM][MAX_STR_LEN];

// static inline void app_info() {
//     char *s;
//     s = _app_names;
//     for (int i = 0; i < ((uint64_t *)_app_num)[0]; i++) {
//         int len = strlen(s);
//         strncpy(names[i], (const char *)s, len);
//         s += len + 1;
//         Info("name %d addr %x : %s", i, ((uint64_t *)_app_num)[i + 1],
//         names[i]);
//     }
// }

struct fat32disk disk;

void kernel_start(uint64_t hartid, uint64_t dtb_pa) {

    w_tp(hartid);

    Info("hartid %d", hartid);

    clear_bss();

    link_info();

    init_mm();

    init_trap();
    Info("dtb_pa %p", dtb_pa);

    // init_clock();

    //    app_info();
    process_init();
    Warn("process manager init");

    //  vmappage_test();

    //    map_dtb(kptp, dtb_pa);

    Warn("kernel in virmem %p", r_satp());
    init_virtio();
    //    init_virtio();
    // Warn("virtio device init");

    binit();

struct buf *test_buf = bread(1, 0);
    // Info("%x", test_buf->data[0]);
    // Info("%x", test_buf->data[1]);
    // Info("%x", test_buf->data[2]);
    // Info("%x", test_buf->data[3]);
    // Info("%x", test_buf->data[4]);

    // test_buf = bread(1, 0);
    // struct fat32disk *disk = (void *)kalloc(sizeof(struct fat32disk));
    init_fat32((char *)test_buf->data, (uintptr_t)&disk);

    // int fd = open((uintptr_t)disk, "text.txt");
    // Info("fd %d", fd);

    // char data[512];
    // read((uintptr_t)disk, fd, (uintptr_t)data, 53);
    // Info("%s", data);
    //  parser_dtb(dtb_pa);

    // while (1) {
    // }
    //   TODO:在fork时如果是从u态跳到s态进行fork，会直接page fault
    //    alloc_proc(((uint64_t *)_app_num)[1], names[0]);
    //    alloc_proc(((uint64_t *)_app_num)[15], names[14]);
    //    alloc_proc(((uint64_t *)_app_num)[25], names[24]);
    //    alloc_proc(((uint64_t *)_app_num)[13], names[12]);
    //    alloc_proc(((uint64_t *)_app_num)[14], names[13]);
    //    alloc_proc(((uint64_t *)_app_num)[26], names[25]);
    //    alloc_proc(((uint64_t *)_app_num)[28], names[27]);
    //    alloc_proc(((uint64_t *)_app_num)[9], names[8]);
    //    alloc_proc(((uint64_t *)_app_num)[33], names[32]);
    Warn("kernel start success");

    sched();

    if (get_current_process() != NULL) {
        extern void _trap_restore(uintptr_t satp, uintptr_t context);
        _trap_restore(get_current_process()->pcb.context->csr_regs.satp,
                      (uintptr_t)get_current_process()->pcb.context);
    }

    shutdown();
}
