#include "include/alloc.h"
#include "include/bio.h"
#include "include/clock.h"
#include "include/common.h"
#include "include/dtb.h"
#include "include/elf.h"
#include "include/extern_symbol.h"
#include "include/fs.h"
#include "include/global.h"
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

#undef DEBUG
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

char names[MAX_APP_NUM][MAX_STR_LEN];

static inline void app_info() {
    char *s;
    s = _app_names;
    for (int i = 0; i < ((uint64_t *)_app_num)[0]; i++) {
        int len = strlen(s);
        strncpy(names[i], (const char *)s, len);
        s += len + 1;
        Info("name %d addr %x : %s", i, ((uint64_t *)_app_num)[i + 1], names[i]);
    }
}

struct fat32disk disk;
AppFileNames_t global_loader;

int app_loader(AppFileNames_t *afn) {
    if (afn->app_files[afn->idx] != NULL) {
#ifdef DEBUG
        Info("%s", ((struct file *)(afn->app_files[afn->idx]))->lfn_name);
#endif
        int status =
            load_task((void *)((struct file *)afn->app_files[afn->idx])->lfn_name);
        if (status == -1) {
            return -1;
        } else if (status == -2) {
            afn->idx = afn->idx + 2;
            return -2;
        }
        // load_task(
        //                     (void *)((struct file
        //                     *)afn->app_files[afn->idx])->lfn_name)
        afn->idx = afn->idx + 2;
        return 0;
    } else {
        return -1;
    }
}

uint64_t global_hartid = 0;

#undef DEBUG
void kernel_start(uint64_t hartid, uint64_t dtb_pa) {

    clear_bss();
    global_hartid = hartid;

    //    w_tp(hartid);

#ifdef DEBUG
    link_info();
#endif

    init_mm();

    init_trap();
#if DEBUG
    Info("dtb_pa %p", dtb_pa);
#endif

    // init_clock();

    //    app_info();
    process_init();
#if DEBUG
    Warn("process manager init");
#endif

    //  vmappage_test();

    //    map_dtb(kptp, dtb_pa);

#if DEBUG
    Warn("kernel in virmem %p", r_satp());
#endif
    init_virtio();
    // Warn("virtio device init");

    binit();

struct buf *test_buf = bread(1, 0);

    global_loader.idx = 0;
    // test_buf = bread(1, 0);
    //     struct fat32disk *disk = (void *)kalloc(sizeof(struct fat32disk));
    init_fat32((char *)test_buf->data, (uintptr_t)&disk);
    global_loader.idx = 0;
    app_loader(&global_loader);

    //    uint64_t entry = find_free_direntry();
    //    Info("kernel idx %d sector %d", ((struct free_entry *)&entry)->idx,
    //         ((struct free_entry *)&entry)->sector);
    //    list_dir(disk.bpb_info.DataStartSector, NULL, &global_loader);
    //
    //    app_loader(&global_loader);
    //    int fd = open((uintptr_t)&disk, "brk");
    //    char *data = (void *)kalloc(disk.file[fd]->fsize);
    //    read((uintptr_t)&disk, fd, (uintptr_t)data, disk.file[fd]->fsize);
    //    alloc_proc((uintptr_t)data, "brk");
    //    close((uintptr_t)&disk, fd);

    // load_task("brk");
    // load_task("fork");
    // load_task("wait");
    // load_task("gettimeofday");
    // load_task("test_echo");
    // load_task("getpid");
    // load_task("getppid");
    // load_task("read");
    // load_task("uname");
    // load_task("times");
    // load_task("write");
    // load_task("fstat");
    // load_task("dup2");
    // load_task("dup");
    // load_task("exit");
    // load_task("munmap");
    // load_task("mmap");
    // load_task("open");
    // load_task("execve");
    // load_task("clone");
    // load_task("close");
    // load_task("mkdir_");
    // load_task("unlink");
    // load_task("chdir");
    // load_task("openat");
    // load_task("waitpid");
    // load_task("exit");
    // load_task("sleep");
    // load_task("yield");
    // load_task("pipe");
    // parser_dtb(dtb_pa);

    //  1 brk
    //  5 dup
    //  6 dup2
    //  9 fork
    //  10 fstat
    //  13 getpid
    //  14 getppid
    //  15 gettimeofday
    //  23 read
    //  32 write
    //  33 yield
    //  28 uname
    //  25 test_echo
    //  26 times
    //  17 mmap
    //  19 munmap
    //  22 pipe
    //  20 open
    //  11 getcwd
    //  7 execve
    //  3 clone
    //  4 close
    //  16 mkdir_
    //  29 unlink
    //  2 chdir
    //  21 openat
    //  31 waitpid
    //  30 wait
    //  8 exit
    //  24 sleep
    //
    //
    //  12 getdents
    //  18 mount
    //  27 umount

    //    while (1) {
    //    }
    //    TODO:在fork时如果是从u态跳到s态进行fork，会直接page fault
    //    alloc_proc(((uint64_t *)_app_num)[1], names[0]);
    //    alloc_proc(((uint64_t *)_app_num)[15], names[14]);
    //    alloc_proc(((uint64_t *)_app_num)[25], names[24]);
    //    alloc_proc(((uint64_t *)_app_num)[13], names[12]);
    //    alloc_proc(((uint64_t *)_app_num)[14], names[13]);
    //    alloc_proc(((uint64_t *)_app_num)[26], names[25]);
    //    alloc_proc(((uint64_t *)_app_num)[28], names[27]);
    //    alloc_proc(((uint64_t *)_app_num)[9], names[8]);
    //    alloc_proc(((uint64_t *)_app_num)[33], names[32]);
    //    alloc_proc(((uint64_t *)_app_num)[23], names[22]);
    Warn("kernel start success");

    sched();

    if (get_current_process() != NULL) {

        extern void _alltrap();
        write_csr(stvec, (uint64_t)_alltrap & ~0x3);
        extern void _trap_restore(uintptr_t satp, uintptr_t context);
        _trap_restore(get_current_process()->pcb.context->csr_regs.satp,
                      (uintptr_t)get_current_process()->pcb.context);
    }
    Info("should not here");

    shutdown();
}
