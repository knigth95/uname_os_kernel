#include "include/trap.h"
#include "include/clock.h"
#include "include/log.h"
#include "include/platform.h"
#include "include/plic.h"
#include "include/proc.h"
#include "include/riscv.h"
#include "include/sbi.h"
#include "include/syscall.h"
#include "include/syscall_ids.h"
#include "include/uart.h"
#include "include/virtio.h"
#include "include/vm.h"

void *smod_software_interrupt(struct Regs *regs, const char *name);
void *smod_time_interrupt(struct Regs *regs, const char *name);
void *smod_outside_intertupt(struct Regs *regs, const char *name);

void *smod_instructions_not_aligned(struct Regs *regs, const char *name);
void *smod_instruction_access_exception(struct Regs *regs, const char *name);
void *smod_invalid_command(struct Regs *regs, const char *name);
void *smod_breakpoint(struct Regs *regs, const char *name);
void *smod_load_access_exception(struct Regs *regs, const char *name);
void *smod_storage_address_not_aligned(struct Regs *regs, const char *name);
void *smod_storage_address_access_exception(struct Regs *regs,
        const char *name);
void *smod_user_syscall(struct Regs *regs, const char *name);
void *smod_instructions_page_fault(struct Regs *regs, const char *name);
void *smod_load_page_fault(struct Regs *regs, const char *name);
void *smod_store_page_fault(struct Regs *regs, const char *name);
void *smod_non(struct Regs *regs, const char *name);

static const struct TrapTagJumpTable interrupt_jump_table[] = {
    {smod_non, "none"}, {smod_software_interrupt, "smod_software_interrupt"},
    {smod_non, "none"}, {smod_non, "none"},
    {smod_non, "none"}, {smod_time_interrupt, "smod_timer_interrupt"},
    {smod_non, "none"}, {smod_non, "none"},
    {smod_non, "none"}, {smod_outside_intertupt, "smod_outside_intertupt"},
    {smod_non, "none"}, {smod_non, "none"},
};

static const struct TrapTagJumpTable exception_jump_table[] = {
    {smod_instructions_not_aligned, "instructions_not_aligned"},
    {smod_instruction_access_exception, "instruction_access_exception"},
    {smod_invalid_command, "invalidque ye_command"},
    {smod_breakpoint, "breakpoint"},
    {smod_non, "non"},
    {smod_load_access_exception, "load_access_exception"},
    {smod_storage_address_not_aligned, "storage_address_not_aligned"},
    {smod_storage_address_access_exception, "storage_address_access_exception"},
    {smod_user_syscall, "user_syscall"},
    {smod_non, "non"},
    {smod_non, "non"},
    {smod_non, "non"},
    {smod_instructions_page_fault, "instructions_page_fault"},
    {smod_load_page_fault, "load_page_fault"},
    {smod_non, "non"},
    {smod_store_page_fault, "store_page_fault"},
};

static const struct SyscallJumpTable syscall_jump_table[] = {
    {func_SYS_io_setup, 0, 0},
    {func_SYS_io_destroy, 1, 1},
    {func_SYS_io_submit, 2, 2},
    {func_SYS_io_cancel, 3, 3},
    {func_SYS_io_getevents, 4, 4},
    {func_SYS_setxattr, 5, 5},
    {func_SYS_lsetxattr, 6, 6},
    {func_SYS_fsetxattr, 7, 7},
    {func_SYS_getxattr, 8, 8},
    {func_SYS_lgetxattr, 9, 9},
    {func_SYS_fgetxattr, 10, 10},
    {func_SYS_listxattr, 11, 11},
    {func_SYS_llistxattr, 12, 12},
    {func_SYS_flistxattr, 13, 13},
    {func_SYS_removexattr, 14, 14},
    {func_SYS_lremovexattr, 15, 15},
    {func_SYS_fremovexattr, 16, 16},
    {func_SYS_getcwd, 17, 17},
    {func_SYS_lookup_dcookie, 18, 18},
    {func_SYS_eventfd2, 19, 19},
    {func_SYS_epoll_create1, 20, 20},
    {func_SYS_epoll_ctl, 21, 21},
    {func_SYS_epoll_pwait, 22, 22},
    {func_SYS_dup, 23, 23},
    {func_SYS_dup3, 24, 24},
    {func_SYS_fcntl, 25, 25},
    {func_SYS_inotify_init1, 26, 26},
    {func_SYS_inotify_add_watch, 27, 27},
    {func_SYS_inotify_rm_watch, 28, 28},
    {func_SYS_ioctl, 29, 29},
    {func_SYS_ioprio_set, 30, 30},
    {func_SYS_ioprio_get, 31, 31},
    {func_SYS_flock, 32, 32},
    {func_SYS_mknodat, 33, 33},
    {func_SYS_mkdirat, 34, 34},
    {func_SYS_unlinkat, 35, 35},
    {func_SYS_symlinkat, 36, 36},
    {func_SYS_linkat, 37, 37},
    {func_SYS_NONE, 38, 38},
    {func_SYS_umount2, 39, 39},
    {func_SYS_mount, 40, 40},
    {func_SYS_pivot_root, 41, 41},
    {func_SYS_nfsservctl, 42, 42},
    {func_SYS_statfs, 43, 43},
    {func_SYS_fstatfs, 44, 44},
    {func_SYS_truncate, 45, 45},
    {func_SYS_ftruncate, 46, 46},
    {func_SYS_fallocate, 47, 47},
    {func_SYS_faccessat, 48, 48},
    {func_SYS_chdir, 49, 49},
    {func_SYS_fchdir, 50, 50},
    {func_SYS_chroot, 51, 51},
    {func_SYS_fchmod, 52, 52},
    {func_SYS_fchmodat, 53, 53},
    {func_SYS_fchownat, 54, 54},
    {func_SYS_fchown, 55, 55},
    {func_SYS_openat, 56, 56},
    {func_SYS_close, 57, 57},
    {func_SYS_vhangup, 58, 58},
    {func_SYS_pipe2, 59, 59},
    {func_SYS_quotactl, 60, 60},
    {func_SYS_getdents64, 61, 61},
    {func_SYS_lseek, 62, 62},
    {func_SYS_read, 63, 63},
    {func_SYS_write, 64, 64},
    {func_SYS_readv, 65, 65},
    {func_SYS_writev, 66, 66},
    {func_SYS_pread64, 67, 67},
    {func_SYS_pwrite64, 68, 68},
    {func_SYS_preadv, 69, 69},
    {func_SYS_pwritev, 70, 70},
    {func_SYS_sendfile, 71, 71},
    {func_SYS_pselect6, 72, 72},
    {func_SYS_ppoll, 73, 73},
    {func_SYS_signalfd4, 74, 74},
    {func_SYS_vmsplice, 75, 75},
    {func_SYS_splice, 76, 76},
    {func_SYS_tee, 77, 77},
    {func_SYS_readlinkat, 78, 78},
    {func_SYS_fstatat, 79, 79},
    {func_SYS_fstat, 80, 80},
    {func_SYS_sync, 81, 81},
    {func_SYS_fsync, 82, 82},
    {func_SYS_fdatasync, 83, 83},
    {func_SYS_sync_file_range, 84, 84},
    {func_SYS_timerfd_create, 85, 85},
    {func_SYS_timerfd_settime, 86, 86},
    {func_SYS_timerfd_gettime, 87, 87},
    {func_SYS_utimensat, 88, 88},
    {func_SYS_acct, 89, 89},
    {func_SYS_capget, 90, 90},
    {func_SYS_capset, 91, 91},
    {func_SYS_personality, 92, 92},
    {func_SYS_exit, 93, 93},
    {func_SYS_exit_group, 94, 94},
    {func_SYS_waitid, 95, 95},
    {func_SYS_set_tid_address, 96, 96},
    {func_SYS_unshare, 97, 97},
    {func_SYS_futex, 98, 98},
    {func_SYS_set_robust_list, 99, 99},
    {func_SYS_get_robust_list, 100, 100},
    {func_SYS_nanosleep, 101, 101},
    {func_SYS_getitimer, 102, 102},
    {func_SYS_setitimer, 103, 103},
    {func_SYS_kexec_load, 104, 104},
    {func_SYS_init_module, 105, 105},
    {func_SYS_delete_module, 106, 106},
    {func_SYS_timer_create, 107, 107},
    {func_SYS_timer_gettime, 108, 108},
    {func_SYS_timer_getoverrun, 109, 109},
    {func_SYS_timer_settime, 110, 110},
    {func_SYS_timer_delete, 111, 111},
    {func_SYS_clock_settime, 112, 112},
    {func_SYS_clock_gettime, 113, 113},
    {func_SYS_clock_getres, 114, 114},
    {func_SYS_clock_nanosleep, 115, 115},
    {func_SYS_syslog, 116, 116},
    {func_SYS_ptrace, 117, 117},
    {func_SYS_sched_setparam, 118, 118},
    {func_SYS_sched_setscheduler, 119, 119},
    {func_SYS_sched_getscheduler, 120, 120},
    {func_SYS_sched_getparam, 121, 121},
    {func_SYS_sched_setaffinity, 122, 122},
    {func_SYS_sched_getaffinity, 123, 123},
    {func_SYS_sched_yield, 124, 124},
    {func_SYS_sched_get_priority_max, 125, 125},
    {func_SYS_sched_get_priority_min, 126, 126},
    {func_SYS_sched_rr_get_interval, 127, 127},
    {func_SYS_restart_syscall, 128, 128},
    {func_SYS_kill, 129, 129},
    {func_SYS_tkill, 130, 130},
    {func_SYS_tgkill, 131, 131},
    {func_SYS_sigaltstack, 132, 132},
    {func_SYS_rt_sigsuspend, 133, 133},
    {func_SYS_rt_sigaction, 134, 134},
    {func_SYS_rt_sigprocmask, 135, 135},
    {func_SYS_rt_sigpending, 136, 136},
    {func_SYS_rt_sigtimedwait, 137, 137},
    {func_SYS_rt_sigqueueinfo, 138, 138},
    {func_SYS_rt_sigreturn, 139, 139},
    {func_SYS_setpriority, 140, 140},
    {func_SYS_getpriority, 141, 141},
    {func_SYS_reboot, 142, 142},
    {func_SYS_setregid, 143, 143},
    {func_SYS_setgid, 144, 144},
    {func_SYS_setreuid, 145, 145},
    {func_SYS_setuid, 146, 146},
    {func_SYS_setresuid, 147, 147},
    {func_SYS_getresuid, 148, 148},
    {func_SYS_setresgid, 149, 149},
    {func_SYS_getresgid, 150, 150},
    {func_SYS_setfsuid, 151, 151},
    {func_SYS_setfsgid, 152, 152},
    {func_SYS_times, 153, 153},
    {func_SYS_setpgid, 154, 154},
    {func_SYS_getpgid, 155, 155},
    {func_SYS_getsid, 156, 156},
    {func_SYS_setsid, 157, 157},
    {func_SYS_getgroups, 158, 158},
    {func_SYS_setgroups, 159, 159},
    {func_SYS_uname, 160, 160},
    {func_SYS_sethostname, 161, 161},
    {func_SYS_setdomainname, 162, 162},
    {func_SYS_getrlimit, 163, 163},
    {func_SYS_setrlimit, 164, 164},
    {func_SYS_getrusage, 165, 165},
    {func_SYS_umask, 166, 166},
    {func_SYS_prctl, 167, 167},
    {func_SYS_getcpu, 168, 168},
    {func_SYS_gettimeofday, 169, 169},
    {func_SYS_settimeofday, 170, 170},
    {func_SYS_adjtimex, 171, 171},
    {func_SYS_getpid, 172, 172},
    {func_SYS_getppid, 173, 173},
    {func_SYS_getuid, 174, 174},
    {func_SYS_geteuid, 175, 175},
    {func_SYS_getgid, 176, 176},
    {func_SYS_getegid, 177, 177},
    {func_SYS_gettid, 178, 178},
    {func_SYS_sysinfo, 179, 179},
    {func_SYS_mq_open, 180, 180},
    {func_SYS_mq_unlink, 181, 181},
    {func_SYS_mq_timedsend, 182, 182},
    {func_SYS_mq_timedreceive, 183, 183},
    {func_SYS_mq_notify, 184, 184},
    {func_SYS_mq_getsetattr, 185, 185},
    {func_SYS_msgget, 186, 186},
    {func_SYS_msgctl, 187, 187},
    {func_SYS_msgrcv, 188, 188},
    {func_SYS_msgsnd, 189, 189},
    {func_SYS_semget, 190, 190},
    {func_SYS_semctl, 191, 191},
    {func_SYS_semtimedop, 192, 192},
    {func_SYS_semop, 193, 193},
    {func_SYS_shmget, 194, 194},
    {func_SYS_shmctl, 195, 195},
    {func_SYS_shmat, 196, 196},
    {func_SYS_shmdt, 197, 197},
    {func_SYS_socket, 198, 198},
    {func_SYS_socketpair, 199, 199},
    {func_SYS_bind, 200, 200},
    {func_SYS_listen, 201, 201},
    {func_SYS_accept, 202, 202},
    {func_SYS_connect, 203, 203},
    {func_SYS_getsockname, 204, 204},
    {func_SYS_getpeername, 205, 205},
    {func_SYS_sendto, 206, 206},
    {func_SYS_recvfrom, 207, 207},
    {func_SYS_setsockopt, 208, 208},
    {func_SYS_getsockopt, 209, 209},
    {func_SYS_shutdown, 210, 210},
    {func_SYS_sendmsg, 211, 211},
    {func_SYS_recvmsg, 212, 212},
    {func_SYS_readahead, 213, 213},
    {func_SYS_brk, 214, 214},
    {func_SYS_munmap, 215, 215},
    {func_SYS_mremap, 216, 216},
    {func_SYS_add_key, 217, 217},
    {func_SYS_request_key, 218, 218},
    {func_SYS_keyctl, 219, 219},
    {func_SYS_clone, 220, 220},
    {func_SYS_execve, 221, 221},
    {func_SYS_mmap, 222, 222},
    {func_SYS_fadvise64, 223, 223},
    {func_SYS_swapon, 224, 224},
    {func_SYS_swapoff, 225, 225},
    {func_SYS_mprotect, 226, 226},
    {func_SYS_msync, 227, 227},
    {func_SYS_mlock, 228, 228},
    {func_SYS_munlock, 229, 229},
    {func_SYS_mlockall, 230, 230},
    {func_SYS_munlockall, 231, 231},
    {func_SYS_mincore, 232, 232},
    {func_SYS_madvise, 233, 233},
    {func_SYS_remap_file_pages, 234, 234},
    {func_SYS_mbind, 235, 235},
    {func_SYS_get_mempolicy, 236, 236},
    {func_SYS_set_mempolicy, 237, 237},
    {func_SYS_migrate_pages, 238, 238},
    {func_SYS_move_pages, 239, 239},
    {func_SYS_rt_tgsigqueueinfo, 240, 240},
    {func_SYS_perf_event_open, 241, 241},
    {func_SYS_accept4, 242, 242},
    {func_SYS_recvmmsg, 243, 243},
    {func_SYS_arch_specific_syscall, 244, 244},

    {func_SYS_NONE, 259, 245},
    {func_SYS_wait4, 260, 246},
    {func_SYS_prlimit64, 261, 247},
    {func_SYS_fanotify_init, 262, 248},
    {func_SYS_fanotify_mark, 263, 249},
    {func_SYS_name_to_handle_at, 264, 250},
    {func_SYS_open_by_handle_at, 265, 251},
    {func_SYS_clock_adjtime, 266, 252},
    {func_SYS_syncfs, 267, 253},
    {func_SYS_setns, 268, 254},
    {func_SYS_sendmmsg, 269, 255},
    {func_SYS_process_vm_readv, 270, 256},
    {func_SYS_process_vm_writev, 271, 257},
    {func_SYS_kcmp, 272, 258},
    {func_SYS_finit_module, 273, 259},
    {func_SYS_sched_setattr, 274, 260},
    {func_SYS_sched_getattr, 275, 261},
    {func_SYS_renameat2, 276, 262},
    {func_SYS_seccomp, 277, 263},
    {func_SYS_getrandom, 278, 264},
    {func_SYS_memfd_create, 279, 265},
    {func_SYS_bpf, 280, 266},
    {func_SYS_execveat, 281, 267},
    {func_SYS_userfaultfd, 282, 268},
    {func_SYS_membarrier, 283, 269},
    {func_SYS_mlock2, 284, 270},
    {func_SYS_copy_file_range, 285, 271},
    {func_SYS_preadv2, 286, 272},
    {func_SYS_pwritev2, 287, 273},
    {func_SYS_pkey_mprotect, 288, 274},
    {func_SYS_pkey_alloc, 289, 275},
    {func_SYS_pkey_free, 290, 276},
    {func_SYS_statx, 291, 277},
    {func_SYS_io_pgetevents, 292, 278},
    {func_SYS_rseq, 293, 279},
    {func_SYS_kexec_file_load, 294, 280},
    {func_SYS_riscv_flush_icache, 295, 281},

    {func_SYS_spawn, 400, 282},
    {func_SYS_mailread, 401, 283},
    {func_SYS_mailwrite, 402, 284},
    {func_SYS_mkdir, 1030, 285},
    {func_SYS_time, 1062, 286},
};

void info_registers(const struct Regs *regs) {
    if (regs == NULL) {
        return;
    }
    Info("%s : %p", "zero", regs->normal_regs.zero);
    Info("%s : %p", "ra", regs->normal_regs.ra);
    Info("%s : %p", "sp", regs->normal_regs.sp);
    Info("%s : %p", "gp", regs->normal_regs.gp);
    Info("%s : %p", "tp", regs->normal_regs.tp);
    Info("%s : %p", "t0", regs->normal_regs.t0);
    Info("%s : %p", "t1", regs->normal_regs.t1);
    Info("%s : %p", "t2", regs->normal_regs.t2);
    Info("%s : %p", "fp", regs->normal_regs.fp);
    Info("%s : %p", "s1", regs->normal_regs.s1);
    Info("%s : %p", "a0", regs->normal_regs.a0);
    Info("%s : %p", "a1", regs->normal_regs.a1);
    Info("%s : %p", "a2", regs->normal_regs.a2);
    Info("%s : %p", "a3", regs->normal_regs.a3);
    Info("%s : %p", "a4", regs->normal_regs.a4);
    Info("%s : %p", "a5", regs->normal_regs.a5);
    Info("%s : %p", "a6", regs->normal_regs.a6);
    Info("%s : %p", "a7", regs->normal_regs.a7);
    Info("%s : %p", "s2", regs->normal_regs.s2);
    Info("%s : %p", "s3", regs->normal_regs.s3);
    Info("%s : %p", "s4", regs->normal_regs.s4);
    Info("%s : %p", "s5", regs->normal_regs.s5);
    Info("%s : %p", "s6", regs->normal_regs.s6);
    Info("%s : %p", "s7", regs->normal_regs.s7);
    Info("%s : %p", "s8", regs->normal_regs.s8);
    Info("%s : %p", "s9", regs->normal_regs.s9);
    Info("%s : %p", "s10", regs->normal_regs.s10);
    Info("%s : %p", "s11", regs->normal_regs.s11);
    Info("%s : %p", "t3", regs->normal_regs.t3);
    Info("%s : %p", "t4", regs->normal_regs.t4);
    Info("%s : %p", "t5", regs->normal_regs.t5);
    Info("%s : %p", "t6", regs->normal_regs.t6);
    Info("%s : %p", "sstatus", regs->csr_regs.sstatus);
    Info("%s : %p", "sepc", regs->csr_regs.sepc);
    Info("%s : %p", "sscratch", regs->csr_regs.sscratch);
    Info("%s : %p", "satp", regs->csr_regs.satp);
}

// uint8_t kernel_process_stack[4096];

void init_trap() {
    // set trap handler func
    //    extern void _alltrap();
    extern void ktrap();
    //    write_csr(stvec, _alltrap);
    // 从s态发起的中断通过ktrap处理
    write_csr(stvec, ktrap);

    // 栈一定是高地址开始，向低地址增长，因此只能存高地址进去，不然直接爆栈
    // set kernel trap stack
    // smod -> smod 这个过程不需要换栈，内核只有自己的内核栈
    // write_csr(sscratch, kernel_process_stack + 4096);

    // disable s mod trap
    smod_disable_trap;
    // smod_enable_trap;

    // enable extern trap
    sie_seie_enable;
    plic_init();
    uart_init();

    // TODO:enable software trap
    // 初始化软件中断
    sie_ssie_enable;

    // enable time trap
    sie_stie_enable;
    //    init_clock();
}

void kernel_handler(struct Regs *regs) {
    uint64_t scause = read_csr(scause);

#undef DEBUG
#ifdef DEBUG
    Info("current process %s", get_current_process()->proc_name);

    info_registers(regs);
#endif

    // 处理完之后应当是已经调度完的状态
    if ((long)scause > 0) {
        Info("kernel exception happen");
        // smod->smod 一般不处理exception
        exception_jump_table[scause].func(regs, "exception");
    } else {
        interrupt_jump_table[scause].func(regs, "interrupt");
    }

    extern void krestore(struct Regs * regs);

    // 如果来源与smod则直接return，如果是umod，则出问题，因为umod不会跳到这里
    if ((read_csr(sstatus) & SSTATUS_SPP)) {
        krestore(regs);
    } else {
        Error("user mod should not be here");
        while (1) {
        }
    }
}

// void *all_handler(struct Regs *regs) {
void all_handler() {
    // 只在发生中断并且在S模式时运行，因此设置状态需要调整status中的spie，否则中断恢复后就是默认开启状态，实际并不是，因为读硬盘需要从s模式开启中断，因此陷入中断后spie默认开启，所以关中断的部分也在virtio处理程序中解决

struct Regs *regs = get_current_process()->pcb.context;

    uint64_t scause = read_csr(scause);

#undef DEBUG
#ifdef DEBUG
    Info("current process %s", get_current_process()->proc_name);

    info_registers(regs);
#endif

    // 源自用户态的陷入，更换为smod处理程序
    if (!(read_csr(sstatus) & SSTATUS_SPP)) {
        extern void ktrap();
        write_csr(stvec, (uint64_t)ktrap & ~0x3);
    } else {
        Error("kernel mod should not be here");
        while (1) {
        }
    }

    // 处理完之后应当是已经调度完的状态
    if ((long)scause > 0) {
        exception_jump_table[scause].func(regs, "exception");
    } else {
        interrupt_jump_table[scause].func(regs, "interrupt");
    }

    if (get_current_process() == NULL) {
#if DEBUG
        Info("task run over");
#endif
        extern AppFileNames_t global_loader;
        extern int app_loader(AppFileNames_t * afn);
        int status = app_loader(&global_loader);
        while (status == -2) {
            status = app_loader(&global_loader);
        }
        if (status == -1) {
            sbi_shutdown();
            while (1) {
            }
        }
        sched();
    }

    if (!(read_csr(sstatus) & SSTATUS_SPP)) {
        extern void _trap_restore(uintptr_t satp, char *context);
        // write_csr(stvec, (uint64_t)_alltrap & ~0x3);
        _trap_restore(get_current_process()->pcb.context->csr_regs.satp,
                      (void *)get_current_process()->pcb.context);
    } else {
        Error("should not be hear");
    }
}

// interupt
void *smod_software_interrupt(struct Regs *regs, const char *name) {
    return regs;
}

void *smod_time_interrupt(struct Regs *regs, const char *name) {
    Info("time interrupt");
    get_current_process()->pcb.times += CLOCK_FREQ / TICKS_PER_SEC;
    set_next_time_interrupt();
    return regs;
}

void *smod_outside_intertupt(struct Regs *regs, const char *name) {
    uint32_t irq = plic_cliam();
#ifdef DEBUG
    Info("irq %d", irq);
#endif
    switch (irq) {
    case UART0_IRQ:
        uart_isr();
        break;
    case VIRTIO_IRQ:
        virtio_disk_intr();
        // 关中断
        // regs->csr_regs.sstatus = regs->csr_regs.sstatus & ~SSTATUS_SPIE;
        break;
    default:
        Error("unknown irq %d", irq);
        while (1) {
        }
        break;
    }
    if (irq) {
        plic_complete(irq);
    }
    return regs;
}

// Exception
void *smod_instructions_not_aligned(struct Regs *regs, const char *name) {
    Warn("%s", name);
    return regs;
}
void *smod_instruction_access_exception(struct Regs *regs, const char *name) {
    Warn("%s", name);
    info_registers(regs);
    Info("stval %lx", read_csr(stval));
    Info("sepc %lx", read_csr(sepc));

    while (1) {
    }
    return regs;
}
void *smod_invalid_command(struct Regs *regs, const char *name) {
    info_registers(regs);
    while (1) {
    }
    Warn("%s", name);
    return regs;
}
void *smod_breakpoint(struct Regs *regs, const char *name) {
    Warn("%s", name);
    return regs;
}
void *smod_load_access_exception(struct Regs *regs, const char *name) {
    Warn("%s", name);
    info_registers(regs);
    Info("stval %lx", read_csr(stval));
    Info("sepc %lx", read_csr(sepc));
    while (1) {
    }
    process_exit();
    return regs;
}
void *smod_storage_address_not_aligned(struct Regs *regs, const char *name) {
    Warn("%s", name);
    return regs;
}
void *smod_storage_address_access_exception(struct Regs *regs,
        const char *name) {
    info_registers(regs);
    Info("stval %lx", read_csr(stval));
    Info("sepc %lx", read_csr(sepc));
    Warn("%s", name);
    while (1) {
    }
    return regs;
}

void *smod_user_syscall(struct Regs *regs, const char *name) {
    uint64_t ret = 0;
    uint64_t syscall_id = regs->normal_regs.a7;
#ifdef DEBUG
    Info("syscall from %d", syscall_id);
#endif

    uint64_t args[6] = {regs->normal_regs.a0, regs->normal_regs.a1,
                        regs->normal_regs.a2, regs->normal_regs.a3,
                        regs->normal_regs.a4, regs->normal_regs.a5
                       };

    regs->csr_regs.sepc += 4;

    ret =
        syscall_jump_table[syscall_id_to_index(syscall_id)].func((args_t *)args);
#ifdef DEBUG
    Info("ret %x", ret);
    Warn("%s", name);
#endif
    if (get_current_process() != NULL) {
        get_current_process()->pcb.context->normal_regs.a0 = ret;
    }

    return NULL;
}

void *smod_instructions_page_fault(struct Regs *regs, const char *name) {
    info_registers(regs);
    Info("stval %lx", read_csr(stval));
    Warn("%s", name);
    while (1) {
    }
    return regs;
}
void *smod_load_page_fault(struct Regs *regs, const char *name) {

    //    Info("a5 %lx", regs->normal_regs.a5);
    //    Info("%s",
    //         (char *)(va2pa((void *)get_current_process()->pcb.ptp_addr,
    //         0x1eb8)));
    info_registers(regs);
    Info("stval %lx", read_csr(stval));

    Info("sepc %lx", read_csr(sepc));
    Warn("%s", name);
    while (1) {
    }
    process_exit();
    return regs;
}
void *smod_store_page_fault(struct Regs *regs, const char *name) {
    info_registers(regs);
    Info("stval %lx", read_csr(stval));
    Warn("%s", name);
    while (1) {
    }

    return regs;
}
void *smod_non(struct Regs *regs, const char *name) {
    Warn("%s", name);
    return regs;
}
