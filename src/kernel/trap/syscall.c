#include "include/syscall.h"
#include "include/clock.h"
#include "include/fs.h"
#include "include/log.h"
#include "include/printf.h"
#include "include/proc.h"
#include "include/string.h"
#include "include/type.h"
#include "include/uart.h"
#include "include/vm.h"

uint64_t func_SYS_io_setup(args_t *args) {
    return 0;
}
uint64_t func_SYS_io_destroy(args_t *args) {
    return 0;
}
uint64_t func_SYS_io_submit(args_t *args) {
    return 0;
}
uint64_t func_SYS_io_cancel(args_t *args) {
    return 0;
}
uint64_t func_SYS_io_getevents(args_t *args) {
    return 0;
}
uint64_t func_SYS_setxattr(args_t *args) {
    return 0;
}
uint64_t func_SYS_lsetxattr(args_t *args) {
    return 0;
}
uint64_t func_SYS_fsetxattr(args_t *args) {
    return 0;
}
uint64_t func_SYS_getxattr(args_t *args) {
    return 0;
}
uint64_t func_SYS_lgetxattr(args_t *args) {
    return 0;
}
uint64_t func_SYS_fgetxattr(args_t *args) {
    return 0;
}
uint64_t func_SYS_listxattr(args_t *args) {
    return 0;
}
uint64_t func_SYS_llistxattr(args_t *args) {
    return 0;
}
uint64_t func_SYS_flistxattr(args_t *args) {
    return 0;
}
uint64_t func_SYS_removexattr(args_t *args) {
    return 0;
}
uint64_t func_SYS_lremovexattr(args_t *args) {
    return 0;
}
uint64_t func_SYS_fremovexattr(args_t *args) {
    return 0;
}
uint64_t func_SYS_getcwd(args_t *args) {
    return 0;
}
uint64_t func_SYS_lookup_dcookie(args_t *args) {
    return 0;
}
uint64_t func_SYS_eventfd2(args_t *args) {
    return 0;
}
uint64_t func_SYS_epoll_create1(args_t *args) {
    return 0;
}
uint64_t func_SYS_epoll_ctl(args_t *args) {
    return 0;
}
uint64_t func_SYS_epoll_pwait(args_t *args) {
    return 0;
}
uint64_t func_SYS_dup(args_t *args) {
    return 0;
}
uint64_t func_SYS_dup3(args_t *args) {
    return 0;
}
uint64_t func_SYS_fcntl(args_t *args) {
    return 0;
}
uint64_t func_SYS_inotify_init1(args_t *args) {
    return 0;
}
uint64_t func_SYS_inotify_add_watch(args_t *args) {
    return 0;
}
uint64_t func_SYS_inotify_rm_watch(args_t *args) {
    return 0;
}
uint64_t func_SYS_ioctl(args_t *args) {
    return 0;
}
uint64_t func_SYS_ioprio_set(args_t *args) {
    return 0;
}
uint64_t func_SYS_ioprio_get(args_t *args) {
    return 0;
}
uint64_t func_SYS_flock(args_t *args) {
    return 0;
}
uint64_t func_SYS_mknodat(args_t *args) {
    return 0;
}
uint64_t func_SYS_mkdirat(args_t *args) {
    return 0;
}
uint64_t func_SYS_unlinkat(args_t *args) {
    return 0;
}
uint64_t func_SYS_symlinkat(args_t *args) {
    return 0;
}
uint64_t func_SYS_linkat(args_t *args) {
    return 0;
}
uint64_t func_SYS_umount2(args_t *args) {
    return 0;
}
uint64_t func_SYS_mount(args_t *args) {
    return 0;
}
uint64_t func_SYS_pivot_root(args_t *args) {
    return 0;
}
uint64_t func_SYS_nfsservctl(args_t *args) {
    return 0;
}
uint64_t func_SYS_statfs(args_t *args) {
    return 0;
}
uint64_t func_SYS_fstatfs(args_t *args) {
    return 0;
}
uint64_t func_SYS_truncate(args_t *args) {
    return 0;
}
uint64_t func_SYS_ftruncate(args_t *args) {
    return 0;
}
uint64_t func_SYS_fallocate(args_t *args) {
    return 0;
}
uint64_t func_SYS_faccessat(args_t *args) {
    return 0;
}
uint64_t func_SYS_chdir(args_t *args) {
    return 0;
}
uint64_t func_SYS_fchdir(args_t *args) {
    return 0;
}
uint64_t func_SYS_chroot(args_t *args) {
    return 0;
}
uint64_t func_SYS_fchmod(args_t *args) {
    return 0;
}
uint64_t func_SYS_fchmodat(args_t *args) {
    return 0;
}
uint64_t func_SYS_fchownat(args_t *args) {
    return 0;
}
uint64_t func_SYS_fchown(args_t *args) {
    return 0;
}
uint64_t func_SYS_openat(args_t *args) {
    extern struct fat32disk disk;
    int fd = open(
                 (uintptr_t)&disk,
                 (void *)va2pa((void *)get_current_process()->pcb.ptp_addr, args->arg1));
    if (fd == 0) {
        return -1;
    }
    return fd;
}
uint64_t func_SYS_close(args_t *args) {
    extern struct fat32disk disk;
    close((uintptr_t)&disk, args->arg0);
    return 0;
}
uint64_t func_SYS_vhangup(args_t *args) {
    return 0;
}
uint64_t func_SYS_pipe2(args_t *args) {
    return 0;
}
uint64_t func_SYS_quotactl(args_t *args) {
    return 0;
}
uint64_t func_SYS_getdents64(args_t *args) {
    return 0;
}
uint64_t func_SYS_lseek(args_t *args) {
    return 0;
}
uint64_t func_SYS_read(args_t *args) {
    return 0;
}
uint64_t func_SYS_write(args_t *args) {
    uintptr_t ptr =
        va2pa((void *)get_current_process()->pcb.ptp_addr, args->arg1);
    int i = 0;
    for (i = 0; i < args->arg2; i++) {
        uart_putc(((char *)ptr)[i]);
    }
    return 0;
}
uint64_t func_SYS_readv(args_t *args) {
    return 0;
}
uint64_t func_SYS_writev(args_t *args) {
    return 0;
}
uint64_t func_SYS_pread64(args_t *args) {
    return 0;
}
uint64_t func_SYS_pwrite64(args_t *args) {
    return 0;
}
uint64_t func_SYS_preadv(args_t *args) {
    return 0;
}
uint64_t func_SYS_pwritev(args_t *args) {
    return 0;
}
uint64_t func_SYS_sendfile(args_t *args) {
    return 0;
}
uint64_t func_SYS_pselect6(args_t *args) {
    return 0;
}
uint64_t func_SYS_ppoll(args_t *args) {
    return 0;
}
uint64_t func_SYS_signalfd4(args_t *args) {
    return 0;
}
uint64_t func_SYS_vmsplice(args_t *args) {
    return 0;
}
uint64_t func_SYS_splice(args_t *args) {
    return 0;
}
uint64_t func_SYS_tee(args_t *args) {
    return 0;
}
uint64_t func_SYS_readlinkat(args_t *args) {
    return 0;
}
uint64_t func_SYS_fstatat(args_t *args) {
    return 0;
}
uint64_t func_SYS_fstat(args_t *args) {
    return 0;
}
uint64_t func_SYS_sync(args_t *args) {
    return 0;
}
uint64_t func_SYS_fsync(args_t *args) {
    return 0;
}
uint64_t func_SYS_fdatasync(args_t *args) {
    return 0;
}
uint64_t func_SYS_sync_file_range(args_t *args) {
    return 0;
}
uint64_t func_SYS_timerfd_create(args_t *args) {
    return 0;
}
uint64_t func_SYS_timerfd_settime(args_t *args) {
    return 0;
}
uint64_t func_SYS_timerfd_gettime(args_t *args) {
    return 0;
}
uint64_t func_SYS_utimensat(args_t *args) {
    return 0;
}
uint64_t func_SYS_acct(args_t *args) {
    return 0;
}
uint64_t func_SYS_capget(args_t *args) {
    return 0;
}
uint64_t func_SYS_capset(args_t *args) {
    return 0;
}
uint64_t func_SYS_personality(args_t *args) {
    return 0;
}
uint64_t func_SYS_exit(args_t *args) {
    process_exit();
    return 0;
}
uint64_t func_SYS_exit_group(args_t *args) {
    return 0;
}
uint64_t func_SYS_waitid(args_t *args) {
    return 0;
}
uint64_t func_SYS_set_tid_address(args_t *args) {
    return 0;
}
uint64_t func_SYS_unshare(args_t *args) {
    return 0;
}
uint64_t func_SYS_futex(args_t *args) {
    return 0;
}
uint64_t func_SYS_set_robust_list(args_t *args) {
    return 0;
}
uint64_t func_SYS_get_robust_list(args_t *args) {
    return 0;
}
uint64_t func_SYS_nanosleep(args_t *args) {
    return 0;
}
uint64_t func_SYS_getitimer(args_t *args) {
    return 0;
}
uint64_t func_SYS_setitimer(args_t *args) {
    return 0;
}
uint64_t func_SYS_kexec_load(args_t *args) {
    return 0;
}
uint64_t func_SYS_init_module(args_t *args) {
    return 0;
}
uint64_t func_SYS_delete_module(args_t *args) {
    return 0;
}
uint64_t func_SYS_timer_create(args_t *args) {
    return 0;
}
uint64_t func_SYS_timer_gettime(args_t *args) {
    return 0;
}
uint64_t func_SYS_timer_getoverrun(args_t *args) {
    return 0;
}
uint64_t func_SYS_timer_settime(args_t *args) {
    return 0;
}
uint64_t func_SYS_timer_delete(args_t *args) {
    return 0;
}
uint64_t func_SYS_clock_settime(args_t *args) {
    return 0;
}
uint64_t func_SYS_clock_gettime(args_t *args) {
    return 0;
}
uint64_t func_SYS_clock_getres(args_t *args) {
    return 0;
}
uint64_t func_SYS_clock_nanosleep(args_t *args) {
    return 0;
}
uint64_t func_SYS_syslog(args_t *args) {
    return 0;
}
uint64_t func_SYS_ptrace(args_t *args) {
    return 0;
}
uint64_t func_SYS_sched_setparam(args_t *args) {
    return 0;
}
uint64_t func_SYS_sched_setscheduler(args_t *args) {
    return 0;
}
uint64_t func_SYS_sched_getscheduler(args_t *args) {
    return 0;
}
uint64_t func_SYS_sched_getparam(args_t *args) {
    return 0;
}
uint64_t func_SYS_sched_setaffinity(args_t *args) {
    return 0;
}
uint64_t func_SYS_sched_getaffinity(args_t *args) {
    return 0;
}
uint64_t func_SYS_sched_yield(args_t *args) {
    yield();

    return 0;
}
uint64_t func_SYS_sched_get_priority_max(args_t *args) {
    return 0;
}
uint64_t func_SYS_sched_get_priority_min(args_t *args) {
    return 0;
}
uint64_t func_SYS_sched_rr_get_interval(args_t *args) {
    return 0;
}
uint64_t func_SYS_restart_syscall(args_t *args) {
    return 0;
}
uint64_t func_SYS_kill(args_t *args) {
    return 0;
}
uint64_t func_SYS_tkill(args_t *args) {
    return 0;
}
uint64_t func_SYS_tgkill(args_t *args) {
    return 0;
}
uint64_t func_SYS_sigaltstack(args_t *args) {
    return 0;
}
uint64_t func_SYS_rt_sigsuspend(args_t *args) {
    return 0;
}
uint64_t func_SYS_rt_sigaction(args_t *args) {
    return 0;
}
uint64_t func_SYS_rt_sigprocmask(args_t *args) {
    return 0;
}
uint64_t func_SYS_rt_sigpending(args_t *args) {
    return 0;
}
uint64_t func_SYS_rt_sigtimedwait(args_t *args) {
    return 0;
}
uint64_t func_SYS_rt_sigqueueinfo(args_t *args) {
    return 0;
}
uint64_t func_SYS_rt_sigreturn(args_t *args) {
    return 0;
}
uint64_t func_SYS_setpriority(args_t *args) {
    return 0;
}
uint64_t func_SYS_getpriority(args_t *args) {
    return 0;
}
uint64_t func_SYS_reboot(args_t *args) {
    return 0;
}
uint64_t func_SYS_setregid(args_t *args) {
    return 0;
}
uint64_t func_SYS_setgid(args_t *args) {
    return 0;
}
uint64_t func_SYS_setreuid(args_t *args) {
    return 0;
}
uint64_t func_SYS_setuid(args_t *args) {
    return 0;
}
uint64_t func_SYS_setresuid(args_t *args) {
    return 0;
}
uint64_t func_SYS_getresuid(args_t *args) {
    return 0;
}
uint64_t func_SYS_setresgid(args_t *args) {
    return 0;
}
uint64_t func_SYS_getresgid(args_t *args) {
    return 0;
}
uint64_t func_SYS_setfsuid(args_t *args) {
    return 0;
}
uint64_t func_SYS_setfsgid(args_t *args) {
    return 0;
}
uint64_t func_SYS_times(args_t *args) {
    struct tms *t =
        (void *)va2pa((void *)get_current_process()->pcb.ptp_addr, args->arg0);
    t->tms_utime = get_current_process()->pcb.times;
    t->tms_stime = get_time() - get_current_process()->pcb.start_times;
    return get_current_process()->pcb.times;
}
uint64_t func_SYS_time(args_t *args) {
    return 0;
}
uint64_t func_SYS_setpgid(args_t *args) {
    return 0;
}
uint64_t func_SYS_getpgid(args_t *args) {
    return 0;
}
uint64_t func_SYS_getsid(args_t *args) {
    return 0;
}
uint64_t func_SYS_setsid(args_t *args) {
    return 0;
}
uint64_t func_SYS_getgroups(args_t *args) {
    return 0;
}
uint64_t func_SYS_setgroups(args_t *args) {
    return 0;
}
uint64_t func_SYS_uname(args_t *args) {
    uintptr_t ut_address =
        va2pa((ptp_t *)get_current_process()->pcb.ptp_addr, args->arg0);
struct utsname *ut = (void *)ut_address;
    strncpy(ut->sysname, "os", 2);
    strncpy(ut->nodename, "os", 2);
    strncpy(ut->release, "os", 2);
    strncpy(ut->version, "os", 2);
    strncpy(ut->machine, "os", 2);
    strncpy(ut->domainname, "os", 2);

    return 0;
}
uint64_t func_SYS_sethostname(args_t *args) {
    return 0;
}
uint64_t func_SYS_setdomainname(args_t *args) {
    return 0;
}
uint64_t func_SYS_getrlimit(args_t *args) {
    return 0;
}
uint64_t func_SYS_setrlimit(args_t *args) {
    return 0;
}
uint64_t func_SYS_getrusage(args_t *args) {
    return 0;
}
uint64_t func_SYS_umask(args_t *args) {
    return 0;
}
uint64_t func_SYS_prctl(args_t *args) {
    return 0;
}
uint64_t func_SYS_getcpu(args_t *args) {
    return 0;
}
uint64_t func_SYS_gettimeofday(args_t *args) {
    TimeVal time;
    time.sec = get_time() / CLOCK_FREQ;
    time.usec = get_time() % CLOCK_FREQ * 1000000 / CLOCK_FREQ;
    TimeVal *target =
        (void *)va2pa((void *)get_current_process()->pcb.ptp_addr, args->arg0);
    target->sec = time.sec;
    target->usec = time.usec;

    return 0;
}
uint64_t func_SYS_settimeofday(args_t *args) {
    return 0;
}
uint64_t func_SYS_adjtimex(args_t *args) {
    return 0;
}
uint64_t func_SYS_getpid(args_t *args) {
    return get_current_process()->pcb.pid;
}
uint64_t func_SYS_getppid(args_t *args) {
    return get_current_process()->parent_proc->pcb.pid + 1;
}
uint64_t func_SYS_getuid(args_t *args) {
    return 0;
}
uint64_t func_SYS_geteuid(args_t *args) {
    return 0;
}
uint64_t func_SYS_getgid(args_t *args) {
    return 0;
}
uint64_t func_SYS_getegid(args_t *args) {
    return 0;
}
uint64_t func_SYS_gettid(args_t *args) {
    return 0;
}
uint64_t func_SYS_sysinfo(args_t *args) {
    return 0;
}
uint64_t func_SYS_mq_open(args_t *args) {
    return 0;
}
uint64_t func_SYS_mq_unlink(args_t *args) {
    return 0;
}
uint64_t func_SYS_mq_timedsend(args_t *args) {
    return 0;
}
uint64_t func_SYS_mq_timedreceive(args_t *args) {
    return 0;
}
uint64_t func_SYS_mq_notify(args_t *args) {
    return 0;
}
uint64_t func_SYS_mq_getsetattr(args_t *args) {
    return 0;
}
uint64_t func_SYS_msgget(args_t *args) {
    return 0;
}
uint64_t func_SYS_msgctl(args_t *args) {
    return 0;
}
uint64_t func_SYS_msgrcv(args_t *args) {
    return 0;
}
uint64_t func_SYS_msgsnd(args_t *args) {
    return 0;
}
uint64_t func_SYS_semget(args_t *args) {
    return 0;
}
uint64_t func_SYS_semctl(args_t *args) {
    return 0;
}
uint64_t func_SYS_semtimedop(args_t *args) {
    return 0;
}
uint64_t func_SYS_semop(args_t *args) {
    return 0;
}
uint64_t func_SYS_shmget(args_t *args) {
    return 0;
}
uint64_t func_SYS_shmctl(args_t *args) {
    return 0;
}
uint64_t func_SYS_shmat(args_t *args) {
    return 0;
}
uint64_t func_SYS_shmdt(args_t *args) {
    return 0;
}
uint64_t func_SYS_socket(args_t *args) {
    return 0;
}
uint64_t func_SYS_socketpair(args_t *args) {
    return 0;
}
uint64_t func_SYS_bind(args_t *args) {
    return 0;
}
uint64_t func_SYS_listen(args_t *args) {
    return 0;
}
uint64_t func_SYS_accept(args_t *args) {
    return 0;
}
uint64_t func_SYS_connect(args_t *args) {
    return 0;
}
uint64_t func_SYS_getsockname(args_t *args) {
    return 0;
}
uint64_t func_SYS_getpeername(args_t *args) {
    return 0;
}
uint64_t func_SYS_sendto(args_t *args) {
    return 0;
}
uint64_t func_SYS_recvfrom(args_t *args) {
    return 0;
}
uint64_t func_SYS_setsockopt(args_t *args) {
    return 0;
}
uint64_t func_SYS_getsockopt(args_t *args) {
    return 0;
}
uint64_t func_SYS_shutdown(args_t *args) {
    return 0;
}
uint64_t func_SYS_sendmsg(args_t *args) {
    return 0;
}
uint64_t func_SYS_recvmsg(args_t *args) {
    return 0;
}
uint64_t func_SYS_readahead(args_t *args) {
    return 0;
}
uint64_t func_SYS_brk(args_t *args) {
    if (args->arg0 == 0) {
        return get_current_process()->pcb.brk;
    } else {
        get_current_process()->pcb.brk = args->arg0;
        return 0;
    }
}
uint64_t func_SYS_munmap(args_t *args) {
    return 0;
}
uint64_t func_SYS_mremap(args_t *args) {
    return 0;
}
uint64_t func_SYS_add_key(args_t *args) {
    return 0;
}
uint64_t func_SYS_request_key(args_t *args) {
    return 0;
}
uint64_t func_SYS_keyctl(args_t *args) {
    return 0;
}
uint64_t func_SYS_clone(args_t *args) {
    Proc_t *fork_proc = fork();
    return PROC_PCB(fork_proc).pid;
}
uint64_t func_SYS_execve(args_t *args) {
    return 0;
}
uint64_t func_SYS_mmap(args_t *args) {
    return 0;
}
uint64_t func_SYS_fadvise64(args_t *args) {
    return 0;
}
uint64_t func_SYS_swapon(args_t *args) {
    return 0;
}
uint64_t func_SYS_swapoff(args_t *args) {
    return 0;
}
uint64_t func_SYS_mprotect(args_t *args) {
    return 0;
}
uint64_t func_SYS_msync(args_t *args) {
    return 0;
}
uint64_t func_SYS_mlock(args_t *args) {
    return 0;
}
uint64_t func_SYS_munlock(args_t *args) {
    return 0;
}
uint64_t func_SYS_mlockall(args_t *args) {
    return 0;
}
uint64_t func_SYS_munlockall(args_t *args) {
    return 0;
}
uint64_t func_SYS_mincore(args_t *args) {
    return 0;
}
uint64_t func_SYS_madvise(args_t *args) {
    return 0;
}
uint64_t func_SYS_remap_file_pages(args_t *args) {
    return 0;
}
uint64_t func_SYS_mbind(args_t *args) {
    return 0;
}
uint64_t func_SYS_get_mempolicy(args_t *args) {
    return 0;
}
uint64_t func_SYS_set_mempolicy(args_t *args) {
    return 0;
}
uint64_t func_SYS_migrate_pages(args_t *args) {
    return 0;
}
uint64_t func_SYS_move_pages(args_t *args) {
    return 0;
}
uint64_t func_SYS_rt_tgsigqueueinfo(args_t *args) {
    return 0;
}
uint64_t func_SYS_perf_event_open(args_t *args) {
    return 0;
}
uint64_t func_SYS_accept4(args_t *args) {
    return 0;
}
uint64_t func_SYS_recvmmsg(args_t *args) {
    return 0;
}
uint64_t func_SYS_arch_specific_syscall(args_t *args) {
    return 0;
}
uint64_t func_SYS_wait4(args_t *args) {
    PROC_PCB(get_current_process()).waitid = args->arg0;
    PROC_PCB_CONTEXT(get_current_process())->normal_regs.a0 = args->arg1;
    sched();
    return 0;
}
uint64_t func_SYS_prlimit64(args_t *args) {
    return 0;
}
uint64_t func_SYS_fanotify_init(args_t *args) {
    return 0;
}
uint64_t func_SYS_fanotify_mark(args_t *args) {
    return 0;
}
uint64_t func_SYS_name_to_handle_at(args_t *args) {
    return 0;
}
uint64_t func_SYS_open_by_handle_at(args_t *args) {
    return 0;
}
uint64_t func_SYS_clock_adjtime(args_t *args) {
    return 0;
}
uint64_t func_SYS_syncfs(args_t *args) {
    return 0;
}
uint64_t func_SYS_setns(args_t *args) {
    return 0;
}
uint64_t func_SYS_sendmmsg(args_t *args) {
    return 0;
}
uint64_t func_SYS_process_vm_readv(args_t *args) {
    return 0;
}
uint64_t func_SYS_process_vm_writev(args_t *args) {
    return 0;
}
uint64_t func_SYS_kcmp(args_t *args) {
    return 0;
}
uint64_t func_SYS_finit_module(args_t *args) {
    return 0;
}
uint64_t func_SYS_sched_setattr(args_t *args) {
    return 0;
}
uint64_t func_SYS_sched_getattr(args_t *args) {
    return 0;
}
uint64_t func_SYS_renameat2(args_t *args) {
    return 0;
}
uint64_t func_SYS_seccomp(args_t *args) {
    return 0;
}
uint64_t func_SYS_getrandom(args_t *args) {
    return 0;
}
uint64_t func_SYS_memfd_create(args_t *args) {
    return 0;
}
uint64_t func_SYS_bpf(args_t *args) {
    return 0;
}
uint64_t func_SYS_execveat(args_t *args) {
    return 0;
}
uint64_t func_SYS_userfaultfd(args_t *args) {
    return 0;
}
uint64_t func_SYS_membarrier(args_t *args) {
    return 0;
}
uint64_t func_SYS_mlock2(args_t *args) {
    return 0;
}
uint64_t func_SYS_copy_file_range(args_t *args) {
    return 0;
}
uint64_t func_SYS_preadv2(args_t *args) {
    return 0;
}
uint64_t func_SYS_pwritev2(args_t *args) {
    return 0;
}
uint64_t func_SYS_pkey_mprotect(args_t *args) {
    return 0;
}
uint64_t func_SYS_pkey_alloc(args_t *args) {
    return 0;
}
uint64_t func_SYS_pkey_free(args_t *args) {
    return 0;
}
uint64_t func_SYS_statx(args_t *args) {
    return 0;
}
uint64_t func_SYS_io_pgetevents(args_t *args) {
    return 0;
}
uint64_t func_SYS_rseq(args_t *args) {
    return 0;
}
uint64_t func_SYS_kexec_file_load(args_t *args) {
    return 0;
}
uint64_t func_SYS_riscv_flush_icache(args_t *args) {
    return 0;
}
uint64_t func_SYS_spawn(args_t *args) {
    return 0;
}
uint64_t func_SYS_mailread(args_t *args) {
    return 0;
}
uint64_t func_SYS_mailwrite(args_t *args) {
    return 0;
}
uint64_t func_SYS_mkdir(args_t *args) {
    return 0;
}
uint64_t func_SYS_NONE(args_t *args) {
    return 0;
}

uint64_t syscall_id_to_index(uint64_t syscall_id) {
    if (syscall_id < 259) {
        return syscall_id;
    } else if (syscall_id >= 260 && syscall_id <= 295) {
        return syscall_id - 14;
    } else if (syscall_id >= 400 && syscall_id <= 1000) {
        return syscall_id - 119;
    } else if (syscall_id == 1030) {
        return syscall_id - 746;
    } else if (syscall_id == 1062) {
        return syscall_id - 777;
    }
    return 0;
}
