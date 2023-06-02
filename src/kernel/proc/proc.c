#include "include/proc.h"
#include "include/alloc.h"
#include "include/clock.h"
#include "include/elf.h"
#include "include/log.h"
#include "include/mm.h"
#include "include/page_table.h"
#include "include/queue.h"
#include "include/riscv.h"
#include "include/string.h"
#include "include/syscall.h"
#include "include/trap.h"
#include "include/vm.h"

ProcManager_t global_manager;
struct Pids pids;

#undef DEBUG

static void init_pids() {
    // lock
    for (int i = 0; i < PROC_MAX_NUM; i++) {
        pids.pid[i] = 0;
    }
    // 内核进程
    pids.pid[0] = 1;
}

static uint64_t alloc_pid() {
    // lock
    for (int i = 0; i < PROC_MAX_NUM; i++) {
        if (pids.pid[i] == 0) {
            pids.pid[i] = 1;
            // unlock
            return i;
        }
    }
    // proc full
    return 0;
}

static inline void free_pid(uint64_t pid) {
    pids.pid[pid] = 0;
}

void sched() {
    Proc_t *old_task = get_current_process();
    // 如果为空则当前任务已经结束
    if (old_task != NULL) {
        old_task->pcb.state = READY;
        if (old_task->pcb.pid != 0) {
            push_queue(&global_manager.proc_queue, (uintptr_t)old_task);
        }
    }

    Proc_t *next_task = fetch_task();
    if (next_task == NULL) {
        global_manager.current_proc = NULL;
        return;
    }
    if (next_task->pcb.times == 0) {
        next_task->pcb.start_times = get_time();
    }
    // 容易死锁，如果出现互相等待的时候，直接就会出问题

    while (next_task->pcb.waitid != 0 && next_task->pcb.waitid != -1) {
        int i = 0;
        for (i = 0; i < QUEUE_SIZE; i++) {
            if (global_manager.proc_queue.data[i] != 0) {
                if (((Proc_t *)global_manager.proc_queue.data[i])->pcb.pid ==
                        next_task->pcb.waitid) {
                    push_queue(&global_manager.proc_queue, (uintptr_t)next_task);
                    next_task = fetch_task();
                    break;
                }
            }
        }
        if (i == QUEUE_SIZE) {
            next_task->pcb.waitid = 0;
            next_task->pcb.context->normal_regs.a0 = next_task->pcb.waitid;
            break;
        }
    }

    if (next_task->pcb.waitid == -1) {
        next_task->pcb.waitid = 0;
        PROC_PCB_CONTEXT(next_task)->normal_regs.a0 = 0;
        push_queue(&global_manager.proc_queue, (uintptr_t)next_task);
        next_task = fetch_task();
    }

    next_task->pcb.state = RUNNING;
#ifdef DEBUG
    Info("task %s running", next_task->proc_name);
#endif
    global_manager.current_proc = next_task;
}

// 分配新的进程空间
// 仅没有shell时使用
Proc_t *new_proc(uintptr_t target_app_address, const char *name, int fork) {

    Proc_t *proc = (void *)kalloc(sizeof(Proc_t));
    if (proc == NULL) {
        return NULL;
    }

    proc->target_app_address = target_app_address;
    proc->proc_name = name;

    PROC_PCB(proc).state = NEW;

    PROC_PCB(proc).pid = alloc_pid();
    if (proc->pcb.pid == 0) {
        return NULL;
    }

    PROC_PCB(proc).times = 0;
    PROC_PCB(proc).start_times = 0;
    PROC_PCB(proc).brk = 0;
    // TODO:还缺一个child proc
    proc->parent_proc = get_current_process();

    // 初始化页表
    PROC_PCB(proc).ptp_addr = page4K_alloc();
    if (PROC_PCB(proc).ptp_addr == NULL) {
        free_pid(PROC_PCB(proc).pid);
        return NULL;
    }

    uintptr_t sepc = parser_elf_file((const char *)target_app_address, proc);
    if (fork == 0) {

#define STACK_SIZE 4096
        PROC_PCB(proc).kstack = kalloc(STACK_SIZE);
        if (PROC_PCB(proc).kstack == NULL) {
            pfree((uintptr_t)proc);
            return NULL;
        }

        PROC_PCB(proc).ustack = kalloc(STACK_SIZE);
        if (PROC_PCB(proc).kstack == NULL) {
            pfree((uintptr_t)proc);
            pfree((uintptr_t)PROC_PCB(proc).kstack);
            return NULL;
        }

        // TODO:验证这里是否需要-4 是需要的，只是对栈做一点处理
        PROC_PCB(proc).context =
            (void *)(PROC_PCB(proc).kstack + STACK_SIZE - 32 - 36 * 8);
        PROC_PCB(proc).kcontext =
            (void *)(PROC_PCB(proc).kstack + STACK_SIZE - 32 - 36 * 8 - 36 * 8);

        // 设置寄存器
        PROC_PCB_CONTEXT(proc)->normal_regs.ra = (uint64_t)process_exit;

        // 这里其实ustack 和 kstack 反设置了，因为在trap返回时，sp中就是kstack
#ifdef DEBUG
        Info("kstack %x", PROC_PCB(proc).kstack);
        Info("ustack %x", PROC_PCB(proc).ustack);
#endif

        // 这里-8，因为如果是完整的4096，那么从该地址处读数据时可能会读4097 4098
        // 4099这类的，然后导致缺页错误，可能的解决方案是直接-8，这样就预留了8字节的空间方便读取
        // TODO:验证该结论是否正确
        // 验证之后发现是4096这个地址处取一个word，这就没法取值了，因为地址压根没映射这个
        PROC_PCB_CONTEXT(proc)->normal_regs.sp =
            PROC_PCB(proc).kstack + STACK_SIZE - 32;

        PROC_PCB_CONTEXT(proc)->csr_regs.sscratch =
            PROC_PCB(proc).ustack + STACK_SIZE - 32;

        PROC_PCB_CONTEXT(proc)->csr_regs.sepc = sepc;
        //            parser_elf_file((const char *)target_app_address, proc);

        PROC_PCB_CONTEXT(proc)->csr_regs.satp = pa2satp(PROC_PCB(proc).ptp_addr);

        PROC_PCB_CONTEXT(proc)->csr_regs.sstatus =
            (read_csr(sstatus) | SSTATUS_UIE | SSTATUS_SUM) & ~SSTATUS_SPP &
            ~SSTATUS_SIE;

        // 设置映射
    }

    map_trap(PROC_PCB(proc).ptp_addr);

    //    map_kernel(PROC_PCB(proc).ptp_addr, &global_mem);

    if (fork == 0) {

        vmap(PROC_PCB(proc).ptp_addr, PROC_PCB(proc).kstack, PROC_PCB(proc).kstack,
             STACK_SIZE, FLAG_V | FLAG_W | FLAG_R);

        // 映射用户栈
        vmap(PROC_PCB(proc).ptp_addr, PROC_PCB(proc).ustack, PROC_PCB(proc).ustack,
             STACK_SIZE, FLAG_V | FLAG_W | FLAG_R | FLAG_U);
    }
    // 设定state
    PROC_PCB(proc).state = READY;

#ifdef DEBUG
    Debug("new proc %x", proc);
    Info("%x", va2pa((ptp_t *)PROC_PCB(proc).ptp_addr, 0x1000));
#endif

    //    push_queue(&global_manager.proc_queue, (uintptr_t)proc);
    return proc;
}

void alloc_proc(uintptr_t target_app_address, const char *name) {
    Proc_t *proc = new_proc(target_app_address, name, 0);
    if (proc == NULL) {
        Error("alloc proc error");
        return;
    }
    // 加入调度队列
    push_queue(&global_manager.proc_queue, (uintptr_t)proc);
}

void delete_proc(Proc_t *proc) {
    PROC_PCB(proc).state = END;
    free_pid(PROC_PCB(proc).pid);

    pfree(PROC_PCB(proc).kstack);
    pfree(PROC_PCB(proc).ustack);

    // 这里存在问题，就是导致page table=l2ptp的bug
    // 猜测是因为存在页表映射
    //  free_ptp((void *)satp2pa((satp_t)PROC_PCB_CONTEXT(proc)->csr_regs.satp));
}

static inline void init_proc_manager(ProcManager_t *manager,
                                     Proc_t *kernel_proc,
                                     Proc_t *current_proc) {
    init_queue(&manager->proc_queue);
    manager->kernel_proc = kernel_proc;
    manager->current_proc = current_proc;
}

// 初始化内核进程，初始化进程管理器
void process_init() {
    // 初始化pids
    init_pids();

    Proc_t *kernel_proc = (void *)kalloc(sizeof(Proc_t));
    kernel_proc->pcb.state = NEW;
    kernel_proc->proc_name = "kernel";
    PROC_PCB(kernel_proc).pid = 0;
    PROC_PCB(kernel_proc).ptp_addr = page4K_alloc();

    // 使用在trap部分时初始化过的kernel stack
    extern uint8_t kernel_process_stack[];
    PROC_PCB(kernel_proc).kstack = (uintptr_t)kernel_process_stack;

    // 在存context时，stack会先减去36*8的大小再减去头8个字节然后开始存东西
    // 因此这里需要重新定位context位置 TODO:不确定，需要调整
    // 确定了，内核不存在，因为没有取栈顶数据
    // 线程应当-32，因为栈桢16字节对齐
    PROC_PCB(kernel_proc).context =
        (void *)(PROC_PCB(kernel_proc).kstack + 4096 - 36 * 8);

    PROC_PCB_CONTEXT(kernel_proc)->csr_regs.sscratch =
        PROC_PCB(kernel_proc).kstack;

    //    map_kernel(PROC_PCB(kernel_proc).ptp_addr, &global_mem);
    //    flush_satp(PROC_PCB(kernel_proc).ptp_addr);

    PROC_PCB(kernel_proc).state = RUNNING;

    init_proc_manager(&global_manager, kernel_proc, kernel_proc);
}

void process_exit() {
    if (global_manager.current_proc == NULL) {
        return;
    }

    Proc_t *proc = get_current_process();
    global_manager.current_proc = NULL;

#ifdef DEBUG
    Info("%s process exit", proc->proc_name);
#endif

    PROC_PCB(proc).state = END;

    delete_proc(proc);
    sched();
}

Proc_t *fetch_task() {
    // 取出一个任务
    Proc_t *next_task = (void *)pop_queue(&global_manager.proc_queue);
    // 为空则是取完了
    if (next_task == NULL) {
        return NULL;
    }

    // 不在READY状态代表不能调度
    while (next_task->pcb.state != READY) {
        // 再送回队列
        push_queue(&global_manager.proc_queue, (uintptr_t)next_task);
        next_task = (void *)pop_queue(&global_manager.proc_queue);
    }

    return next_task;
}

Proc_t *get_current_process() {
    return global_manager.current_proc;
}

void yield() {
    sched();
}

Proc_t *fork() {
    Proc_t *current_proc = get_current_process();
    if (current_proc == NULL) {
        Error("no proc running");
        return NULL;
    }
    Proc_t *fork_proc =
        new_proc(current_proc->target_app_address, current_proc->proc_name, 1);
    if (fork_proc == NULL) {
        Error("mem full");
        return NULL;
    }

    PROC_PCB(fork_proc).ustack = kalloc(STACK_SIZE);
    PROC_PCB(fork_proc).kstack = kalloc(STACK_SIZE);
    PROC_PCB(fork_proc).context =
        (void *)(PROC_PCB(fork_proc).kstack + STACK_SIZE - 32 - 36 * 8);
    PROC_PCB(fork_proc).kcontext =
        (void *)(PROC_PCB(fork_proc).kstack + STACK_SIZE - 32 - 36 * 8 - 36 * 8);

    memmove((void *)PROC_PCB(fork_proc).ustack,
            (void *)PROC_PCB(current_proc).ustack, STACK_SIZE);
    memmove((void *)PROC_PCB(fork_proc).kstack,
            (void *)PROC_PCB(current_proc).kstack, STACK_SIZE);

    // 重置内核栈为新进程独立的内核栈
    PROC_PCB_CONTEXT(fork_proc)->normal_regs.sp =
        (uintptr_t)PROC_PCB(fork_proc).context;

    // 重置页表为新进程的页表
    PROC_PCB_CONTEXT(fork_proc)->csr_regs.satp =
        pa2satp(PROC_PCB(fork_proc).ptp_addr);

    // 等值映射内核栈
    vmap(PROC_PCB(fork_proc).ptp_addr, PROC_PCB(fork_proc).kstack,
         PROC_PCB(fork_proc).kstack, STACK_SIZE, FLAG_W | FLAG_V | FLAG_R);

    // 不等值映射用户栈

    vmap(PROC_PCB(fork_proc).ptp_addr, PROC_PCB(current_proc).ustack,
         PROC_PCB(fork_proc).ustack, STACK_SIZE,
         FLAG_W | FLAG_V | FLAG_R | FLAG_U);

    PROC_PCB_CONTEXT(fork_proc)->normal_regs.a0 = 0;
    push_queue(&global_manager.proc_queue, (uintptr_t)fork_proc);
    return fork_proc;
}
