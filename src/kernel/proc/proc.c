#include "include/proc.h"
#include "include/alloc.h"
#include "include/clock.h"
#include "include/elf.h"
#include "include/fs.h"
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

// 初始化进程描述符
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

// 调出当前任务，调入下一个任务
void sched() {
    Proc_t *old_task = get_current_process();
    Proc_t *next_task = NULL;

    // 不为空，需要处理旧的任务
    if (old_task != NULL) {
        old_task->pcb.state = READY;
        if (old_task->pcb.pid != 0) {
            if (old_task->pcb.waitid != 0) {
                push_queue(&global_manager.wait_queue, (uintptr_t)old_task);
            } else {
                push_queue(&global_manager.proc_queue, (uintptr_t)old_task);
            }
        }
    } else {
        // 如果为空则当前任务已经结束
        // 如果存在等待的进程
        // 并且随便那个进程结束都可以，则优先调度
        Proc_t *wait_proc = (void *)pop_queue(&global_manager.wait_queue);
        if (wait_proc == NULL) {
            global_manager.current_proc = NULL;
            goto fetch;
        }
        wait_proc->pcb.waitid = 0;
        wait_proc->pcb.context->normal_regs.a0 = global_manager.last_pid;

        if (wait_proc->pcb.waitstatus != NULL) {
            *(int *)(wait_proc->pcb.waitstatus) = 0;
        }
        next_task = wait_proc;
        global_manager.current_proc = next_task;
        next_task->pcb.state = RUNNING;
        return;
    }

fetch:
    next_task = fetch_task();

    if (next_task == NULL) {
        global_manager.current_proc = NULL;
        return;
    }

    if (next_task->pcb.times == 0) {
        next_task->pcb.start_times = get_time();
    }

    global_manager.current_proc = next_task;
    // 容易死锁，如果出现互相等待的时候，直接就会出问题
    //

    next_task->pcb.state = RUNNING;
//    Info("task %s running", next_task->proc_name);
#ifdef DEBUG
#endif
}

// 分配新的进程空间
// 仅没有shell时使用
Proc_t *new_proc(uintptr_t target_app_address, const char *name, int fork) {

    // 分配进程控制块内存
    Proc_t *proc = (void *)kalloc(sizeof(Proc_t));
    if (proc == NULL) {
        return NULL;
    }

    // 设置使用的文件的内存地址
    proc->target_app_address = target_app_address;
    // 设置进程名
    proc->proc_name = name;

    // 设置进程状态
    PROC_PCB(proc).state = NEW;

    // 初始化等待该进程的队列
    init_queue(&proc->pcb.wait_queue);

    // 分配进程id
    PROC_PCB(proc).pid = alloc_pid();
    if (proc->pcb.pid == 0) {
        return NULL;
    }

    // 设置计时，以及进程堆
    PROC_PCB(proc).times = 0;
    PROC_PCB(proc).start_times = 0;
    PROC_PCB(proc).brk = 0;

    // 设置当前目录
    strncpy(PROC_PCB(proc).cwd, "/", 1);

    // 设置父进程
    //  TODO:还缺一个child proc
    proc->parent_proc = get_current_process();

    // 初始化页表
    PROC_PCB(proc).ptp_addr = page4K_alloc();
    if (PROC_PCB(proc).ptp_addr == NULL) {
        free_pid(PROC_PCB(proc).pid);
        return NULL;
    }

    // 解析文件，并映射到内存
    uintptr_t sepc = parser_elf_file((const char *)target_app_address, proc, 0);
    if (sepc == NULL) {
        // TODO:实际如果是NULL的话还要考虑free掉已经映射的地址
        free_pid(PROC_PCB(proc).pid);
        pfree(PROC_PCB(proc).ptp_addr);
        return NULL;
    }

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

        // TODO:验证这里是否需要-4
        // DONE: 是需要的，只是对栈做一点处理
        PROC_PCB(proc).context =
            (void *)(PROC_PCB(proc).kstack + STACK_SIZE - 32 - 37 * 8);
        //        PROC_PCB(proc).kcontext =
        //            (void *)(PROC_PCB(proc).kstack + STACK_SIZE - 32 - 36 * 8 - 36
        //            * 8);

        // 设置ra寄存器，实际这个不太有必要
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
        // 设置默认当前陷入smod，因此设置指向内核栈
        PROC_PCB_CONTEXT(proc)->normal_regs.sp =
            PROC_PCB(proc).kstack + STACK_SIZE - 32;

        // 设置sscratch地址指向用户栈
        PROC_PCB_CONTEXT(proc)->csr_regs.sscratch =
            PROC_PCB(proc).ustack + STACK_SIZE - 32;

        // 设置sepc指向起始地址
        PROC_PCB_CONTEXT(proc)->csr_regs.sepc = sepc;

        // 设置satp
        PROC_PCB_CONTEXT(proc)->csr_regs.satp = pa2satp(PROC_PCB(proc).ptp_addr);

        // 设置返回用户态时的处理程序的地址
        extern void _alltrap();
        PROC_PCB_CONTEXT(proc)->csr_regs.stvec = (uintptr_t)_alltrap;

        // 设置sstatus
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

    return proc;
}

// 分配一个进程，如果初始化成功则放入进程队列
int alloc_proc(uintptr_t target_app_address, const char *name) {
    Proc_t *proc = new_proc(target_app_address, name, 0);
    if (proc == NULL) {
#if DEBUG
        Error("alloc proc error");
#endif
        return -1;
    }
    // 加入调度队列
    push_queue(&global_manager.proc_queue, (uintptr_t)proc);
    return 0;
}

// 从内存中删除一个进程，并释放资源
void delete_proc(Proc_t *proc) {
    PROC_PCB(proc).state = END;
    free_pid(PROC_PCB(proc).pid);

    // 过早的free掉stack会导致当前使用的内核栈被释放，具体释放位置还得再决定
    //  pfree(PROC_PCB(proc).kstack);
    pfree(PROC_PCB(proc).ustack);

    parser_elf_file((void *)proc->target_app_address, proc, 1);

    // 如果free掉文件的target_app_address
    // 则由于多个进程可能使用同一个target_app_address
    // 导致多次free的问题，这个需要内存管理部分解决 TODO:
    //
    // 这里存在问题，就是导致page table=l2ptp的bug
    // 猜测是因为存在页表映射
    //    free_ptp((void
    //    *)satp2pa((satp_t)PROC_PCB_CONTEXT(proc)->csr_regs.satp));
    //
    // free ptp
}

// 初始化进程管理器
static inline void init_proc_manager(ProcManager_t *manager,
                                     Proc_t *kernel_proc,
                                     Proc_t *current_proc) {
    init_queue(&manager->proc_queue);
    init_queue(&manager->wait_queue);
    manager->kernel_proc = kernel_proc;
    manager->current_proc = NULL;
}

// 初始化内核进程，初始化进程管理器
void process_init() {
    // 初始化pids
    init_pids();

    Proc_t *kernel_proc = (void *)kalloc(sizeof(Proc_t));
    kernel_proc->pcb.state = NEW;
    kernel_proc->proc_name = "kernel";
    PROC_PCB(kernel_proc).pid = 0;
    // PROC_PCB(kernel_proc).ptp_addr = page4K_alloc();

    // 使用在trap部分时初始化过的kernel stack
    // extern uint8_t kernel_process_stack[];
    // PROC_PCB(kernel_proc).kstack = (uintptr_t)kernel_process_stack;

    // 在存context时，stack会先减去36*8的大小再减去头8个字节然后开始存东西
    // 因此这里需要重新定位context位置 TODO:不确定，需要调整
    // 确定了，内核不存在，因为没有取栈顶数据
    // 线程应当-32，因为栈桢16字节对齐
    // PROC_PCB(kernel_proc).context =
    //    (void *)(PROC_PCB(kernel_proc).kstack + 4096 - 37 * 8);

    // PROC_PCB_CONTEXT(kernel_proc)->csr_regs.sscratch =
    //     PROC_PCB(kernel_proc).kstack;

    //    map_kernel(PROC_PCB(kernel_proc).ptp_addr, &global_mem);
    //    flush_satp(PROC_PCB(kernel_proc).ptp_addr);

    // 可以初始化好kernel process然后直接ret到kernel process中去
    PROC_PCB(kernel_proc).state = RUNNING;

    init_proc_manager(&global_manager, kernel_proc, kernel_proc);
}

// 进程结束，从当前运行进程中摘下，并删除，并执行调度
void process_exit() {
    Proc_t *proc = get_current_process();
    if (proc == NULL) {
        return;
    }

    global_manager.current_proc = NULL;
    global_manager.last_pid = proc->pcb.pid;

#ifdef DEBUG
    Info("%s process exit", proc->proc_name);
#endif

    PROC_PCB(proc).state = END;
    // 等待队列不空
    while (!proc->pcb.wait_queue.empty) {
        // 取出
        uintptr_t ready_proc = pop_queue(&proc->pcb.wait_queue);

        if (ready_proc == NULL) {
            break;
        }

        // 下一个被调度，并且返回值是当前刚结束的任务
        ((Proc_t *)ready_proc)->pcb.context->normal_regs.a0 = proc->pcb.pid;

        // 意味着用户程序正常结束
        *(int *)(((Proc_t *)ready_proc)->pcb.waitstatus) = 0x300;
        // 准备好被调度
        ((Proc_t *)ready_proc)->pcb.state = READY;

        // 插入等待调度的队列
        push_queue(&global_manager.proc_queue, ready_proc);
    }

    // 删除进程
    delete_proc(proc);
    // 调度
    sched();
}

// 取出一个任务
Proc_t *fetch_task() {
    // 取出一个任务
    Proc_t *next_task = (void *)pop_queue(&global_manager.proc_queue);
    // 为空则是取完了
    if (next_task == NULL) {
        return NULL;
    }

    int i = 0;
    // 不在READY状态代表不能调度
    while (next_task->pcb.state != READY && i < 50) {
        // 再送回队列
        push_queue(&global_manager.proc_queue, (uintptr_t)next_task);
        next_task = (void *)pop_queue(&global_manager.proc_queue);
        // 防止取出放入取出放入的死等
        i++;
    }

    if (i == 50) {
        return NULL;
    }

    return next_task;
}

Proc_t *get_current_process() {
    return global_manager.current_proc;
}

void yield() {
    sched();
}

// 从当前运行进程中fork
Proc_t *fork(uintptr_t child_stack) {
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
    if (PROC_PCB(fork_proc).ustack == NULL) {
        return NULL;
    }
    PROC_PCB(fork_proc).kstack = kalloc(STACK_SIZE);
    if (PROC_PCB(fork_proc).kstack == NULL) {
        return NULL;
    }

    PROC_PCB(fork_proc).context =
        (void *)(PROC_PCB(fork_proc).kstack + STACK_SIZE - 32 - 37 * 8);
    //    PROC_PCB(fork_proc).kcontext =
    //        (void *)(PROC_PCB(fork_proc).kstack + STACK_SIZE - 32 - 36 * 8 - 36
    //        * 8);

    memmove((void *)PROC_PCB(fork_proc).ustack,
            (void *)PROC_PCB(current_proc).ustack, STACK_SIZE);
    memmove((void *)PROC_PCB(fork_proc).kstack,
            (void *)PROC_PCB(current_proc).kstack, STACK_SIZE);

    // 重置内核栈为新进程独立的内核栈，并且此时内核栈已经存了上下文，因此要-36*8
    PROC_PCB_CONTEXT(fork_proc)->normal_regs.sp =
        (uintptr_t)PROC_PCB(fork_proc).context;

    // 重置页表为新进程的页表
    PROC_PCB_CONTEXT(fork_proc)->csr_regs.satp =
        pa2satp(PROC_PCB(fork_proc).ptp_addr);

    // 需要判断是否映射成功，需要调整整个判断映射成功的逻辑TODO:
    //  等值映射内核栈
    vmap(PROC_PCB(fork_proc).ptp_addr, PROC_PCB(fork_proc).kstack,
         PROC_PCB(fork_proc).kstack, STACK_SIZE, FLAG_W | FLAG_V | FLAG_R);

    // 不等值映射用户栈

    vmap(PROC_PCB(fork_proc).ptp_addr, PROC_PCB(current_proc).ustack,
         PROC_PCB(fork_proc).ustack, STACK_SIZE,
         FLAG_W | FLAG_V | FLAG_R | FLAG_U);

    // 子进程返回0
    PROC_PCB_CONTEXT(fork_proc)->normal_regs.a0 = 0;

    // 这里其实用户态程序指定了栈空间以及clone后的函数，但是函数并没有传进来，所以看上去只是它指定的栈空间需要手动copy，其他的照旧，所以对他指定的栈空间进行copy后直接返回它栈空间地址，另外由于没指定栈大小，所以先按照1024来操作
    if (child_stack != NULL) {
        uintptr_t current_proc_address =
            va2pa((void *)PROC_PCB(current_proc).ptp_addr, child_stack);
        uintptr_t fork_proc_address =
            va2pa((void *)PROC_PCB(fork_proc).ptp_addr, child_stack);
        // 这里+16是因为在用户态程序中，传入的stack提前-16存了两个8字节的东西，这里先对他们地址补齐，也就是按照完整的栈去move，move完在栈中是正常的布局，然后返回的地址是原本栈传入的地址，这个地址+0和+8可以直接取值
        memmove((void *)(fork_proc_address - 1024 + 16),
                (void *)(current_proc_address - 1024 + 16), 1024);
        //        Info("%x", &((uint64_t *)(current_proc_address))[0]);
        //        Info("%x", &((uint64_t *)(current_proc_address))[1]);
        PROC_PCB_CONTEXT(fork_proc)->csr_regs.sscratch = child_stack;
    }

    push_queue(&global_manager.proc_queue, (uintptr_t)fork_proc);
    return fork_proc;
}

// 从磁盘load程序
int load_task(char *name) {
    extern struct fat32disk disk;
    int fd = open((uintptr_t)&disk, name);

    if (fd == 0) {
        return -1;
    }

    char *data = (void *)kalloc(disk.file[fd]->fsize);
    read((uintptr_t)&disk, fd, (uintptr_t)data, disk.file[fd]->fsize);
    if (alloc_proc((uintptr_t)data, name) == -1) {
        return -2;
    }
    // 考虑后续还需要fork，此时的close会导致文件释放TODO:
    //  close((uintptr_t)&disk, fd);
    return 0;
}

int insert_proc_wait_queue(Proc_t *process, int pid) {
    int i = 0;
    Proc_t *target_process;
    for (i = global_manager.proc_queue.front; i < global_manager.proc_queue.tail;
            i++) {
        target_process = (void *)global_manager.proc_queue.data[i];
        if (target_process != NULL && PROC_PCB(target_process).pid == pid) {
            push_queue(&PROC_PCB(target_process).wait_queue, (uintptr_t)process);
            return 0;
        }
    }
    return -1;
}
