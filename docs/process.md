# 进程管理和线程管理

## 基本情况

在初赛阶段，我们的内核以进程为单位进行调度，实现方式较为简单。

## 进程

### 进程控制块

PCB将占用部分资源保存进程的信息和状态系统通过PCB对进程进行控制和管理。

```c
typedef struct ProcessControlBlock {
    // 进程id
    int pid;
    // 进程状态
    enum procstate state;
    // 页表
    uintptr_t ptp_addr;
    // 用户态栈空间
    uint64_t ustack;
    // 内核态栈空间
    uint64_t kstack;
    // 等待进程结束
    uint64_t waitid;
    // 当前目录
    char *cwd;
    // 累计cpu时间
    uint64_t times;
    // 运行开始时间
    uint64_t start_times;
    // brk，程序堆空间大小
    uint64_t brk;
    // 上下文，指向内核栈合适的位置
    TaskContext_t *context;
    // smod上下文
    TaskContext_t *kcontext;
} PCB_t;
```

获取进程控制块的方式是在代码中使用了一组宏定义 `PROC_PCB` 和 `PROC_PCB_CONTEXT` 来获取和操作进程控制块。
`PROC_PCB(proc)`：获取一个进程 `proc` 的进程控制块，在代码中实现是通过指针运算和宏定义计算来得到一个 `Proc_t` 结构体里面 pcb 成员的指针`(&proc->pcb)`。
`PROC_PCB_CONTEXT(proc)`：获取一个进程 `proc` 的进程控制块的上下文信息。在代码中实现是通过先运算获取进程控制块的指针，然后进行强制类型转换得到进程控制块的上下文结构体类型 `(struct proc_context *)`，最后再获得上下文信息 `context` 成员。

### 进程ID

通过`init_pids()`初始化进程的ID，再通过 `alloc_pid()`为分配ID。

```c

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
```

### 进程状态
enum procstate { NEW = 0, READY = 1, RUNNING = 2, BLOCK = 3, END = 4 };
进程总共包含三种状态，如下所示：

- `NEW` ：表示该进程是新创建的
- `READY` ：进程控制块空闲，可以被分配给某一个进程。
- `RUNNING` ：该进程控制块正在被使用。
- `BLOCK` ：该进程被阻塞，将释放它占用的资源。
- `END` ：该进程已完成所有工作

### 启动初始化

内核在 `process_init()` 函数里对所有的进程控制块进行初始化。

```c
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

    PROC_PCB(kernel_proc).context =
        (void *)(PROC_PCB(kernel_proc).kstack + 4096 - 36 * 8);

    PROC_PCB_CONTEXT(kernel_proc)->csr_regs.sscratch =
        PROC_PCB(kernel_proc).kstack;

    PROC_PCB(kernel_proc).state = RUNNING;

    init_proc_manager(&global_manager, kernel_proc, kernel_proc);
}
```

### 进程初始化

在申请一个新的进程时，需要申请进程控制块，因此需要进行使用 `fetch_task()` 函数从全局进程调度器`ProcManager`中取出下一个可运行`PCB`。

- 初始化全局进程调度器`ProcManager`的变量，如进程队列。
- 为当前运行的进程分配内存并初始其进程控制块(Proc_t)。
- 设定当前进程状态为RUNNING，以便它成为第一个运行的进程。


### 进程申请

申请新进程通过 `alloc_proc(...)` 函数进行。

- 新的进程控制块`Proc_t`会被初始化，包括要运行的程序的起始地址、进程名称、页表、用户栈和内核栈等。
- 为新进程分配一个新的页表(page table)，用于管理其虚拟内存空间。
- 为新进程分配一个新的用户栈和内核栈，并把当前进程的用户栈和内核栈的数据拷贝到新进程中。

### 进程调度
以下是调度的简化过程，详细过程参见`sched(...)` 函数
- 调用`fetch_task()`函数从全局进程调度器`ProcManager`的进程队列中取出下一个可运行(process state为READY)的进程控制块`Proc_t`。
- 循环从进程队列中取出进程控制块，直到找到一个可运行的进程控制块为止。
- 调用`yield()`函数将CPU使用权让给下一个可运行的进程。

### 进程结束

当一个进程的所有线程全部结束之后，该进程将会调用 `process_exit()` 函数自行销毁：

- 检查全局进程调度器`ProcManager`的`current_proc`变量是否为NULL。如果为NULL，则直接返回，不进行任何操作。
- 获取当前正在运行的进程`proc`的进程控制块 `Proc_t`，使用`get_current_process()`函数实现。
- 置空全局进程调度器`ProcManager`的`current_proc`变量，表示当前没有正在运行的进程。设置进程状态为END
- 调用`delete_proc()`函数，释放进程控制块`Proc_t`所占用的内存，并将其从`ProcManager`的进程队列中移除。
- 调用`sched()`函数，选择下一个可运行的进程并开始运行它。












