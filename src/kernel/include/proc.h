#ifndef __PROC_H__
#define __PROC_H__

#include "include/list.h"
#include "include/queue.h"
#include "include/trap.h"
#include "include/type.h"

#define PROC_MAX_NUM (512)

#define PROC_PCB(proc) (proc->pcb)
#define PROC_PCB_CONTEXT(proc) (proc->pcb.context)

typedef struct Regs TaskContext_t;

enum procstate { NEW = 0, READY = 1, RUNNING = 2, BLOCK = 3, END = 4 };

struct Pids {
    uint64_t pid[PROC_MAX_NUM];
    //// lock
};
extern struct Pids pids;

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

typedef struct Proc Proc_t;
typedef struct Proc {
    // lock
    //
    const char *proc_name;
    uintptr_t target_app_address;
    Proc_t *parent_proc;

    // 子进程换成队列
    Proc_t *child_proc;

    PCB_t pcb;
} Proc_t;

typedef struct ProcManager {
    // lock
    Proc_t *kernel_proc;

    Proc_t *current_proc;

    Queue_t proc_queue;

} ProcManager_t;
extern ProcManager_t global_manager;

Proc_t *new_proc(uintptr_t target_app_address, const char *name, int fork);

void delete_proc(Proc_t *proc);
void process_init();
void process_exit();
Proc_t *get_current_process();

void alloc_proc(uintptr_t target_app_address, const char *name);
void sched();
void yield();
Proc_t *fetch_task();
Proc_t *fork();
#endif
