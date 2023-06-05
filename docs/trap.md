# 异常与系统调用

在我们的OS的设计中，有四种事件会导致CPU停止执行普通指令并且强制跳转到一段特殊的代码来处理这个事件。
- 发生未处理的异常（Exception），如指令地址不对齐、指令访问权限异常、非法指令执行、断点、加载数据地址 不对齐、存储数据地址不对齐、存储数据访问权限异常等。
- 发生外部设备中断（External Interrupt），如UART中断和virtio磁盘中断。
- 发生时钟中断（Timer Interrupt）。
- 发生系统调用（System Call）。

异常发生时，控制权将转移到内核中，内核保存寄存器和其它状态以便于可以恢复之前的代码。之后内核执行适当的处理程序。之后内核恢复之前保存的状态并且从异常返回，原始代码从中断处继续开始执行。

我们的OS将所有的Trap在内核中处理，而不会分发到用户态。

下文中将Exception 、External Interrupt 、Timer Interrupt、System Call统称为异常。

## 异常处理机制

内核通过读取一些控制寄存器来判断哪一种Trap发生了。下面是最重要的几个寄存器。

- stvec：内核将自己的异常处理函数的地址保存在这个寄存器里。
- sepc：当异常发生时，RISC-V将程序计数器（PC）的值保存在这个寄存器里。
- scause：RISC-V 将异常的原因保存在这个寄存器里。
- sstatus：该寄存器里的SIE位控制着中断（interrupt）是否被启用，如果SIE位被设置位0，RISC-V将忽略所有的设备中断知道SIE位被置为1。该寄存器里的SPP位表示这个异常是来在于用户态还是内核态。

这些与异常相关的寄存器都是S级别的寄存器，并且不能在U级被读写。在多核心芯片上的每个CPU都有自己的一套控制寄存器。

- 如果当前异常是一个设备中断（interrupt），并且sstatus::SIE位的值为0，则忽略该中断，什么事情也不做。
- 将sstatus::SIE位设置为0，关闭中断。
- 将pc赋值给sepc
- 将当前的特权级（U级或者S级）赋值给sstatus::SPP
- 将异常的原因赋值给scause
- 将特权级设置为S级
- 将stvec赋值给pc
- 从新的pc值处开始执行。

## 初始化

CPU通过`stvec` CSR标志位设置所有异常和中断的跳转入口地址，在程序启动时通过 `init_trap()` 函数进行设置

```c
void init_trap() {
    // set trap handler func
    extern void _alltrap();
    write_csr(stvec, _alltrap);

    // set kernel trap stack
    write_csr(sscratch, kernel_process_stack + 4096);

    // disable s mod trap
    smod_disable_trap;
    // smod_enable_trap;

    // enable extern trap
    sie_seie_enable;
    plic_init();
    uart_init();

    // 初始化软件中断
    sie_ssie_enable;

    // enable time trap
    sie_stie_enable;
    init_clock();
    Info("trap init");
}
```

## 异常处理
- `smod_instructions_not_aligned(...)` ：该函数用于处理指令地址未对齐的异常。
- `smod_instruction_access_exception(...)`：该函数用于处理指令访问异常。
- `smod_invalid_command(...)`：该函数用于处理无效指令异常。
- `smod_breakpoint(...)`：该函数用于处理断点异常，打印出 name 并返回 `regs` 结构体。
- `smod_load_access_exception(...)`：该函数用于处理加载访问异常。
- `smod_storage_address_access_exception(...)`：该函数用于处理存储访问异常。
- `smod_user_syscall(...)`：该函数用于处理系统调用异常。
- `smod_instructions_page_fault(...)`：该函数用于处理指令页故障异常。
- `smod_load_page_fault(...)`：该函数用于处理加载页故障异常。
- `smod_store_page_fault(...)`：该函数用于处理存储页故障异常。
- `smod_non(...)`：该函数用于处理未定义异常。


## 进入异常

在该程序中，通过设置 `STVEC` 寄存器标志位来指定中断/异常处理程序的入口地址，从而为每个异常或中断设置了入口点，即跳转表中对应的处理函数。

- 发生异常时，使用 `read_csr(scause)` 读取当前异常的原因，并根据跳转表找到对应的处理函数。
- 在处理函数中，程序会保存当前指令执行的上下文（如寄存器的值、特权模式标志位等）到相应的数据结构中，然后进入异常处理流程，例如进行异常逻辑的判断，打印错误信息等。
- 异常处理完成后，程序会将保存的上下文从数据结构中恢复到相应的寄存器中，并使用异常返回指令返回到原指令执行的现场。

## 中断处理
发生中断时，CPU会根据设置的 `stvec` 寄存器中的地址跳转到中断处理程序，即 `all_handler(...)` 函数。

- 据当前模式判断是用户态的中断陷入还是内核态的中断陷入。
- 根据 `scause` 寄存器的值确定中断类型，调用相应的中断处理程序。

本OS中的处理为根据 `scause` 寄存器的值确定中断类型，调用相应的中断处理程序。如果 `scause` 的值大于0，说明是异常请求，调用 `exception_jump_table[]` 中相应的异常处理程序；否则调用 `interrupt_jump_table[]` 中相应的中断处理程序。
- 对于软件中断，调用 `smod_software_interrupt(...)`；
- 对于定时器中断，调用 smod_time_interrupt；
- 对于外部中断，调用 `smod_outside_interrupt(...)`。在 `smod_outside_interrupt(...)` 中，根据外部中断类型的不同，进行相应的处理。
- 对于`UART0`中断，调用 `uart_isr`；
- 对于`VirtIO`磁盘中断，调用 `virtio_disk_intr`。在处理期间，将`SPIE`位（全局中断使能位）清零，禁止中断。
- 处理完中断后，重新开启`SPIE`位，以允许其他中断的发生。

## 内核态Trap

内核态 Trap 的处理函数为 `kernelTrap`。在正常情况下能进入内核态 Trap的方式只有外部中断，否则内核直接 panic。
