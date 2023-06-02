    .align 4
    .section .data
    .global _app_num
_app_num:
    .quad 33
    .quad app_0_start
    .quad app_1_start
    .quad app_2_start
    .quad app_3_start
    .quad app_4_start
    .quad app_5_start
    .quad app_6_start
    .quad app_7_start
    .quad app_8_start
    .quad app_9_start
    .quad app_10_start
    .quad app_11_start
    .quad app_12_start
    .quad app_13_start
    .quad app_14_start
    .quad app_15_start
    .quad app_16_start
    .quad app_17_start
    .quad app_18_start
    .quad app_19_start
    .quad app_20_start
    .quad app_21_start
    .quad app_22_start
    .quad app_23_start
    .quad app_24_start
    .quad app_25_start
    .quad app_26_start
    .quad app_27_start
    .quad app_28_start
    .quad app_29_start
    .quad app_30_start
    .quad app_31_start
    .quad app_32_start
    .quad app_32_end

    .global _app_names
_app_names:
   .string "brk"
   .string "chdir"
   .string "clone"
   .string "close"
   .string "dup"
   .string "dup2"
   .string "execve"
   .string "exit"
   .string "fork"
   .string "fstat"
   .string "getcwd"
   .string "getdents"
   .string "getpid"
   .string "getppid"
   .string "gettimeofday"
   .string "mkdir_"
   .string "mmap"
   .string "mount"
   .string "munmap"
   .string "open"
   .string "openat"
   .string "pipe"
   .string "read"
   .string "sleep"
   .string "test_echo"
   .string "times"
   .string "umount"
   .string "uname"
   .string "unlink"
   .string "wait"
   .string "waitpid"
   .string "write"
   .string "yield"

    .section .data.app0
    .global app_0_start
app_0_start:
    .incbin "./riscv64/brk"

    .section .data.app1
    .global app_1_start
app_1_start:
    .incbin "./riscv64/chdir"

    .section .data.app2
    .global app_2_start
app_2_start:
    .incbin "./riscv64/clone"

    .section .data.app3
    .global app_3_start
app_3_start:
    .incbin "./riscv64/close"

    .section .data.app4
    .global app_4_start
app_4_start:
    .incbin "./riscv64/dup"

    .section .data.app5
    .global app_5_start
app_5_start:
    .incbin "./riscv64/dup2"

    .section .data.app6
    .global app_6_start
app_6_start:
    .incbin "./riscv64/execve"

    .section .data.app7
    .global app_7_start
app_7_start:
    .incbin "./riscv64/exit"

    .section .data.app8
    .global app_8_start
app_8_start:
    .incbin "./riscv64/fork"

    .section .data.app9
    .global app_9_start
app_9_start:
    .incbin "./riscv64/fstat"

    .section .data.app10
    .global app_10_start
app_10_start:
    .incbin "./riscv64/getcwd"

    .section .data.app11
    .global app_11_start
app_11_start:
    .incbin "./riscv64/getdents"

    .section .data.app12
    .global app_12_start
app_12_start:
    .incbin "./riscv64/getpid"

    .section .data.app13
    .global app_13_start
app_13_start:
    .incbin "./riscv64/getppid"

    .section .data.app14
    .global app_14_start
app_14_start:
    .incbin "./riscv64/gettimeofday"

    .section .data.app15
    .global app_15_start
app_15_start:
    .incbin "./riscv64/mkdir_"

    .section .data.app16
    .global app_16_start
app_16_start:
    .incbin "./riscv64/mmap"

    .section .data.app17
    .global app_17_start
app_17_start:
    .incbin "./riscv64/mount"

    .section .data.app18
    .global app_18_start
app_18_start:
    .incbin "./riscv64/munmap"

    .section .data.app19
    .global app_19_start
app_19_start:
    .incbin "./riscv64/open"

    .section .data.app20
    .global app_20_start
app_20_start:
    .incbin "./riscv64/openat"

    .section .data.app21
    .global app_21_start
app_21_start:
    .incbin "./riscv64/pipe"

    .section .data.app22
    .global app_22_start
app_22_start:
    .incbin "./riscv64/read"

    .section .data.app23
    .global app_23_start
app_23_start:
    .incbin "./riscv64/sleep"

    .section .data.app24
    .global app_24_start
app_24_start:
    .incbin "./riscv64/test_echo"

    .section .data.app25
    .global app_25_start
app_25_start:
    .incbin "./riscv64/times"

    .section .data.app26
    .global app_26_start
app_26_start:
    .incbin "./riscv64/umount"

    .section .data.app27
    .global app_27_start
app_27_start:
    .incbin "./riscv64/uname"

    .section .data.app28
    .global app_28_start
app_28_start:
    .incbin "./riscv64/unlink"

    .section .data.app29
    .global app_29_start
app_29_start:
    .incbin "./riscv64/wait"

    .section .data.app30
    .global app_30_start
app_30_start:
    .incbin "./riscv64/waitpid"

    .section .data.app31
    .global app_31_start
app_31_start:
    .incbin "./riscv64/write"

    .section .data.app32
    .global app_32_start
app_32_start:
    .incbin "./riscv64/yield"
app_32_end:

