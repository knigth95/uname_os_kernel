.DEFAULT_GOAL := target

ARCH ?= riscv64
MODE ?= debug

app_dir = src
elf_dir := build/$(ARCH)
bin_dir := build/bin
out_dir := target


CROSS_COMPILE_TOOL = riscv64-unknown-elf-

QEMU = qemu-system-riscv64
QEMU_USER_TEST = qemu-riscv64
CC = $(CROSS_COMPILE_TOOL)-gcc
OBJCOPY = $(CROSS_COMPILE_TOOL)-objcopy
OBJDUMP = $(CROSS_COMPILE_TOOL)-objdump

CFLAGS = 
QFLAGS = 


BUILDDIR = build
C_SRCS = $(wildcard src/*.c)
AS_SRCS = $(wildcard src/*.S)

C_OBJS = $(addprefix $(BUILDDIR)/,$(addsuffix .o,$(basename $(C_SRCS))))
AS_OBJS = $(addprefix $(BUILDDIR)/,$(addsuffix .o,$(basename $(AS_SRCS))))
OBJS = $(C_OBJS) $(AS_OBJS)







build:

test:

