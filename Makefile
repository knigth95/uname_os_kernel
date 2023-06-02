# normal
.DEFAULT_GOAL := build
platform := qemu 
mode := debug
LOG ?= error
ifeq ($(LOG),error)
	CFLAGS += -D LOG_LEVEL_ERROR
else ifeq ($(LOG),warn)
	CFLAGS += -D LOG_LEVEL_WARN
else ifeq ($(LOG),info)
	CFLAGS += -D LOG_LEVEL_INFO
else ifeq ($(LOG),debug)
	CFLAGS += -D LOG_LEVEL_DEBUG
else ifeq ($(LOG),trace)
	CFLAGS += -D LOG_LEVEL_TRACE
endif

LINK_SCRIPT := ./linker/qemu.ld
# link script
ifeq ($(platform),k210)
	LINK_SCRIPT = ./linker/k210.ld
endif

ifeq ($(platform),qemu)
	LINK_SCRIPT = ./linker/qemu.ld
endif

# tools
CROSS_COMPILE=riscv64-unknown-elf-

GDB=gdb-multiarch
CC=$(CROSS_COMPILE)gcc
AS=$(CROSS_COMPILE)gas
LD=$(CROSS_COMPILE)ld
OBJCOPY=$(CROSS_COMPILE)objcopy
OBJDUMP=$(CROSS_COMPILE)objdump
QEMU=qemu-system-riscv64

# flags
QDEBUGFLAGS=-trace events=./eventlist.txt -trace file=./trace.log -d mmu

CFLAGS = -Wall -Werror -O0 -fno-omit-frame-pointer -ggdb -g
CFLAGS += -MD
CFLAGS += -mcmodel=medany
CFLAGS += -ffreestanding -fno-common -nostdlib -mno-relax
CFLAGS += -ffixed-tp
CFLAGS += -Isrc/kernel
CFLAGS += $(shell $(CC) -fno-stack-protector -E -x c /dev/null >/dev/null 2>&1 && echo -fno-stack-protector)

ifneq ($(shell $(CC) -dumpspecs 2>/dev/null | grep -e '[^f]no-pie'),)
	CFLAGS += -fno-pie -no-pie
endif
ifneq ($(shell $(CC) -dumpspecs 2>/dev/null | grep -e '[^f]nopie'),)
	CFLAGS += -fno-pie -nopie
endif

ifeq ($(mode),debug)
	CFLAGS += -DDEBUG
endif

ifeq ($(platform),qemu)
	CFLAGS += -D QEMU
endif

LDFLAGS =-z max-page-size=4096

# platform
ifeq ($(platform),k210)
	BOOTLOADER := ./bootloader/SBI/sbi-k210
else
#	BOOTLOADER := ./bootloader/SBI/sbi-qemu
	BOOTLOADER := ./bootloader/SBI/opensbi
#	BOOTLOADER := ./boot/fw_payload
#	BOOTLOADER := ./boot/rustsbi-qemu.bin
endif

#OBJS
BUILDDIR = build
C_SRCS = $(wildcard src/kernel/*.c)
C_SRCS += $(wildcard src/kernel/memory/*.c)
C_SRCS += $(wildcard src/kernel/trap/*.c)
C_SRCS += $(wildcard src/kernel/utils/*.c)
C_SRCS += $(wildcard src/kernel/driver/*.c)
C_SRCS += $(wildcard src/kernel/proc/*.c)
C_SRCS += $(wildcard src/kernel/filesys/*.c)
AS_SRCS = $(wildcard src/kernel/*.S)
AS_SRCS += $(wildcard src/kernel/trap/*.S)
# 原本是src/kernel/kernel.c
# 改后缀为src/kernel/kernel.o
# 增加前缀为build/src/kernel/kernel.o
C_OBJS = $(addprefix $(BUILDDIR)/, $(addsuffix .o, $(basename $(C_SRCS))))
AS_OBJS = $(addprefix $(BUILDDIR)/, $(addsuffix .o, $(basename $(AS_SRCS))))
OBJS = $(C_OBJS) $(AS_OBJS)

# build target
RUSTSBI:
ifeq ($(platform),k210)
	@cd ./bootloader/SBI/rustsbi-k210 && cargo make&& cp ./target/riscv64imac-unknown-none-elf/release/rustsbi-k210 ../sbi-k210
	@$(OBJDUMP) -S ./bootloader/SBI/sbi-k210 > $(BUILDDIR)/rustsbi-k210.asm
else
	@cd ./bootloader/SBI/rustsbi-qemu && cargo make&& cp ./target/riscv64imac-unknown-none-elf/release/rustsbi-qemu ../sbi-qemu
	@$(OBJDUMP) -S ./bootloader/SBI/sbi-qemu > $(BUILDDIR)/rustsbi-qemu.asm
endif

rustsbi-clean:
	@cd ./bootloader/SBI/rustsbi-k210 && cargo clean
	@cd ./bootloader/SBI/rustsbi-qemu && cargo clean


CPUS = 2
# qemu flags
ifndef CPUS
	CPUS := 2
endif

QFLAGS = -machine virt -nographic -kernel $(BUILDDIR)/kernel -m 128M
#QFLAGS = -machine virt  -nographic -m 128M
#QFLAGS += -device loader,file=$(BUILDDIR)/kernel,addr=0x80200000
QFLAGS += -smp $(CPUS)
QFLAGS += -bios $(BOOTLOADER)
QFLAGS += -serial mon:stdio
#QFLAGS += -drive file=disk.img,if=none,format=raw,id=x0
QFLAGS += -drive file=new_fs.img,if=none,format=raw,id=x0
QFLAGS += -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0

# target file
image = $(BUILDDIR)/kernel.bin
k210 = $(BUILDDIR)/k210.bin
k201-serialport := /dev/ttyUSB0

$(C_OBJS): $(BUILDDIR)/%.o : %.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(AS_OBJS): $(BUILDDIR)/%.o : %.S
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@


run: build
ifeq ($(platform),k210)
	@$(OBJCOPY) $(BUILDDIR)/kernel --strip-all -O binary $(image)
	@$(OBJCOPY) $(BOOTLOADER) --strip-all -O binary $(k211)
	@dd if=$(image) of=$(k210) bs=128K seek=1
	@$(OBJDUMP) -D -b binary -m riscv $(k210) > $(BUILDDIR)/k210.asm
	@sudo chmod 777 $(k210-serialport)
	@python3 ./tools/kflash.py -p $(k210-serialport) -b 1500000 -t $(k210)
else
	@$(QEMU) $(QFLAGS)
endif


build: build/kernel

build/kernel: $(OBJS) $(LINK_SCRIPT)
	$(LD) $(LDFLAGS) -T $(LINK_SCRIPT) -o $(BUILDDIR)/kernel $(OBJS)
	$(OBJDUMP) -S $(BUILDDIR)/kernel > $(BUILDDIR)/kernel.asm
	$(OBJDUMP) -t $(BUILDDIR)/kernel | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $(BUILDDIR)/kernel.sym
	$(OBJCOPY) --strip-all $(BUILDDIR)/kernel -O binary $(BUILDDIR)/kernel
	@echo 'Build kernel done'


.PHONY: clean
clean:
	@rm -rf build
