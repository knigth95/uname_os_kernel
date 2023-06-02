#ifndef __ELF_H__
#define __ELF_H__

#include "include/proc.h"
#include "include/type.h"

#define EI_MAG0 0
#define EI_MAG1 1
#define EI_MAG2 2
#define EI_MAG3 3

#define EI_DATA 5
#define EI_VERSION 0
#define EI_PAD 0
#define EI_NIDENT 16
#define EI_MAGIC "\177ELF"

// p_type
#define PT_NULL 0
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_INTERP 3
#define PT_NOTE 4
#define PT_SHLIB 5
#define PT_PHDR 6
#define PT_LOADPROC 0x70000000
#define PT_HIPROC 0x7fffffff

// segment permissions
#define PF_X 0x1
#define PF_W 0x2
#define PF_R 0x4
#define PF_MASKPROC 0xf0000000

#define EI_CLASS 4
#define EI_CLASSNONE 0
#define EI_CLASS32 1
#define EI_CLASS64 2
#define EI_CLASSNUM 3

#define EM_RISCV 243

typedef struct {
    uint8_t e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr_t;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr_t;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint32_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} Elf64_Shdr_t;

typedef struct {
    uint32_t st_name;
    uint8_t st_info;
    uint8_t st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} Elf64_Sym_t;

typedef struct {
    uint64_t r_offset;
    uint32_t r_type;
    uint32_t r_sym;
    long r_addend;
} Elf64_Rela_t;

uintptr_t parser_elf_file(const char *address, Proc_t *proc);

#endif
