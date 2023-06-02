#include "include/elf.h"
#include "include/alloc.h"
#include "include/log.h"
#include "include/page_table.h"
#include "include/proc.h"
#include "include/string.h"
#include "include/type.h"
#include "include/vm.h"

static inline pte_flag_t flag_conversion(Elf64_Phdr_t *phdr) {
    pte_flag_t flag;
    flag.flag = 0;
    if (phdr->p_flags & PF_X) {
        flag.flag |= FLAG_X;
    } else if (phdr->p_flags & PF_R) {
        flag.flag |= FLAG_R;
    } else if (phdr->p_flags & PF_W) {
        flag.flag |= FLAG_W;
    }
    return flag;
}

static inline void load_pheader(const char *address, int i, Elf64_Ehdr_t *ehdr,
                                Elf64_Phdr_t **phdr) {
    *phdr = (void *)(address + ehdr->e_phoff + (i * ehdr->e_phentsize));
}

// map的时候，是否需要处理没对齐的问题 TODO:
static inline void pheader2mem(uintptr_t seg_addr, Elf64_Phdr_t *phdr,
                               Proc_t *proc) {
#define PAGE_SIZE 4096
    Info("phdr->p_memsz %x", phdr->p_memsz);
    uintptr_t phdr_paddr = kalloc(phdr->p_memsz);
    uintptr_t phdr_vaddr = PALIGN_DOWN(phdr->p_vaddr, PAGE_SIZE);

    Info("phdr paddr %lx seg_addr %lx", phdr_paddr, seg_addr);
    // TODO:memmove放在vmap之后，页表内容直接为空，需要排查

#ifdef DEBUG
    Info("phdr_paddr %x phdr_vaddr %x", phdr_paddr, phdr_vaddr);
#endif
    memmove((void *)phdr_paddr, (void *)seg_addr, phdr->p_memsz);
    Info("fork");
    // vmap在这里只map filesz会出现page fault 然后map memsz就可以了
    vmap(PROC_PCB(proc).ptp_addr, phdr_vaddr, phdr_paddr, phdr->p_memsz,
         flag_conversion(phdr).flag | FLAG_R | FLAG_U | FLAG_V);

#ifdef DEBUG
    Debug("va %x ->pa %x", 0x1000,
          va2pa((void *)PROC_PCB(proc).ptp_addr, 0x1000));
#endif
}

// 解析elf文件并返回入口地址
uintptr_t parser_elf_file(const char *address, Proc_t *proc) {
    Elf64_Ehdr_t *ehdr = (Elf64_Ehdr_t *)address;
    if (*(uint32_t *)ehdr != *(uint32_t *)EI_MAGIC) {
        return NULL;
    }
    if (ehdr->e_machine != EM_RISCV || ehdr->e_ident[EI_CLASS] != EI_CLASS64) {
        return NULL;
    }

    Elf64_Phdr_t *phdr;
    phdr = NULL;

#ifdef DEBUG
    Info("ehdr -> e_phnum %x", ehdr->e_phnum);
#endif

    for (int i = 0; i < ehdr->e_phnum; i++) {
        load_pheader(address, i, ehdr, &phdr);
        if (phdr->p_type == PT_LOAD && PROC_PCB(proc).ptp_addr != NULL) {
            pheader2mem((uintptr_t)(address + phdr->p_offset), phdr, proc);
#ifdef DEBUG
            Debug("va %x ->pa %x", 0x1000,
                  va2pa((void *)PROC_PCB(proc).ptp_addr, 0x1000));
            Info("load seg %x", phdr->p_vaddr);
#endif
        }
    }
    Info("end of parser_elf_file");
    return ehdr->e_entry;
}
