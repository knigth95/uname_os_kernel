#ifndef EXTERN_SYMBOL_H
#define EXTERN_SYMBOL_H
#include "type.h"

#define MAX_APP_NUM (33)
#define MAX_STR_LEN (200)

extern char s_kernel[];
extern char e_kernel[];

extern char s_text[];
extern char e_text[];

extern char s_rodata[];
extern char e_rodata[];

extern char s_data[];
extern char e_data[];

extern char s_bss[];
extern char e_bss[];

extern char boot_stack[];
extern char boot_stack_top[];

extern char e_mem[];

extern char s_tramponline[];
extern char e_tramponline[];

extern char _app_num[];
extern char _app_names[];

#define s_memory e_kernel

#define e_memory e_mem

#endif
