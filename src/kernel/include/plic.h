#ifndef __PLIC_H__
#define __PLIC_H__

#include "include/type.h"

void plic_init();
uint32_t plic_cliam();
void plic_complete(uint32_t irq);

void plicinit();
#endif
