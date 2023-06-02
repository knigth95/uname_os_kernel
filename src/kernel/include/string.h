#ifndef __STRING_H__
#define __STRING_H__

#include "type.h"
void *memset(void *dst, int c, uint64_t n);

int memcmp(const void *v1, const void *v2, uint32_t n);
void *memmove(void *dst, const void *src, uint32_t n);
void *memcpy(void *dst, const void *src, uint32_t n);
int strncmp(const char *p, const char *q, uint32_t n);
char *strncpy(char *s, const char *t, int n);
char *safestrcpy(char *s, const char *t, int n);
int strlen(const char *s);
void dummy(int _, ...);
#endif
