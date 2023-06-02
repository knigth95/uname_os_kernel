#ifndef __MACRO_H__
#define __MACRO_H__

#include "type.h"

// 直接使用了 linux的实现
#define offsetof(TYPE, MEMBER) ((uint64_t) & ((TYPE *)0)->MEMBER)
#define container_of(ptr, type, field)                                         \
  ((type *)((void *)(ptr) - (uint64_t)(&(((type *)(0))->field))))

#define container_of_safe(ptr, type, field)                                    \
  ({                                                                           \
    typeof(ptr) __ptr = (ptr);                                                 \
    type *__obj = container_of(__ptr, type, field);                            \
    (__ptr ? __obj : NULL);                                                    \
  })

#endif
