#include "include/type.h"

//
uint64_t powers(uint64_t x) {
    if (x == 1)
        return 1;
    return 1 + powers(x >> 1);
}
