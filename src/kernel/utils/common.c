#include "include/type.h"

//
uint64_t powers(uint64_t x) {
    if (x == 1 || x == 0)
        return 0;
    return 1 + powers(x >> 1);
}
