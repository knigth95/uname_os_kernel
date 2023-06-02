#include "include/dtb.h"
#include "include/log.h"
#include "include/riscv.h"
#include "include/string.h"

// GUN linux
/* Swap bytes in 32-bit value.  */
#define __bswap_constant_32(x)                                                 \
  ((((x)&0xff000000u) >> 24) | (((x)&0x00ff0000u) >> 8) |                      \
   (((x)&0x0000ff00u) << 8) | (((x)&0x000000ffu) << 24))

static __inline uint32_t __bswap_32(uint32_t __bsx) {
    return __bswap_constant_32(__bsx);
}

static inline uint32_t fdt_magic(struct fdt_header *header) {
    return __bswap_32(header->magic);
}
static inline uint32_t fdt_totalsize(struct fdt_header *header) {
    return __bswap_32(header->totalsize);
}
static inline uint32_t fdt_off_dt_struct(struct fdt_header *header) {
    return __bswap_32(header->off_dt_struct);
}
static inline uint32_t fdt_off_dt_strings(struct fdt_header *header) {
    return __bswap_32(header->off_dt_strings);
}
static inline uint32_t fdt_version(struct fdt_header *header) {
    return __bswap_32(header->version);
}
static inline uint32_t fdt_size_dt_struct(struct fdt_header *header) {
    return __bswap_32(header->size_dt_struct);
}
static inline uint32_t fdt_size_dt_strings(struct fdt_header *header) {
    return __bswap_32(header->size_dt_strings);
}

static inline uint64_t first_struct_addr(struct fdt_header *header) {
    return (uint64_t)header + __bswap_32(header->off_dt_struct);
}

static inline uint64_t first_string_addr(struct fdt_header *header) {
    return (uint64_t)header + __bswap_32(header->off_dt_strings);
}

static inline uint32_t is_begin_node(struct fdt_node_header *node) {
    return __bswap_32(node->tag) == FDT_BEGIN_NODE;
}

static inline uint32_t is_end_node(struct fdt_node_header *node) {
    return __bswap_32(node->tag) == FDT_END_NODE;
}

static inline uint32_t is_prop(struct fdt_node_header *node) {
    return __bswap_32(node->tag) == FDT_PROP;
}

static inline uint32_t is_nop(struct fdt_node_header *node) {
    return __bswap_32(node->tag) == FDT_NOP;
}

static inline uint32_t is_end(struct fdt_node_header *node) {
    return __bswap_32(node->tag) == FDT_END;
}

void info_dtb_header(struct fdt_header *header) {
    Info("magic %x", fdt_magic(header));
    Info("totalsize %x", fdt_totalsize(header));
    Info("struct %x %x", fdt_off_dt_struct(header), fdt_size_dt_struct(header));
    Info("string %x %x", fdt_off_dt_strings(header), fdt_size_dt_strings(header));
    Info("version %x", fdt_version(header));
}

// int strlen(char str[]) {
//     if (str[0] == '\0') {
//         return 0;
//     }
//     char *p = str;
//     int count = 0;
//     while (*p++ != '\0') {
//         count++;
//     }
//     return count + 1;
// }

void parser_dtb(uint64_t dtb_addr) {
    struct fdt_header *header;
    header = (void *)dtb_addr;
    if (header->magic == 0xedfe0dd0) {
        struct fdt_node_header *node = (void *)first_struct_addr(header);
        struct fdt_property *prop = NULL;
        while (!is_end(node)) {
            if (is_begin_node(node)) {
                Info("begin");
                Info("node %p", node);
                if (node->name[0] == '\0') {
                    node = (void *)((uint64_t)node + 8);

                } else {
                    node = (void *)((uint64_t)node + sizeof(struct fdt_node_header) +
                                    strlen(node->name));
                }
                Info("node %p", node);
            } else if (is_prop(node)) {
                Info("prop");
                prop = (void *)node;
                Info("%p", __bswap_32(prop->tag));
                Info("%p", __bswap_32(prop->len));
                Info("%p", __bswap_32(prop->nameoff));
                char *name =
                    (void *)(first_string_addr(header) + __bswap_32(prop->nameoff));
                Info("%s", name);
                node = (void *)(uint64_t)node +
                       (__bswap_32(prop->len) / sizeof(uint32_t)) * 4 +
                       sizeof(struct fdt_property);
                Info("node %p", node->tag);
            } else if (is_nop(node)) {
                Info("nop");
                node = (void *)((uint64_t *)node + 1);
            } else if (is_end_node(node)) {
                Info("endnode");
                node = (void *)((uint64_t *)node + 1);
            }
        }
    }
}
