#ifndef __BIO_H__
#define __BIO_H__

#include "include/type.h"
#include "include/virtio.h"

struct buf *bread(uint32_t dev, uint32_t blockno);
void bwrite(struct buf *b);
void brelse(struct buf *b);
void binit();
#endif
