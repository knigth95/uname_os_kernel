#include "include/log.h"
#include "include/type.h"
#include "include/virtio.h"

#define MAXOPBLOCKS 512        // max # of blocks any FS op writes
#define NBUF (MAXOPBLOCKS * 3) // size of disk block cache
struct {
    struct buf buf[NBUF];
    struct buf head;
} bcache;

void binit() {
    struct buf *b;
    // Create linked list of buffers
    bcache.head.prev = &bcache.head;
    bcache.head.next = &bcache.head;
    for (b = bcache.buf; b < bcache.buf + NBUF; b++) {
        b->next = bcache.head.next;
        b->prev = &bcache.head;
        bcache.head.next->prev = b;
        bcache.head.next = b;
    }
}

// Look through buffer cache for block on device dev.
// If not found, allocate a buffer.
static struct buf *bget(uint32_t dev, uint32_t blockno) {
    struct buf *b;
    // Is the block already cached?
    for (b = bcache.head.next; b != &bcache.head; b = b->next) {
        if (b->dev == dev && b->blockno == blockno) {
            b->refcnt++;
            return b;
        }
    }
    // Not cached.
    // Recycle the least recently used (LRU) unused buffer.
    for (b = bcache.head.prev; b != &bcache.head; b = b->prev) {
        if (b->refcnt == 0) {
            b->dev = dev;
            b->blockno = blockno;
            b->valid = 0;
            b->refcnt = 1;
            return b;
        }
    }
    Error("bget: no buffers");
    return 0;
}

const int R = 0;
const int W = 1;

// Return a buf with the contents of the indicated block.
struct buf *bread(uint32_t dev, uint32_t blockno) {
    struct buf *b;
    b = bget(dev, blockno);
    if (!b->valid) {
        virtio_disk_rw(b, R);
        b->valid = 1;
    }
    //    Info("over");
    return b;
}

// Write b's contents to disk.
void bwrite(struct buf *b) {
    virtio_disk_rw(b, W);
}

// Release a buffer.
// Move to the head of the most-recently-used list.
void brelse(struct buf *b) {
    b->refcnt--;
    if (b->refcnt == 0) {
        // no one is waiting for it.
        b->next->prev = b->prev;
        b->prev->next = b->next;
        b->next = bcache.head.next;
        b->prev = &bcache.head;
        bcache.head.next->prev = b;
        bcache.head.next = b;
    }
}

void bpin(struct buf *b) {
    b->refcnt++;
}

void bunpin(struct buf *b) {
    b->refcnt--;
}
