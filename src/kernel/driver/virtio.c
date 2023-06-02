#include "include/virtio.h"
#include "include/alloc.h"
#include "include/list.h"
#include "include/log.h"
#include "include/page_table.h"
#include "include/riscv.h"
#include "include/string.h"

static struct disk {
#define PAGE_SIZE 4096
    char pages[2 * PAGE_SIZE];
    struct virtq_desc *desc;

    struct virtq_avail *avail;

    struct virtq_used *used;

    char free[NUM];
    uint16_t used_idx;

    struct {
        struct buf *buf;
        char status;
    } info[NUM];

    int queue_running;

    struct virtio_blk_req ops[NUM];
} __attribute__((aligned(PAGE_SIZE))) disk;

static int virtio_queue_init() {
    // 初始化队列选择为0
    WRITE_VIRTIO_REG(QUEUE_SEL_W, 0);

    uint32_t queue_pfn = READ_VIRTIO_REG(V1_QUEUE_PFN_W);
    if (queue_pfn != 0) {
        Error("queue pfn !=0 ");
        return -1;
    }

    uint32_t max_queue_num = READ_VIRTIO_REG(QUEUE_NUM_MAX_R);
    if (max_queue_num == 0) {
        Error("max queue num is 0");
        return -2;
    }
    if (max_queue_num < NUM) {
        Error("queue too short");
        return -3;
    }

#define PAGE_SIZE 4096
#define PAGE_SHIFT 12
    //    uintptr_t virtq = palloc(2 * PAGE_SIZE);
    memset((void *)disk.pages, 0, sizeof(disk.pages));

    disk.desc = (void *)(disk.pages);
    // desc大小等于sizeof(struct virtq_desc)*NUM

    uint64_t avail_addr =
        (uint64_t)((char *)disk.desc + sizeof(struct virtq_desc) * NUM);

    // avail 大小等于6+(2*NUM)
    disk.avail = (void *)PALIGN_UP(avail_addr, 16);

    uint64_t used_addr = (uint64_t)((char *)disk.pages + 4096);
    Info("used addr :%x", used_addr);

    // used ring对齐到页面大小
    disk.used = (void *)PALIGN_UP(used_addr, 2);
    Info("palign up used addr : %x", disk.used);

    // mmio要求写入该寄存器
    // pci貌似要求不写该寄存器
    // 队列大小（队列条目数）写入NUM寄存器
    WRITE_VIRTIO_REG(QUEUE_NUM_W, NUM);
    Info("max_queue_num %d", max_queue_num);

    // used ring的对齐字节数写入ALIGN
    WRITE_VIRTIO_REG(V1_QUEUE_ALIGN_W, PAGE_SIZE);

    // 将第一页的物理编号写入PFN
    WRITE_VIRTIO_REG(V1_QUEUE_PFN_W, (uint64_t)disk.pages >> PAGE_SHIFT);

    for (int i = 0; i < NUM; i++) {
        disk.free[i] = 1;
    }

    return 0;
}

static inline int device_legal() {
    if (READ_VIRTIO_REG(MAGIC_R) != VIRTIO_MAGIC) {
        return -1;
    }
    if (READ_VIRTIO_REG(VERSION_R) != VIRTIO_VERSION_V1) {
        return -2;
    }
    if (READ_VIRTIO_REG(DEVICE_ID_R) != VIRTIO_DEVICE_TYPE_BLOCK_DEVICE) {
        return -3;
    }
    if (READ_VIRTIO_REG(VENDOR_ID_R) != VIRTIO_VENDOR) {
        return -4;
    }
    return 0;
}

int device_init() {
    // 判断设备是否合法
    if (device_legal() != 0) {
        Error("cannot find virtio disk");
        return -1;
    }

    // reset device
    WRITE_VIRTIO_REG(STATUS_RW, 0);

    // 设置ack和driver
    uint32_t status = READ_VIRTIO_REG(STATUS_RW) |
                      VIRTIO_DEVICE_STATUS_ACKNOWLEDGE |
                      VIRTIO_DEVICE_STATUS_DRIVER;
    WRITE_VIRTIO_REG(STATUS_RW, status);

    // 读取并设置特征位，以表示驱动支持的功能
    //  读取features前先写入sel
    WRITE_VIRTIO_REG(DEVICE_FEATURES_SEL_W, 0);
    uint32_t features = READ_VIRTIO_REG(DEVICE_FEATURES_R);

struct virtio_blk_config *blk_config = (void *)VIRTIO_REG_ADDR(CONFIG_RW);
    Info("blk_config cap %x", blk_config->capacity);
    Info("blk_config size max %x", blk_config->size_max);
    Info("blk_config seg max %d", blk_config->seg_max);

    features &= ~FEATURE_V(VIRTIO_BLK_F_RO_P);
    features &= ~FEATURE_V(V1_VIRTIO_BLK_F_SCSI_P);
    features &= ~FEATURE_V(VIRTIO_BLK_F_CONFIG_WCE_P);
    features &= ~FEATURE_V(VIRTIO_BLK_F_MQ);
    features &= ~FEATURE_V(VIRTIO_F_ANY_LAYOUT);     // unset f any layout
    features &= ~FEATURE_V(VIRTIO_RING_F_EVENT_IDX); // unset ring f event idx
    features &=
        ~FEATURE_V(VIRTIO_RING_F_INDIRECT_DESC); // unset ring f indiect desc
    Info("features %x", features);

    // 写入features之前先写入sel
    WRITE_VIRTIO_REG(DRIVER_FEATURES_SEL_W, 0);
    WRITE_VIRTIO_REG(DRIVER_FEATURES_W, features);

    //
    // 设置features ok状态，然而v1设备不支持该标志，设置不设置无所谓
    status |= VIRTIO_DEVICE_STATUS_FEATURES_OK;
    WRITE_VIRTIO_REG(STATUS_RW, status);

    // 重读feature ok位判断功能集是否被支持，v1版不支持该功能，但是也可以读出
    if (READ_VIRTIO_REG(STATUS_RW) & VIRTIO_DEVICE_STATUS_FEATURES_OK) {
        Info("features ok");
    } else {
        return -5;
    }

    // 设置driver ok表示设备活跃
    status |= VIRTIO_DEVICE_STATUS_DRIVER_OK;
    WRITE_VIRTIO_REG(STATUS_RW, status);

#define VIRTIO_PAGE_SIZE 4096
    // 写完之后只能马上读，才有合适的值
    WRITE_VIRTIO_REG(V1_GUEST_PAGE_SIZE, VIRTIO_PAGE_SIZE);

    virtio_queue_init();

    return 0;
}

static int alloc_desc() {
    for (int i = 0; i < NUM; i++) {
        if (disk.free[i]) {
            disk.free[i] = 0;
            return i;
        }
    }
    return -1;
}

static void free_desc(int i) {
    if (i > NUM) {
        return;
    }
    if (disk.free[i]) {
        return;
    }

    disk.desc[i].addr = 0;
    disk.desc[i].len = 0;
    disk.desc[i].flags = 0;
    disk.desc[i].next = 0;
    disk.free[i] = 1;
}

static void free_chain(int i) {
    while (1) {
        int flag = disk.desc[i].flags;
        int next = disk.desc[i].next;
        free_desc(i);
        if (flag & VIRTQ_DESC_F_NEXT) {
            i = next;
        } else {
            break;
        }
    }
}

static int alloc3_desc(int *idx) {
    for (int i = 0; i < 3; i++) {
        idx[i] = alloc_desc();
        if (idx[i] < 0) {
            for (int j = 0; j < i; j++) {
                free_desc(idx[j]);
            }
            return -1;
        }
    }
    return 0;
}

void virtio_disk_rw(struct buf *buf, int write) {
    // 因为读写磁盘需要确定的磁盘号，因此需要记录磁盘号写到那里了
    uint64_t sector = buf->blockno * (BUF_SIZE / 512);

    int idx[3];
    while (1) {
        if (alloc3_desc(idx) == 0) {
            break;
        }
        Error("error idx full");
        // yield
    }

    struct virtio_blk_req *buf0 = &disk.ops[idx[0]];

    if (write) {
        buf0->type = VIRTIO_BLK_T_OUT;
    } else {
        buf0->type = VIRTIO_BLK_T_IN;
    }

    buf0->reserved = 0;
    buf0->sector = sector;

    disk.desc[idx[0]].addr = (uint64_t)buf0;
    disk.desc[idx[0]].len = sizeof(struct virtio_blk_req);
    disk.desc[idx[0]].flags = VIRTQ_DESC_F_NEXT;
    disk.desc[idx[0]].next = idx[1];

    disk.desc[idx[1]].addr = (uint64_t)buf->data;
    disk.desc[idx[1]].len = BUF_SIZE;
    if (write) {
        // 否则设置flag为0
        disk.desc[idx[1]].flags = 0;
    } else {
        // 如果是设备可写的则设置该标志
        // 意思是如果是驱动读出，则是设备写入：设置了write，如果是写入设备，则驱动写入，设备读出不设置write

        disk.desc[idx[1]].flags = VIRTQ_DESC_F_WRITE;
    }
    disk.desc[idx[1]].flags |= VIRTQ_DESC_F_NEXT;
    disk.desc[idx[1]].next = idx[2];

    disk.info[idx[0]].status = 0xfb;
    disk.desc[idx[2]].addr = (uint64_t)&disk.info[idx[0]].status;
    disk.desc[idx[2]].len = 1;
    disk.desc[idx[2]].flags = VIRTQ_DESC_F_WRITE;
    disk.desc[idx[2]].next = 0;

    buf->disk = 1;
    disk.info[idx[0]].buf = buf;

    disk.avail->ring[disk.avail->idx % NUM] = idx[0];

    __sync_synchronize();

    disk.avail->idx += 1;

    __sync_synchronize();

    WRITE_VIRTIO_REG(QUEUE_NOTIFY_W, 0); // queue number

    struct buf volatile *b = buf;

    __sync_synchronize();

    smod_enable_trap;
    while (b->disk == 1) {
        // yield()
    }

    __sync_synchronize();
    smod_disable_trap;
    disk.info[idx[0]].buf = 0;
    free_chain(idx[0]);
}

int init_virtio() {

    Info("%x", device_init());
    Info("%x", *VIRTIO_REG_ADDR(DEVICE_FEATURES_R));
    WRITE_VIRTIO_REG(DEVICE_FEATURES_SEL_W, 0)
    Info("page size %d", READ_VIRTIO_REG(V1_GUEST_PAGE_SIZE));
    return 0;
}

void virtio_disk_intr() {
    WRITE_VIRTIO_REG(INTERRUPT_ACK_W, READ_VIRTIO_REG(INTERRUPT_STATUS_R) & 0x3);
    __sync_synchronize();

    while (disk.used_idx != disk.used->idx) {
        __sync_synchronize();
        int id = disk.used->ring[disk.used_idx % NUM].id;

        if (disk.info[id].status != 0) {
            Error("error disk info status not 0");
            while (1) {
            }
        }

        struct buf *b = disk.info[id].buf;
        b->disk = 0;
        disk.used_idx += 1;
    }
}
