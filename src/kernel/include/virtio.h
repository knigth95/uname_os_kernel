#ifndef __VIRTIO_H__
#define __VIRTIO_H__
#include "include/type.h"

// 小端顺序
#define VIRTIO_MAGIC 0x74726976
#define VIRTIO_VENDOR 0x554d4551

// 版本
#define VIRTIO_VERSION_V1 0x01
#define VIRTIO_VERSION_V2 0x02

// 设备类型将
#define VIRTIO_DEVICE_TYPE_NETWORK_CARD 0x01
#define VIRTIO_DEVICE_TYPE_BLOCK_DEVICE 0x02
#define VIRTIO_DEVICE_TYPE_CONSOLE 0x03
#define VIRTIO_DEVICE_TYPE_ENTROPY_SOURCE 0x04
#define VIRTIO_DEVICE_TYPE_MEMORY_BALLOONING 0x05
#define VIRTIO_DEVICE_TYPE_IO_MEMORY 0x06
#define VIRTIO_DEVICE_TYPE_RPMSG 0x07
#define VIRTIO_DEVICE_TYPE_SCSI_HOST 0x08

// 设备状态
#define VIRTIO_DEVICE_STATUS_ACKNOWLEDGE 0x01
#define VIRTIO_DEVICE_STATUS_DRIVER 0x02
#define VIRTIO_DEVICE_STATUS_DRIVER_OK 0x04
#define VIRTIO_DEVICE_STATUS_FEATURES_OK 0x08
#define VIRTIO_DEVICE_STATUS_DRIVER_NEEDS_RESET 0x40
#define VIRTIO_DEVICE_STATUS_DRIVER_FAILED 0x80

// virtio设备地址
#define VIRTIO_REG_BASE 0x10001000L

// 寄存器偏移量
#define MAGIC_R (0x000)
#define VERSION_R (0x004)
#define DEVICE_ID_R (0x008)
#define VENDOR_ID_R (0x00c)
#define DEVICE_FEATURES_R (0x010)
#define DEVICE_FEATURES_SEL_W (0x014)
#define DRIVER_FEATURES_W (0x020)
#define DRIVER_FEATURES_SEL_W (0x024)
#define V1_GUEST_PAGE_SIZE                                                     \
  (0x028) // 使用任何队列之前，在初始化期间，驱动程序会把guest
// page（字节为单位）写入寄存器，并且大小应当是2的幂，设备使用它来计算第一个队列页的访客地址
#define QUEUE_SEL_W                                                            \
  (0x030) // 写入该寄存器可以选择虚拟队列，第一个队列的索引号为0
#define QUEUE_NUM_MAX_R                                                        \
  (0x034) // 从寄存器读取设备准备处理的队列的最大大小，如果队列不可用则返回0x0
// 适用于通过写入queuesel选择的队列，并且仅当queuepfn设置为0时才允许，
#define QUEUE_NUM_W                                                            \
  (0x038) // 队列大小是队列元素的数量，写入此寄存器会通知设备驱动程序将使用的队列大小，适用于通过写入queuesel选择的队列
#define V1_QUEUE_ALIGN_W                                                       \
  (0x03c) // 写入该寄存器会通知设备有关已用环的对齐边界，该值是2的幂并且使用于通过写入queuesel选择的队列
#define V1_QUEUE_PFN_W                                                         \
  (0x040) // 写入该寄存器会通知设备虚拟队列在访客物理地址空间中的位置，该值是以队列描述符开始的页面的索引号，值0表示物理地址0，并且是非法的，驱动程序停止使用队列时，会将0写入该寄存器，读取该寄存器会返回队列当前使用的页码，因此非0值表示队列
#define V2_QUEUE_READY_RW (0x044)
#define QUEUE_NOTIFY_W (0x050)     // 队列通知
#define INTERRUPT_STATUS_R (0x060) // 中断状态
#define INTERRUPT_ACK_W (0x064)    // 中断确认
#define STATUS_RW (0x070) // 读取该寄存器返回当前设备状态，写入会标示状态
#define V2_QUEUE_DESC_LOW_W (0x080)
#define V2_QUEUE_DESC_HIGH_W (0x084)
#define V2_QUEUE_AVAIL_LOW_W (0x090)
#define V2_QUEUE_AVAIL_HIGH_W (0x094)
#define V2_QUEUE_USED_LOW_W (0x0a0)
#define V2_QUEUE_USED_HIGH_W (0x0a4)
#define V2_CONFIG_GENERATION_R (0x0fc)
#define CONFIG_RW (0x100)

// 将偏移与地址相加转换为寄存器地址
#define VIRTIO_REG_ADDR(offset) (volatile uint32_t *)(VIRTIO_REG_BASE + offset)

// 寄存器读写操作
#define READ_VIRTIO_REG(offset) *(VIRTIO_REG_ADDR(offset))
#define WRITE_VIRTIO_REG(offset, value) *(VIRTIO_REG_ADDR(offset)) = value;

// feature bits
// 特征位 0-23特定设备类型的功能位 24-32保留用于扩展队列和功能协商机制 33+
#define V1_VIRTIO_BLK_F_BARRIER_P (0) // 支持请求障碍
#define VIRTIO_BLK_F_SIZE_MAX_P (1)   // 任何单个段的最大大小
#define VIRTIO_BLK_F_SEG_MAX_P (2)    // 请求中的最大段数
#define VIRTIO_BLK_GEOMETRY_P (4)     // 在geometry中指定磁盘样式
#define VIRTIO_BLK_F_RO_P (5)         // 只读设备
#define VIRTIO_BLK_F_BLK_SIZE_P (6)   // 磁盘块的大小
#define V1_VIRTIO_BLK_F_SCSI_P (7)    // 支持scsi数据传输
#define VIRTIO_BLK_F_FLUSH_P (9)      // 缓存刷新命令支持
#define VIRTIO_BLK_F_TOPOLOGY_P (10) // 设备导出的有关最佳io对齐的信息
#define VIRTIO_BLK_F_CONFIG_WCE_P (11) // 设备可以在回写和直写模式之间切换内存
#define VIRTIO_BLK_F_MQ (12)
#define VIRTIO_F_ANY_LAYOUT (27)
#define VIRTIO_RING_F_INDIRECT_DESC (28)
#define VIRTIO_RING_F_EVENT_IDX (29)

// 取特征位
#define FEATURE_V(position) (uint32_t)(1 << position)

// 设备config
//  设备容量始终存在，其他的位取决与上述feature bits
struct virtio_blk_config {
    uint64_t capacity;
    uint32_t size_max;
    uint32_t seg_max;
    struct virtio_blk_geometry {
        uint16_t cylinders;
        uint8_t heads;
        uint8_t sectors;
    } geometry;
    uint32_t blk_size;
    struct virtio_blk_topology {
        // # of logical blocks per physical block (log2)
        uint8_t physical_block_exp;
        // offset of first aligned logical block
        uint8_t alignment_offset;
        // suggested minimum I/O size in blocks
        uint16_t min_io_size;
        // optimal (suggested maximum) I/O size in blocks
        uint32_t opt_io_size;
    } topology;
    uint8_t writeback;
}; // 设备配置布局

// 队列总数
#define NUM 32

#define DESC_ALIGN_BYTES(queue_size) (16 * queue_size)

// from kernel 描述符表
struct virtq_desc {
    // 指向一块保存有io data的share memory
    uint64_t addr;
    // 表示该块共享内存长度
    uint32_t len;
// this marks a buffer as continuing via the next field
#define VIRTQ_DESC_F_NEXT 1
// this marks a buffer as device write-only (otherwise device read-only)
#define VIRTQ_DESC_F_WRITE 2
// this means the buffer contains a list of buffer desc
#define VIRTQ_DESC_F_INDIRECT 4
    // the flags as indicated above 描述符属性
    uint16_t flags;
    // next field if flag & next 指向描述符表中的下一个描述符，相当于数组下标
    uint16_t next;
}; // 虚拟队列描述符表

// 可用环
#define AVAIL_ALIGN_BYTES(queue_size) (6 + 2 * queue_size)
struct virtq_avail {
#define VIRTQ_AVAIL_F_NO_INTERRUPT 1
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[NUM];
};

struct virtq_used_elem {
    uint32_t id;
    uint32_t len;
};

// 已用环
#define USED_ALIGN_BYTES(queue_size) (6 + 8 * queue_size)
struct virtq_used {
#define VIRTQ_USED_F_NO_NOTIFY 1
    uint16_t flags;
    uint16_t idx;
    struct virtq_used_elem ring[NUM];
    //    uint16_t avail_event;
};

// 队列
struct virtq {
    uint32_t num;
    struct virtq_desc *desc;
    struct virtq_avail *avail;
    struct virtq_used *used;
};

// final status 请求状态由设备写入
#define VIRTIO_BLK_S_OK 0     // 成功
#define VIRTIO_BLK_S_IOERR 1  // 程序或者驱动错误
#define VIRTIO_BLK_S_UNSUPP 2 // 表示设备不支持的请求

// 驱动程序会将请求排队到virtqueue，然后设备会读取请求
//  req type 请求类型
// 扇区号表示读取或者写入发生的偏移量
#define VIRTIO_BLK_T_IN 0    // 读取请求
#define VIRTIO_BLK_T_OUT 1   // 写入请求
#define VIRTIO_BLK_T_FLUSH 4 // 刷新 刷新请求中不得包含任何数据
#define VIRTIO_BLK_T_DISCARD 11
#define VIRTIO_BLK_T_WRITE_ZEROES 13
// 请求
struct virtio_blk_req {
    uint32_t type;
    uint32_t reserved;
    uint64_t sector;
};

struct virtio_blk_discard_write_zeroes {
    uint64_t sector;
    uint32_t num_sectors;
    struct {
        uint32_t unmap : 1;
        uint32_t reserved : 31;
    } flags;
};

#define BUF_SIZE 512
struct buf {
    int valid; // has data been read from disk?
    int disk;  // does disk "own" buf?
    uint32_t dev;
    uint32_t blockno;
    uint32_t refcnt;
    struct buf *prev; // LRU cache list
    struct buf *next;
    uint8_t data[BUF_SIZE];
};

static inline int virtq_need_event(uint16_t event_idx, uint16_t new_idx,
                                   uint16_t old_idx) {
    return (uint16_t)(new_idx - event_idx - 1) < (uint16_t)(new_idx - old_idx);
}

/* Get location of event indices (only with VIRTIO_F_EVENT_IDX) */
static inline uint16_t *virtq_used_event(struct virtq *vq) {
    /* For backwards compat, used event index is at *end* of avail ring. */
    return &vq->avail->ring[vq->num];
}

static inline uint16_t *virtq_avail_event(struct virtq *vq) {
    /* For backwards compat, avail event index is at *end* of used ring. */
    return (uint16_t *)&vq->used->ring[vq->num];
}
// struct virtio_config_ops {
//     bool (*feature)(struct virtio_device *vdev, unsigned bit);
//     void (*get)(struct virtio_device *vdev, unsigned offset, void *buf,
//                 unsigned len);
//     void (*set)(struct virtio_device *vdev, unsigned offset, const void *buf,
//                 unsigned len);
//     u8 (*get_status)(struct virtio_device *vdev);
//     void (*set_status)(struct virtio_device *vdev, u8 status);
//     void (*reset)(struct virtio_device *vdev);
//     struct virtqueue *(*find_vq)(struct virtio_device *vdev, unsigned index,
//                                  void (*callback)(struct virtqueue *));
//     void (*del_vq)(struct virtqueue *vq);
// };
//
// struct virtqueue_ops {
//     int (*add_buf)(struct virtqueue *vq, struct scatterlist sg[],
//                    unsigned int out_num, unsigned int in_num, void *data);
//
//     void (*kick)(struct virtqueue *vq);
//
//     void *(*get_buf)(struct virtqueue *vq, unsigned int *len);
//
//     void (*disable_cb)(struct virtqueue *vq);
//     bool (*enable_cb)(struct virtqueue *vq);
// };

int init_virtio();
void virtio_disk_rw(struct buf *buf, int write);
void virtio_disk_intr();
#endif
