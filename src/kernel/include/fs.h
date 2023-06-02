#ifndef __FS_H__
#define __FS_H__
#include "include/type.h"
struct BPB_fields {
    // 引导程序代码的跳转指令
    uint8_t BS_JmpBoot[3];
    // 只是个名字
    uint8_t BS_OEMName[8];
    // 扇区大小，有效值为 512 1024 2048 4096
    uint8_t BPB_BytsPerSec[2];
    // 每个cluster的扇区数，cluster也称为簇，有效值是1 2
    // 4 8...128，但是簇大小不应超过32KB
    uint8_t BPB_SecPerClus;
    // 保留区中的扇区数，不能为0，因为引导扇区本身在保留区中包含此BPB，fat32上通常为32
    uint8_t BPB_ResvdSecCnt[2];
    // fat的数量，应当始终为2
    uint8_t BPB_NumFATs;
    // 根目录中32字节目录条目的数量，应设置为根目录大小与2扇区边界对齐的值，该值*32应该是bytspresec的偶数倍，fat32中该字段为0
    uint8_t BPB_RootEntCnt[2];
    // 旧16位字段中卷的扇区总数，fat32中为0
    uint8_t BPB_TotSec16[2];
    // 有效值为F0 F8 F9 FA FB FC FD FE FF
    uint8_t BPB_Media;
    // fat 占用的扇区数，fat32中为0并使用fatsz32替代
    uint8_t BPB_FATSz16[2];
    // 每个磁道的扇区数，仅仅和IBMPC的磁盘bios介质有关
    uint8_t BPB_SecPerTrk[2];
    // 头数，无关
    uint8_t BPB_NumHeads[2];
    // 无关
    uint8_t BPB_HiddSec[4];
    // 所有四个区域的扇区总数fat32上该值始终有效，
    uint8_t BPB_TotSec32[4];
};

struct fat32_volumes_fields {
    // fat的大小（以扇区为单位），fat区的大小为BPB_FATSz32*BPB_NumFATs
    uint8_t BPB_FATSz32[4];
    // bit 3-0:active fat 从0开始，bit7为1时有效
    // bit 6-4:保留0
    // bit 7
    // :表示每个fat都处于活动状态和镜像状态，1表示中有一个由bit3-0指示的fat处于活动状态
    // bit 15-8-4:保留
    uint8_t BPB_ExtFlags[2];
    // fat32版本，高字节是主版本号，低字节是次版本号
    uint8_t BPB_FSVer[2];
    // 根目录的第一个簇号，通常为2，卷的第一个簇，但不需要始终为2
    uint8_t BPB_RootClus[4];
    // fsinfo结构的扇区与fat32卷顶部的偏移量
    uint8_t BPB_FSInfo[2];
    // 从fat32卷顶部偏移的备份引导扇区，通常为6，位于引导扇区旁边，但不建议设置为6和任何其他1值
    uint8_t BPB_BkBootSec[2];
    // 保留
    uint8_t BPB_Reserved[12];
    // 保留
    uint8_t BS_DrvNum;
    // 保留
    uint8_t BS_Reserved;
    // 保留
    uint8_t BS_BootSig;
    // 保留
    uint8_t BS_VolID[4];
    // 保留
    uint8_t BS_VolLab[11];
    // 始终为fat32，对类型确定无影响
    uint8_t BS_FilSysType[8];
    // 引导程序，平台相关的，不使用是填充0
    uint8_t BS_BootCode32[420];
    // 0xAA55有效引导扇区
    uint8_t BS_BootSign[2];
};

struct fat32_disk {
    uint32_t FatStartSector;
    uint32_t FatSectors;
    uint32_t RootDirStartSector;
    uint32_t RootDirSectors;
    uint32_t DataStartSector;
    uint32_t DataSectors;
    uint32_t CountofClusters;
    uint32_t ThisFATSecNum;
    uint32_t ThisFATEntOffset;
};

struct fat_dir {
    // DIR_Name:
    // 0xE5 已经删除的条目会将第一个字节设置为E5
    // 0x05
    // 0x2E 单个.以及两个..
    // 0x00
    uint8_t DIR_Name[11];

    // 只读文件，拒绝任何更改或者删除
#define ATTR_READ_ONLY 0x01
    // 正常直接列出不应当显示该文件
#define ATTR_HIDDEN 0x02
    // 这是一个系统文件
#define ATTR_SYSTEM 0x04
    // 这是一个目录的容器
#define ATTR_VOLUME_ID 0x08
    // 这是用于备份
#define ATTR_DIRECTORY 0x10
    // 具有此属性的条目具有卷的卷标，根目录中只能存在一个条目
#define ATTR_ARCHIVE 0x20
    // 具有该属性的条目表示设备，不确定是否还在使用
#define ATTR_DEVICE 0x40
    // 表明该条目是长文件名的一部分
#define ATTR_LONG_FILE_NAME 0x0F
    uint8_t DIR_Attr;

#define Z_0x08 0x08
#define K_0x10 0x10
    uint8_t DIR_Ntres;
    // 亚秒级计数
    uint8_t DIR_CrtTimeTenth;
    // 文件创建时间
    uint16_t DIR_CrtTime;
    // 文件创建日期
    uint16_t DIR_CrtData;
    // 上次访问日期
    uint16_t DIR_LstAccDate;
    // 簇号的上层部分
    uint16_t DIR_FstClusHI;
    // 上次对文件进行任何更改的时间
    uint16_t DIR_WrtTime;
    // 对文件进行任何更改的时间
    uint16_t DIR_WrtDate;
    // 簇数的下半部分，文件大小为0时，不分配簇并且此项必须为0，如果该项是目录，则始终是一个有效值
    uint16_t DIR_FstClusL0;
    // 以字节为单位的文件大小，为目录时该值始终为0
    uint32_t DIR_FileSize;
};

struct lfn_entry {
// 表示LFN条目在整个LFN中的位置0x40表示LFN的最后部分
#define LAST_LONG_ENTRY 0x40
#define LAST_AND_FIRST 0x41
    uint8_t LDIR_0rd;
    uint8_t LDIR_Name1[10];
    uint8_t LDIR_Attr;
    // 必须为0
    uint8_t LDIR_Type;
    // 与此条目关联的SFN条目的校验和
    uint8_t LDIR_Chksum;
    // LFN的第6个字符到第11个字符
    uint8_t LDIR_Name2[12];
    // 必须为0以避免旧磁盘实用程序进行任何错误修复
    uint8_t LDIR_FstClusL0[2];
    // LFN的第12个字符到第14个字符
    uint8_t LDIR_Name3[4];
};

struct partition_table_entry {
    uint8_t PT_BootID;
    uint8_t PT_StartHd;
    uint8_t PT_StartCySc[2];
#define BLANKENTRY 0x00
#define FAT12 0x01
#define FAT16 0x04
#define EXTENDEDPARTITION 0x05
#define FAT12_16 0x06
#define HPFS_NTFS_exFAT 0x07
#define FAT32 0x0B
#define FAT32_LBA 0x0C
#define LBA_FAT12_16 0x0E
#define EXTENDEDPARTITION2 0x0F
    uint8_t PT_System;
    uint8_t PT_EndHd;
    uint8_t PT_EndCySc[2];
    uint8_t PT_Lba0fs[4];
    uint8_t PT_LbaSize[4];
};

struct BPB_info {
    uint16_t ResvdSecCnt;
    // 每个扇区大小
    uint16_t BytsPerSec;
    // 每个簇包含多少簇号
    uint8_t SecPerClus;
    // fat的数量
    uint8_t NumFats;
    // fat卷的所有扇区总数
    uint32_t TotSec32;
    // fat的大小，以扇区为单位，等于BPB_FATSz32*BPB_NumFATs
    uint32_t FatSz32;
    // 根目录的第一个簇号
    uint32_t RootClus;
    // fs info结构的扇区与fat32卷顶部的偏移量，通常为1
    uint16_t FsInfoOffset;
    // 两个字节保留空间
    uint16_t re;
    // fat区域的起始扇区号
    uint32_t FatStartSector;
    // fat扇区总数
    uint32_t FatSectors;
    // 根目录区域的起始扇区号
    uint32_t RootDirStartSector;
    // 根目录区域的扇区总数
    uint32_t RootDirSectors;
    // 数据区的起始扇区数
    uint32_t DataStartSector;
    // 数据区的扇区总数
    uint32_t DataSectors;
    // 簇总数
    uint32_t CountofClusters;
};

struct fat32disk {
    struct BPB_info bpb_info;
#define FILES 1024
    uint8_t fds[FILES];
    struct file *file[FILES];
};

typedef struct file {
    // 文件名
    char sfn_name[32];
    char lfn_name[128];
    // 文件大小
    uint64_t fsize;
#define DIR 1
#define FILE 0
    // 是否目录
    uint32_t isdir;
    // 修改时间
    uint32_t mdata;
    // 修改时间
    uint32_t mtime;
    // 创建时间
    uint32_t cdata;
    // 创建时间
    uint32_t ctime;
    // 权限
    uint32_t fflag;
    // 所属簇
    uint32_t start_cluster;
    // 所有簇数
    uint32_t clusters;
    // 读取或者写入在这个扇区中的偏移量
    uint32_t data_offset;
    struct buf *buf;
} file_t;

void init_fat32(char *data, uintptr_t d);
uintptr_t list_dir(uint32_t start_sector, char *filename);
uint8_t alloc_fd(uintptr_t disk);
void free_fds(uintptr_t disk, uint8_t fd);
int open(uintptr_t disk, char *filename);
int read(uintptr_t disk, uint8_t fd, uintptr_t target_address, uint32_t size);
void close(uintptr_t disk, uint32_t fd);
#endif
