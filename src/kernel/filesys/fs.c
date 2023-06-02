#include "include/fs.h"
#include "include/alloc.h"
#include "include/bio.h"
#include "include/log.h"
#include "include/string.h"

void info_fat32_header(char *data) {
struct BPB_fields *fs = (void *)data;
    Info("bs jmp boot %x%x%x", fs->BS_JmpBoot[0], fs->BS_JmpBoot[1],
         fs->BS_JmpBoot[2]);

    Info("bs oem name %s", fs->BS_OEMName);
    Info("byts per sec %d", *(uint16_t *)fs->BPB_BytsPerSec);
    Info("sec per clus %d", fs->BPB_SecPerClus);
    Info("rsvd sec cnt %d", *(uint16_t *)fs->BPB_ResvdSecCnt);
    Info("num fats %d", fs->BPB_NumFATs);
    Info("root ent cnt %d", *(uint16_t *)fs->BPB_RootEntCnt);
    Info("tot sec 16 %d", *(uint16_t *)fs->BPB_TotSec16);
    Info("media %x", fs->BPB_Media);
    Info("fatsz 16 %d", *(uint16_t *)fs->BPB_FATSz16);
    Info("sec per trk %d", *(uint16_t *)fs->BPB_SecPerTrk);
    Info("num heads %d", *(uint16_t *)fs->BPB_NumHeads);
    Info("hiddsec %d", *(uint32_t *)fs->BPB_HiddSec);
    Info("tot sec 32 %d", *(uint32_t *)fs->BPB_TotSec32);
}

void info_fat32_seg(char *data) {
struct fat32_volumes_fields *fs = (void *)(data + 36);
    Info("fatsz 32 %d", *(uint32_t *)fs->BPB_FATSz32);
    Info("ext flags %d", *(uint16_t *)fs->BPB_ExtFlags);
    Info("fsver %d", *(uint16_t *)fs->BPB_FSVer);
    Info("root clus %d", *(uint32_t *)fs->BPB_RootClus);
    Info("fsinfo %d", *(uint16_t *)fs->BPB_FSInfo);
    Info("bk boot sec %d", *(uint16_t *)fs->BPB_BkBootSec);
    // Info("reserved %d",fs->BPB_Reserved[12]);
    Info("drv num %d", fs->BS_DrvNum);
    Info("reserved %d", fs->BS_Reserved);
    Info("boot sig %d", fs->BS_BootSig);
    Info("bs volid %d", *(uint32_t *)fs->BS_VolID);
    // Info("bs vollab %d",fs->BS_VolLab[11]);
    //    Info("file sys type %s", fs->BS_FilSysType);
    // Info("boot code 32 %d",fs->BS_BootCode32[420]);
    Info("boot sign %x", *(uint16_t *)fs->BS_BootSign);
}

char *parse_entry(char *address, char *end_address, struct file *f) {
    if (address[0] == 0x00 || address[0] == 0xe5 ||
            (address + sizeof(struct fat_dir)) > end_address) {
        return address;
    }

    char name[128];
    memset(name, 0, 128);
    int idx = 0;
struct fat_dir *dir_entrys = (void *)address;
struct lfn_entry *lfn_entry = (void *)dir_entrys;
    char *next_addr = address;
    if (dir_entrys->DIR_Attr == ATTR_LONG_FILE_NAME) {
        if (dir_entrys->DIR_Name[0] & LAST_LONG_ENTRY) {

            // 本条目是end，所以先移动到下一个条目
            dir_entrys = (void *)((uintptr_t)dir_entrys + sizeof(struct fat_dir));
            if ((uintptr_t)dir_entrys >= (uintptr_t)end_address) {
                return next_addr;
            }

            // 迭代本条目的长文件名信息
            while (dir_entrys->DIR_Name[0] < 20 && dir_entrys->DIR_Name[0] != 0x00 &&
                    ((uintptr_t)dir_entrys) + sizeof(struct fat_dir) <
                    (uintptr_t)end_address) {
                dir_entrys = (void *)((uintptr_t)dir_entrys + sizeof(struct fat_dir));
            }
            if ((uintptr_t)dir_entrys >= (uintptr_t)end_address) {
                return next_addr;
            }

            strncpy(f->sfn_name, (void *)dir_entrys->DIR_Name,
                    strlen((void *)dir_entrys->DIR_Name));
            f->fsize = dir_entrys->DIR_FileSize;
            Info("hi %x lo %x", dir_entrys->DIR_FstClusHI, dir_entrys->DIR_FstClusL0);
            f->start_cluster =
                dir_entrys->DIR_FstClusHI << 16 | dir_entrys->DIR_FstClusL0;

            f->cdata = dir_entrys->DIR_CrtData;
            f->ctime = dir_entrys->DIR_CrtTime;
            f->mdata = dir_entrys->DIR_WrtDate;
            f->mtime = dir_entrys->DIR_WrtTime;
            f->fflag = dir_entrys->DIR_Attr;
            // 游标已经指向下一个条目，所以回退
            dir_entrys = (void *)((uintptr_t)dir_entrys - sizeof(struct fat_dir));
        }

        // 处理长文件名
        lfn_entry = (void *)dir_entrys;

        // 处理指针指向下一个区域
        next_addr = (char *)dir_entrys + sizeof(struct fat_dir);
        while (dir_entrys->DIR_Name[0] < 20) {
            name[idx + 0] = lfn_entry->LDIR_Name1[0];
            name[idx + 1] = lfn_entry->LDIR_Name1[2];
            name[idx + 2] = lfn_entry->LDIR_Name1[4];
            name[idx + 3] = lfn_entry->LDIR_Name1[6];
            name[idx + 4] = lfn_entry->LDIR_Name1[8];

            name[idx + 5] = lfn_entry->LDIR_Name2[0];
            name[idx + 6] = lfn_entry->LDIR_Name2[2];
            name[idx + 7] = lfn_entry->LDIR_Name2[4];
            name[idx + 8] = lfn_entry->LDIR_Name2[6];
            name[idx + 9] = lfn_entry->LDIR_Name2[8];
            name[idx + 10] = lfn_entry->LDIR_Name2[10];

            name[idx + 11] = lfn_entry->LDIR_Name3[0];
            name[idx + 12] = lfn_entry->LDIR_Name3[2];
            name[idx + 13] = 0x00;
            idx += 13;
            // 回退，直到抵达上一个结尾处
            dir_entrys = (void *)((uintptr_t)dir_entrys - sizeof(struct fat_dir));
            lfn_entry = (void *)dir_entrys;
        }

        // 处理结尾处的值
        name[idx + 0] = lfn_entry->LDIR_Name1[0];
        name[idx + 1] = lfn_entry->LDIR_Name1[2];
        name[idx + 2] = lfn_entry->LDIR_Name1[4];
        name[idx + 3] = lfn_entry->LDIR_Name1[6];
        name[idx + 4] = lfn_entry->LDIR_Name1[8];

        name[idx + 5] = lfn_entry->LDIR_Name2[0];
        name[idx + 6] = lfn_entry->LDIR_Name2[2];
        name[idx + 7] = lfn_entry->LDIR_Name2[4];
        name[idx + 8] = lfn_entry->LDIR_Name2[6];
        name[idx + 9] = lfn_entry->LDIR_Name2[8];
        name[idx + 10] = lfn_entry->LDIR_Name2[10];

        name[idx + 11] = lfn_entry->LDIR_Name3[0];
        name[idx + 12] = lfn_entry->LDIR_Name3[2];
        name[idx + 13] = 0x00;
        name[idx + 14] = 0x00;
        name[idx + 15] = 0x00;
        strncpy(f->lfn_name, (void *)name, strlen(name));
    } else {
        next_addr += sizeof(struct fat_dir);
    }
    return next_addr;
}

void init_fat32(char *data, uintptr_t d) {
struct BPB_fields *bpb = (void *)data;
struct fat32_volumes_fields *fat32seg = (void *)(data + 36);
    // struct fat32disk *disk = (void *)kalloc(sizeof(struct fat32disk));
struct fat32disk *disk = (void *)d;
    if (bpb->BS_JmpBoot[0] != 0xeb) {
        Error("rsvd sec cnt = 0");
        return;
    }
    // 扇区大小，有效值为 512 1024 2048 4096
    if (*(uint16_t *)bpb->BPB_BytsPerSec != 512 &&
            *(uint16_t *)bpb->BPB_BytsPerSec != 1024 &&
            *(uint16_t *)bpb->BPB_BytsPerSec != 2048 &&
            *(uint16_t *)bpb->BPB_BytsPerSec != 4096) {
        Error("byts per sec error");
        return;
    }
    disk->bpb_info.BytsPerSec = *(uint16_t *)bpb->BPB_BytsPerSec;
    // 每个cluster的扇区数，cluster也称为簇，有效值是1 2
    // 4 8...128，但是簇大小不应超过32KB
    if (bpb->BPB_SecPerClus * 512 >= 32 * 1024) {
        Error("sec per clus too big");
        return;
    }
    disk->bpb_info.SecPerClus = bpb->BPB_SecPerClus;
    // 保留区中的扇区数，不能为0，因为引导扇区本身在保留区中包含此BPB，fat32上通常为32
    if (*(uint16_t *)bpb->BPB_ResvdSecCnt == 0) {
        Error("resvd sec cnt = 0");
        return;
    }
    disk->bpb_info.ResvdSecCnt = *(uint16_t *)bpb->BPB_ResvdSecCnt;
    // fat的数量，应当始终为2
    if (bpb->BPB_NumFATs != 2) {
        Error("num fats != 2");
        return;
    }
    disk->bpb_info.NumFats = bpb->BPB_NumFATs;
    // 根目录中32字节目录条目的数量，应设置为根目录大小与2扇区边界对齐的值，该值*32应该是bytspresec的偶数倍，fat32中该字段为0
    if (*(uint16_t *)bpb->BPB_RootEntCnt != 0) {
        Error("root ent cnt != 0");
        return;
    }
    // 旧16位字段中卷的扇区总数，fat32中为0
    if (*(uint16_t *)bpb->BPB_TotSec16 != 0) {
        Error("tot sec16 != 0");
        return;
    }
    // 有效值为F0 F8 F9 FA FB FC FD FE FF
    if (bpb->BPB_Media != 0xF0 && bpb->BPB_Media != 0xF8 &&
            bpb->BPB_Media != 0xF9 && bpb->BPB_Media != 0xFA &&
            bpb->BPB_Media != 0xFB && bpb->BPB_Media != 0xFC &&
            bpb->BPB_Media != 0xFD && bpb->BPB_Media != 0xFE &&
            bpb->BPB_Media != 0xFF) {
        Error("media error");
        return;
    }

    if (*(uint16_t *)fat32seg->BS_BootSign != 0xAA55) {
        Error("not a full disk");
        return;
    }
    disk->bpb_info.TotSec32 = *(uint32_t *)bpb->BPB_TotSec32;
    disk->bpb_info.FatSz32 =
        (*(uint32_t *)fat32seg->BPB_FATSz32) * disk->bpb_info.NumFats;

    info_fat32_header(data);
    info_fat32_seg(data);

    //    struct fat32_disk fat32disk;
    disk->bpb_info.FatStartSector = *(uint16_t *)bpb->BPB_ResvdSecCnt;
    disk->bpb_info.FatSectors =
        (*(uint32_t *)fat32seg->BPB_FATSz32) * (bpb->BPB_NumFATs);

    Info("fat start sector %d sectors %d", disk->bpb_info.FatStartSector,
         disk->bpb_info.FatSectors);

    disk->bpb_info.RootDirStartSector =
        disk->bpb_info.FatStartSector + disk->bpb_info.FatSectors;
    disk->bpb_info.RootDirSectors = (32 * (*(uint16_t *)bpb->BPB_RootEntCnt) +
                                     (*(uint16_t *)bpb->BPB_BytsPerSec) - 1) /
                                    (*(uint16_t *)bpb->BPB_BytsPerSec);

    disk->bpb_info.DataStartSector =
        disk->bpb_info.RootDirStartSector + disk->bpb_info.RootDirSectors;
    disk->bpb_info.DataSectors =
        (*(uint32_t *)bpb->BPB_TotSec32) - (disk->bpb_info.DataStartSector);
    Info("data start sector %d sectors %d", disk->bpb_info.DataStartSector,
         disk->bpb_info.DataSectors);

    disk->bpb_info.CountofClusters =
        disk->bpb_info.DataSectors / bpb->BPB_SecPerClus;
    if (disk->bpb_info.CountofClusters > 65526) {
        Info("fat32 disk");
    }

    memset(disk->fds, 0, sizeof(disk->fds));
    disk->fds[0] = 1;

    list_dir(disk->bpb_info.DataStartSector, NULL);
    // #define N 1
    //     struct fat32_disk fat32disk;
    //     fat32disk.ThisFATSecNum = (*(uint16_t *)bpb->BPB_ResvdSecCnt +
    //                                (N * 4 / (*(uint16_t
    //                                *)bpb->BPB_BytsPerSec)));
    //     fat32disk.ThisFATEntOffset = (N * 4) % *(uint16_t
    //     *)bpb->BPB_BytsPerSec;
    //
    //     Info("fat32 %d", fat32disk.CountofClusters);
}

uint8_t alloc_fd(uintptr_t disk) {
struct fat32disk *d = (void *)disk;
    for (int i = 0; i < FILES; i++) {
        if (d->fds[i] == 0) {
            return i;
        }
    }
    return 0;
}

void free_fds(uintptr_t disk, uint8_t fd) {
struct fat32disk *d = (void *)disk;
    d->fds[fd] = 0;
}

uintptr_t list_dir(uint32_t start_sector, char *filename) {
    int sector_idx = 0;
struct buf *dir_temp_buf = bread(1, start_sector + sector_idx);
    char data_buf[4096] = {0};

    memmove(data_buf + sector_idx * 512, dir_temp_buf->data, 512);

    sector_idx++;
struct file *f = (void *)kalloc(sizeof(struct file));
    char *cursor = data_buf;
    char *end_cursor = data_buf + 512 * (sector_idx);

    char *old_cursor = cursor;

    while (cursor[0] != 0x00 && cursor[0] != 0xE5 &&
            cursor + sizeof(struct fat_dir) < end_cursor) {
        cursor = parse_entry(old_cursor, end_cursor, f);
        if (old_cursor != cursor) {

            if (filename != NULL) {
                if (strncmp(filename, f->lfn_name, sizeof(f->lfn_name)) == 0) {
                    return (uintptr_t)f;
                }
            }
            Info(
                "sfn name %s lfn name %s fsize %d mdata %d cdata %d start_cluster %d",
                f->sfn_name, f->lfn_name, f->fsize, f->mdata, f->cdata,
                f->start_cluster);
        }

        if ((uintptr_t)cursor + sizeof(struct fat_dir) >= (uintptr_t)end_cursor ||
                old_cursor == cursor) {

            dir_temp_buf = bread(1, start_sector + sector_idx);
            memmove(data_buf + (sector_idx * 512), dir_temp_buf->data, 512);

            sector_idx++;

            end_cursor = data_buf + 512 * sector_idx;
        }
        old_cursor = cursor;
    }
    //    Info("cursor %x end_cursor %x is bigger %d size %d", cursor, end_cursor,
    //         cursor + sizeof(struct fat_dir) > end_cursor, sizeof(struct
    //         fat_dir));
    Info("end ls dir");
    return NULL;
}

int open(uintptr_t disk, char *filename) {
struct fat32disk *d = (void *)disk;
struct file *f = (void *)list_dir(d->bpb_info.DataStartSector, filename);
    if (f != NULL) {
        uint8_t fd = alloc_fd(disk);
        d->file[fd] = f;
        return fd;
    }
    return 0;
}

void close(uintptr_t disk, uint32_t fd) {
struct fat32disk *d = (void *)disk;
    d->fds[fd] = 0;
}

int read(uintptr_t disk, uint8_t fd, uintptr_t target_address, uint32_t size) {
struct fat32disk *d = (void *)disk;

    // 数据开始的簇号
    int N = d->file[fd]->start_cluster;

    // 由簇号计算得出扇区号
    uint32_t FirstSectorofCluster =
        d->bpb_info.DataStartSector + (N - 2) * d->bpb_info.SecPerClus;

    // 该簇号在fat区域中的扇区号
    uint32_t fatsecnum =
        d->bpb_info.ResvdSecCnt + (N * 4 / d->bpb_info.BytsPerSec);
    // fat区域偏移量
    uint32_t fatenoffset = (N * 4) % d->bpb_info.BytsPerSec;
    Info("fat sec num %d,offset %d", fatsecnum, fatenoffset);

    // 看下后续是否还有文件
    //     d->file[fd]->buf = bread(1, fatsecnum);
    //     uint32_t entry =
    //         (*(uint32_t *)(&(d->file[fd]->buf->data[fatenoffset]))) &
    //         0x0FFFFFFF;

    //    Info("entry %x", entry);

    // 读数据
    d->file[fd]->buf = bread(1, FirstSectorofCluster);
    memmove((void *)target_address, d->file[fd]->buf->data, size);

    //    Info("%s", d->file[fd]->buf->data);

    return 0;
}
