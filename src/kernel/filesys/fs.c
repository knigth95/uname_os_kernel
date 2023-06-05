#include "include/fs.h"
#include "include/alloc.h"
#include "include/bio.h"
#include "include/log.h"
#include "include/proc.h"
#include "include/string.h"
#include "include/virtio.h"

#undef DEBUG
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
            (address + sizeof(struct sfn_entry)) > end_address) {
        return address;
    }

    char name[128];
    memset(name, 0, 128);
    int idx = 0;
struct sfn_entry *dir_entrys = (void *)address;
struct lfn_entry *lfn_entry = (void *)dir_entrys;
    char *next_addr = address;
    if (dir_entrys->DIR_Attr == ATTR_LONG_FILE_NAME) {
        if (dir_entrys->DIR_Name[0] & LAST_LONG_ENTRY) {

            // 本条目是end，所以先移动到下一个条目
            dir_entrys = (void *)((uintptr_t)dir_entrys + sizeof(struct sfn_entry));
            if ((uintptr_t)dir_entrys >= (uintptr_t)end_address) {
                return next_addr;
            }

            // 迭代本条目的长文件名信息
            while (dir_entrys->DIR_Name[0] < 20 && dir_entrys->DIR_Name[0] != 0x00 &&
                    ((uintptr_t)dir_entrys) + sizeof(struct sfn_entry) <
                    (uintptr_t)end_address) {
                dir_entrys = (void *)((uintptr_t)dir_entrys + sizeof(struct sfn_entry));
            }
            if ((uintptr_t)dir_entrys >= (uintptr_t)end_address) {
                return next_addr;
            }

            strncpy(f->sfn_name, (void *)dir_entrys->DIR_Name,
                    strlen((void *)dir_entrys->DIR_Name));
            f->fsize = dir_entrys->DIR_FileSize;
            f->start_cluster =
                dir_entrys->DIR_FstClusHI << 16 | dir_entrys->DIR_FstClusL0;

            f->cdata = dir_entrys->DIR_CrtData;
            f->ctime = dir_entrys->DIR_CrtTime;
            f->mdata = dir_entrys->DIR_WrtDate;
            f->mtime = dir_entrys->DIR_WrtTime;
            f->fflag = dir_entrys->DIR_Attr;
            // 游标已经指向下一个条目，所以回退
            dir_entrys = (void *)((uintptr_t)dir_entrys - sizeof(struct sfn_entry));
        }

        // 处理长文件名
        lfn_entry = (void *)dir_entrys;

        // 处理指针指向下一个区域
        next_addr = (char *)dir_entrys + sizeof(struct sfn_entry);
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
            dir_entrys = (void *)((uintptr_t)dir_entrys - sizeof(struct sfn_entry));
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
        next_addr += sizeof(struct sfn_entry);
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

#ifdef DEBUG
    info_fat32_header(data);
    info_fat32_seg(data);
#endif

    //    struct fat32_disk fat32disk;
    disk->bpb_info.FatStartSector = *(uint16_t *)bpb->BPB_ResvdSecCnt;
    disk->bpb_info.FatSectors =
        (*(uint32_t *)fat32seg->BPB_FATSz32) * (bpb->BPB_NumFATs);

#ifdef DEBUG
    Info("fat start sector %d sectors %d", disk->bpb_info.FatStartSector,
         disk->bpb_info.FatSectors);
#endif

    disk->bpb_info.RootDirStartSector =
        disk->bpb_info.FatStartSector + disk->bpb_info.FatSectors;
    disk->bpb_info.RootDirSectors = (32 * (*(uint16_t *)bpb->BPB_RootEntCnt) +
                                     (*(uint16_t *)bpb->BPB_BytsPerSec) - 1) /
                                    (*(uint16_t *)bpb->BPB_BytsPerSec);

    disk->bpb_info.DataStartSector =
        disk->bpb_info.RootDirStartSector + disk->bpb_info.RootDirSectors;
    disk->bpb_info.DataSectors =
        (*(uint32_t *)bpb->BPB_TotSec32) - (disk->bpb_info.DataStartSector);

#ifdef DEBUG
    Info("data start sector %d sectors %d", disk->bpb_info.DataStartSector,
         disk->bpb_info.DataSectors);
#endif

    disk->bpb_info.CountofClusters =
        disk->bpb_info.DataSectors / bpb->BPB_SecPerClus;

#ifdef DEBUG
    if (disk->bpb_info.CountofClusters > 65526) {
        Info("fat32 disk");
    }
#endif

    memset(disk->fds, 0, sizeof(disk->fds));
    disk->fds[0] = 1;
    disk->fds[1] = 1;
    disk->fds[2] = 1;

    extern AppFileNames_t global_loader;
    list_dir(disk->bpb_info.DataStartSector, NULL, &global_loader);
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

uintptr_t list_dir(uint32_t start_sector, char *filename, AppFileNames_t *afn) {
    int sector_idx = 0;
struct buf *dir_temp_buf = bread(1, start_sector + sector_idx);
    brelse(dir_temp_buf);
    //    char data_buf[4096] = {0};

    char *data_buf = (void *)kalloc(4096);

    memmove(data_buf + sector_idx * 512, dir_temp_buf->data, 512);

    sector_idx++;

struct file *f = (void *)kalloc(sizeof(struct file));

    char *cursor = data_buf;
    char *end_cursor = data_buf + 512 * (sector_idx);

    char *old_cursor = cursor;

    while (cursor[0] != 0x00 && cursor[0] != 0xE5 &&
            cursor + sizeof(struct sfn_entry) < end_cursor) {
        cursor = parse_entry(old_cursor, end_cursor, f);
        if (old_cursor != cursor) {

            // 判断是否存在该文件，并传出
            if (filename != NULL) {
                if (strncmp(filename, f->lfn_name, sizeof(f->lfn_name)) == 0) {
                    pfree((uintptr_t)data_buf);
                    return (uintptr_t)f;
                }
            }

#if DEBUG
            Info(
                "sfn name %s lfn name %s fsize %d mdata %d cdata %d start_cluster %d",
                f->sfn_name, f->lfn_name, f->fsize, f->mdata, f->cdata,
                f->start_cluster);
#endif

            if (afn != NULL) {
            struct file *afn_file = (void *)kalloc(sizeof(struct file));
                memmove(afn_file, f, sizeof(struct file));
                afn->app_files[afn->idx] = (uintptr_t)afn_file;
#if DEBUG

#endif
                afn->idx = afn->idx + 1;
            }
        }

        if ((uintptr_t)cursor + sizeof(struct sfn_entry) >= (uintptr_t)end_cursor ||
                old_cursor == cursor) {

            dir_temp_buf = bread(1, start_sector + sector_idx);
            brelse(dir_temp_buf);
            memmove(data_buf + (sector_idx * 512), dir_temp_buf->data, 512);

            sector_idx++;

            end_cursor = data_buf + 512 * sector_idx;
        }
        old_cursor = cursor;
    }

    //    Info("cursor %x end_cursor %x is bigger %d size %d", cursor, end_cursor,
    //         cursor + sizeof(struct sfn_entry) > end_cursor,
    //         sizeof(struct sfn_entry));
    //    Info("end ls dir");

    pfree((uintptr_t)data_buf);
    pfree((uintptr_t)f);
    return 0;
}

uint64_t find_free_direntry() {
    extern struct fat32disk disk;
    int dir_start_sector = disk.bpb_info.DataStartSector;

struct buf *dir_temp_buf = bread(1, dir_start_sector);
struct sfn_entry *data_buf = (void *)dir_temp_buf->data;
    memmove(data_buf, dir_temp_buf, 512);

    int idx = 0;
    int new_sector = dir_start_sector;

    while (data_buf[idx].DIR_Name[0] != 0x00 &&
            data_buf[idx].DIR_Name[0] != 0xE5) {
        idx += 1;
        if (idx % 16 == 0 && idx != 0) {
            idx = idx % 16;
            new_sector += 1;
            brelse(dir_temp_buf);
            data_buf = (void *)bread(1, new_sector)->data;
        }
    }
    uint64_t entry;
    ((struct free_entry *)&entry)->idx = idx;
    ((struct free_entry *)&entry)->sector = new_sector;
    Info("idx %d sector %d old sector %d", idx, new_sector,
         disk.bpb_info.DataStartSector);
    return entry;
}

int open(uintptr_t disk, char *filename) {
struct fat32disk *d = (void *)disk;
    extern AppFileNames_t global_loader;
    for (int i = 0; i < 1024; i++) {
        if (global_loader.app_files[i] == NULL) {
            break;
        }
        if (strncmp(((struct file *)(global_loader.app_files[i]))->lfn_name,
                    filename, strlen(filename)) == 0) {
            uint8_t fd = alloc_fd(disk);
        struct file *f = (void *)global_loader.app_files[i];
            f->openfds = 1;
            d->file[fd] = f;
            return fd;
        }
    }
    //    struct file *f = NULL;
    //    f = (void *)list_dir(d->bpb_info.DataStartSector, filename, NULL);
    //
    //    if (f != NULL) {
    //        uint8_t fd = alloc_fd(disk);
    //        f->openfds = 1;
    //        d->file[fd] = f;
    //        return fd;
    //    }
    return 0;
}

void close(uintptr_t disk, uint32_t fd) {
struct fat32disk *d = (void *)disk;
    if (fd < 3) {
        return;
    }
    // 该描述符对应的文件存在
    if (d->file[fd] != NULL && fd > 3) {
        // 否则需要先减少引用
        if (d->file[fd]->openfds > 1) {
            d->file[fd]--;
            // 如果已打开的只有一个可以直接释放
        } else {
            pfree((uintptr_t)d->file[fd]);
        }
    }
    d->file[fd] = NULL;
    d->fds[fd] = 0;
}

int fs_dup(uintptr_t disk, uint32_t fd) {
struct fat32disk *d = (void *)disk;
    struct file *dup_file = d->file[fd];
    // 如果该描述符没分配文件
    if (dup_file == NULL) {
        // 并且不是输入标准输入输出一类
        if (fd > 3) {
            // 则返回-1
            return -1;
        }
    }

    int dup_fd = alloc_fd(disk);
    d->file[dup_fd] = dup_file;
    if (d->file[dup_fd] != NULL) {
        d->file[dup_fd]->openfds++;
    }
    return dup_fd;
}

int fs_dup3(uintptr_t disk, uint32_t fd, uint32_t fd3) {
struct fat32disk *d = (void *)disk;
    struct file *dup_file = d->file[fd];
    if (dup_file == NULL) {
        if (fd > 3) {
            return -1;
        }
    }
    if (d->fds[fd3] == 1) {
        return -1;
    } else {
        d->fds[fd3] = 1;
        d->file[fd3] = dup_file;
        if (d->file[fd3] != NULL) {
            d->file[fd3]->openfds++;
        }

        return fd3;
    }
}

// 从指定磁盘，指定文件描述符，读出文件，存入指定地址上，存指定size大小
int read(uintptr_t disk, uint8_t fd, uintptr_t target_address, uint32_t size) {

    if ((int)fd == -1) {
        return -1;
    }
    if (target_address == NULL) {
        return -1;
    }
    if (size == 0) {
        return 0;
    }

struct fat32disk *d = (void *)disk;

    // 数据开始的簇号
    int cluster_num = d->file[fd]->start_cluster;

    // 由簇号计算得出扇区号
    uint32_t first_sector_of_cluster =
        d->bpb_info.DataStartSector + (cluster_num - 2) * d->bpb_info.SecPerClus;

    struct file *f = d->file[fd];
    // 如果小于等于一个扇区大小，可以直接读了就走，实际可以和下面的逻辑合并
    if (f->fsize <= 512) {
        f->buf = bread(1, first_sector_of_cluster);
        brelse(f->buf);
        if (d->file[fd]->fsize < size) {
            memmove((void *)target_address, (d->file[fd]->buf)->data,
                    d->file[fd]->fsize);
            return d->file[fd]->fsize;
        } else {
            memmove((void *)target_address, (d->file[fd]->buf)->data, size);
            return size;
        }
    } else {
        // 该簇号在fat区域中的扇区号
        uint32_t fat_sec_num =
            d->bpb_info.ResvdSecCnt + (cluster_num * 4 / d->bpb_info.BytsPerSec);
        // fat区域偏移量
        uint32_t fat_en_offset = (cluster_num * 4) % d->bpb_info.BytsPerSec;

#if DEBUG
        Info("fat sec num %d,offset %d", fat_sec_num, fat_en_offset);
#endif

        uint32_t ret = 0;
        uint32_t sec_num = 0;
        if (f->fsize <= size) {
            sec_num = size % 512 ? size / 512 : size / 512 + 1;
            ret = f->fsize;
        } else {
            sec_num = f->fsize % 512 ? f->fsize / 512 : f->fsize / 512 + 1;
            ret = size;
        }

        for (int i = 0; i < sec_num; i++) {

            if (i % 8 == 0 && i != 0) {
                f->buf = bread(1, fat_sec_num);
                brelse(f->buf);
                // 算出上个簇的下一个簇
                cluster_num =
                    (*(uint32_t *)(&(f->buf->data[fat_en_offset]))) & 0x0FFFFFFF;

                // 如果没有下一个簇了直接break，理论上是不会到这一步的，但是以防出现没有预料的问题
                if (cluster_num == 0x0FFFFFFF) {
                    break;
                }

                // 再次取出簇号对应的扇区号
                first_sector_of_cluster = d->bpb_info.DataStartSector +
                                          (cluster_num - 2) * d->bpb_info.SecPerClus;
                // 准备下次用作计算cluster的中间量
                fat_sec_num = d->bpb_info.ResvdSecCnt +
                              (cluster_num * 4 / d->bpb_info.BytsPerSec);
                fat_en_offset = (cluster_num * 4) % d->bpb_info.BytsPerSec;
            }

            //            Info("sectors %d", first_sector_of_cluster + (i % 8));
            f->buf = bread(1, first_sector_of_cluster + (i % 8));
            brelse(f->buf);
            memmove((void *)((uintptr_t)target_address + (i * 512)), f->buf->data,
                    512);
        }
        // 如果最后一个扇区没读满，则说明读完了，按照fsize返回

        // 需要调整ret的值为实际读取的值
        return ret;
    }
}

char *sfn_name(char *name) {
    char *target_name = (void *)kalloc(4096);
    int target_name_idx = 0;
    int src_name_idx = 0;
    while (name[src_name_idx] != 0x00 && target_name_idx < 8) {
        if (name[src_name_idx] >= 'A' && name[src_name_idx] <= 'Z') {
            target_name[target_name_idx++] = name[src_name_idx++];
        } else if (name[src_name_idx] >= 'a' && name[src_name_idx] <= 'z') {
            target_name[target_name_idx++] = name[src_name_idx++] - 32;
        } else {
            src_name_idx += 1;
        }
    }
    return target_name;
}

char *lfn_name(char *name) {
    char *target_name = (void *)kalloc(4096);
    strncpy(target_name, name, strlen(name));
    return target_name;
}

int create_new_file(char *name) {
    uint64_t temp_entry = find_free_direntry();
struct free_entry free_entry = *((struct free_entry *)&temp_entry);

struct buf *buf = bread(1, free_entry.sector);

struct lfn_entry *entry = (void *)buf->data;
struct sfn_entry *sentry = (void *)buf->data;

    uint32_t len = strlen(name) % 14 ? strlen(name) / 14 : strlen(name) / 14 + 1;

    uint32_t idx = free_entry.idx;

    entry[idx].LDIR_0rd = 0x40 | len;
    entry[idx].LDIR_Attr = ATTR_LONG_FILE_NAME;

    for (int i = len; i > 0; i--) {
        char *lname = lfn_name(name);
        entry[idx].LDIR_0rd = 0x40 | i;
        entry[idx].LDIR_Attr = ATTR_LONG_FILE_NAME;

        entry[idx].LDIR_Name1[0] = lname[0];
        entry[idx].LDIR_Name1[1] = 0x00;
        entry[idx].LDIR_Name1[2] = lname[1];
        entry[idx].LDIR_Name1[3] = 0x00;
        entry[idx].LDIR_Name1[4] = lname[2];
        entry[idx].LDIR_Name1[5] = 0x00;
        entry[idx].LDIR_Name1[6] = lname[3];
        entry[idx].LDIR_Name1[7] = 0x00;
        entry[idx].LDIR_Name1[8] = lname[4];
        entry[idx].LDIR_Name1[9] = 0x00;

        entry[idx].LDIR_Name2[0] = lname[5];
        entry[idx].LDIR_Name2[1] = 0x00;
        entry[idx].LDIR_Name2[2] = lname[6];
        entry[idx].LDIR_Name2[3] = 0x00;
        entry[idx].LDIR_Name2[4] = lname[7];
        entry[idx].LDIR_Name2[5] = 0x00;
        entry[idx].LDIR_Name2[6] = lname[8];
        entry[idx].LDIR_Name2[7] = 0x00;
        entry[idx].LDIR_Name2[8] = lname[9];
        entry[idx].LDIR_Name2[9] = 0x00;
        entry[idx].LDIR_Name2[10] = lname[10];
        entry[idx].LDIR_Name2[11] = 0x00;

        entry[idx].LDIR_Name3[0] = lname[11];
        entry[idx].LDIR_Name3[1] = 0x00;
        entry[idx].LDIR_Name3[2] = lname[12];
        entry[idx].LDIR_Name3[3] = 0x00;

        pfree((uintptr_t)lname);
        idx += 1;
    }
    char *sname = sfn_name(name);
    strncpy((void *)sentry[idx].DIR_Name, sname, strlen(sname));
    pfree((uintptr_t)sname);

    return 0;
}

uintptr_t fake_new_file(char *name) {
struct file *f = (void *)kalloc(sizeof(struct file));
    strncpy(f->lfn_name, name, strlen(name));
    f->openfds = 1;
    f->fsize = 0;
    f->fake = 1;
    f->isdir = 0;
    f->mdata = 1;
    f->mtime = 1;
    f->cdata = 1;
    f->ctime = 1;
    f->buf = (void *)kalloc(sizeof(struct buf));
    return (uintptr_t)f;
}
