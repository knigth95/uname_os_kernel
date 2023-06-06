# 文件系统

本OS采用FAT32格式的文件系统，FAT 全称 File Allocation Table，整个磁盘被分成若干簇。FAT 用于描述每个文件使用了哪些簇。是的，FAT32 是微软的文件系统，而且也有些年纪了，但最重要的是，它与类 Unix 文件系统的观念不同。
这就给我们带来了问题。我们最终还是决定实现一个简单的虚拟文件系统。我们重新建立了 `fs.c` 模块，并引入了 Linux 的 VFS 四大组件——超级块 `superblock`、索引节点 `inode`、目录项 `dentry` 和文件 `file`。

## 超级块

FAT32 文件系统的第一个磁盘块为超级块，包含文件系统的基本信息。具体信息见下表

| 字节位置 | 内容 | 名称 |
| -- | -- | -- |
| 11~12 | 每个块的大小 | `BPB_BytsPerSec` |
| 13 | 每个簇包含的块数 | `BPB_SecPerClus` |
| 14-15 | 保留块的数量 | `BPB_ResvdSecCnt` |
| 16 | FAT 表的复制份数 | `BPB_NumFATs` |
| 28~31 | 隐藏块数量 | `BPB_HiddSec` |
| 32~35 | 文件系统总块数 | `BPB_TotSec32` |
| 36~39 | 每个 FAT 的块数 | `BPB_FATSz32` |
| 44~47 | 根目录的第一个簇 | `BPB_RootClus` 
| 82~89 | 表示文件系统类型 | `BS_FilSysType` |

通过这些读出的数据，可以算出：
- 第一个数据块的块号 = `BPB_ResvdSecCnt` + (`BPB_NumFATs` * `BPB_FATSz32`)
- 数据块总数 = `BPB_TotSec32` - `BPB_ResvdSecCnt` - (`BPB_NumFATs` * `FATSz`) - `RootDirSectors`
- 数据簇总数 = (`BPB_TotSec32` - `FirstDataSector`) / `BPB_SecPerClus`

- 每个簇字节数 `BytesPerCluster` = `BPB_SecPerClus` * `BPB_BytsPerSec`

其中，`FirstDataSector`为第一个数据块的块号,`FATSz`为扇区中每个FAT表的大小
## 文件

`init_fat32(...)` 函数通过验证磁盘引导扇区和 FAT32 卷段中各个字段的值来初始化 FAT32 磁盘。如果任何字段具有无效值，则返回错误并中止初始化。如果初始化成功，有关磁盘的信息将存储在 disk 参数指向的 `fat32disk` 结构中。
`alloc_fd(...)` 函数分配一个文件描述符以用于指定的 FAT32 磁盘。文件描述符表示为文件描述符标志数组的索引，该数组存储在 disk 参数指向的 `fat32disk` 结构。其中，`FirstDataSector`为第一个数据块的块号。中。如果找到空闲文件描述符，则返回其索引。如果没有空闲文件描述符可用，则返回索引 0。
```c
struct fat32disk {
    struct BPB_info bpb_info;
#define FILES 512
    uint8_t fds[FILES];
    struct file *file[FILES];
};
```
`free_entry`结构用于跟踪 FAT 表上的空闲条目。idx是free entry的索引，sector是free entry所在的扇区。
`dirent`结构表示 FAT 文件系统中的目录条目。
```c
struct dirent {
    uint64_t d_ino;          // 索引结点号
    long d_off;              // 到下一个dirent的偏移
    unsigned short d_reclen; // 当前dirent的长度
    unsigned char d_type;    // 文件类型
    char d_name[];           // 文件名
};
```
`kstat` 结构用于检索和保存文件元数据,以下介绍的是它的部分主要参数。
- `st_dev`：文件所在文件系统的设备ID。
- `st_ino`：文件的 inode 编号，它在文件系统中唯一标识文件。
- `st_mode`：文件的模式，包含文件类型和文件权限。低 12 位定义文件权限（例如，读、写、执行），高位定义文件类型（例如，常规文件、目录、套接字）。
- `st_nlink`：文件的硬链接数。
- `st_uid`：文件所有者的用户 ID。
- `st_gid`：文件所有者的组 ID。
- `st_rdev`: 文件的设备 ID（如果文件是特殊设备文件）。
- `st_size`：文件的大小（以字节为单位）。
- `st_blksize`：文件的首选 I/O 块大小（用于预读和后写优化）。
- `st_blocks`：分配给文件的文件系统块数。
- `st_atime_sec和st_atime_nsec`：文件的访问时间（上次读取时）。
- `st_mtime_sec和st_mtime_nsec`：文件的修改时间（上次修改数据的时间）。
- `st_ctime_sec和st_ctime_nsec`：文件的状态更改时间（上次修改其元数据的时间）。

### 文件权限宏定义
- `O_RDONLY`: 指示文件应以只读方式打开的标志。
- `O_WRONLY`: 指示文件应以只写方式打开的标志。
- `O_RDWR`: 表示文件应该以读写访问权限打开。
- `O_CREATE`:指示如果文件不存在则应创建该文件。O_WRONLY此标志与or结合O_RDWR以指定对新文件的写访问权。
- `O_DIRECTORY`:表示正在打开的文件是一个目录

## 参考链接

[文件系统实验](https://ftutorials.gitee.io/ftutorials_book/Chapter3/3_1.html)