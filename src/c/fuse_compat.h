#ifndef SPIDERWEB_FUSE_COMPAT_H
#define SPIDERWEB_FUSE_COMPAT_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#ifdef _WIN32
#ifndef _UID_T_DEFINED
typedef unsigned int uid_t;
#define _UID_T_DEFINED
#endif
#ifndef _GID_T_DEFINED
typedef unsigned int gid_t;
#define _GID_T_DEFINED
#endif
#ifndef SPIDERWEB_FLOCK_DEFINED
#define SPIDERWEB_FLOCK_DEFINED
struct flock {
    short l_type;
    short l_whence;
    long long l_start;
    long long l_len;
    int l_pid;
};
#endif
#ifndef SPIDERWEB_STATVFS_DEFINED
#define SPIDERWEB_STATVFS_DEFINED
struct statvfs {
    uint64_t f_bsize;
    uint64_t f_frsize;
    uint64_t f_blocks;
    uint64_t f_bfree;
    uint64_t f_bavail;
    uint64_t f_files;
    uint64_t f_ffree;
    uint64_t f_favail;
    uint64_t f_fsid;
    uint64_t f_flag;
    uint64_t f_namemax;
};
#endif
#ifndef LOCK_SH
#define LOCK_SH 1
#endif
#ifndef LOCK_EX
#define LOCK_EX 2
#endif
#ifndef LOCK_NB
#define LOCK_NB 4
#endif
#ifndef LOCK_UN
#define LOCK_UN 8
#endif
#else
#include <sys/statvfs.h>
#include <sys/uio.h>
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct statx;
struct fuse_conn_info;
struct fuse_config;
struct fuse_pollhandle;
struct fuse_bufvec;
struct fuse_dirhandle;

struct libfuse_version {
    int major;
    int minor;
    int hotfix;
    int padding;
};

#ifdef _WIN32
typedef uint32_t fuse_uid_t;
typedef uint32_t fuse_gid_t;
typedef int32_t fuse_pid_t;
typedef uint32_t fuse_dev_t;
typedef uint64_t fuse_ino_t;
typedef uint32_t fuse_mode_t;
typedef uint16_t fuse_nlink_t;
typedef int64_t fuse_off_t;
typedef uint64_t fuse_fsblkcnt_t;
typedef uint64_t fuse_fsfilcnt_t;
typedef int32_t fuse_blksize_t;
typedef int64_t fuse_blkcnt_t;

struct fuse_utimbuf {
    int64_t actime;
    int64_t modtime;
};

struct fuse_timespec {
    int64_t tv_sec;
    int64_t tv_nsec;
};

struct fuse_stat {
    fuse_dev_t st_dev;
    fuse_ino_t st_ino;
    fuse_mode_t st_mode;
    fuse_nlink_t st_nlink;
    fuse_uid_t st_uid;
    fuse_gid_t st_gid;
    fuse_dev_t st_rdev;
    fuse_off_t st_size;
    struct fuse_timespec st_atim;
    struct fuse_timespec st_mtim;
    struct fuse_timespec st_ctim;
    fuse_blksize_t st_blksize;
    fuse_blkcnt_t st_blocks;
    struct fuse_timespec st_birthtim;
};

struct fuse_statvfs {
    uint64_t f_bsize;
    uint64_t f_frsize;
    fuse_fsblkcnt_t f_blocks;
    fuse_fsblkcnt_t f_bfree;
    fuse_fsblkcnt_t f_bavail;
    fuse_fsfilcnt_t f_files;
    fuse_fsfilcnt_t f_ffree;
    fuse_fsfilcnt_t f_favail;
    uint64_t f_fsid;
    uint64_t f_flag;
    uint64_t f_namemax;
};

struct fuse_file_info {
    int32_t flags;
    uint32_t fh_old;
    int32_t writepage;
    uint32_t direct_io : 1;
    uint32_t keep_cache : 1;
    uint32_t flush : 1;
    uint32_t nonseekable : 1;
    uint32_t padding : 28;
    uint64_t fh;
    uint64_t lock_owner;
};

typedef struct fuse_dirhandle *fuse_dirh_t;
typedef int (*fuse_fill_dir_t)(void *buf, const char *name, const struct fuse_stat *stbuf, fuse_off_t off);
typedef int (*fuse_dirfil_t)(fuse_dirh_t h, const char *name, int type, fuse_ino_t ino);

struct fuse_operations {
    int (*getattr)(const char *, struct fuse_stat *);
    int (*getdir)(const char *, fuse_dirh_t, fuse_dirfil_t);
    int (*readlink)(const char *, char *, size_t);
    int (*mknod)(const char *, fuse_mode_t, fuse_dev_t);
    int (*mkdir)(const char *, fuse_mode_t);
    int (*unlink)(const char *);
    int (*rmdir)(const char *);
    int (*symlink)(const char *, const char *);
    int (*rename)(const char *, const char *);
    int (*link)(const char *, const char *);
    int (*chmod)(const char *, fuse_mode_t);
    int (*chown)(const char *, fuse_uid_t, fuse_gid_t);
    int (*truncate)(const char *, fuse_off_t);
    int (*utime)(const char *, struct fuse_utimbuf *timbuf);
    int (*open)(const char *, struct fuse_file_info *);
    int (*read)(const char *, char *, size_t, fuse_off_t, struct fuse_file_info *);
    int (*write)(const char *, const char *, size_t, fuse_off_t, struct fuse_file_info *);
    int (*statfs)(const char *, struct fuse_statvfs *);
    int (*flush)(const char *, struct fuse_file_info *);
    int (*release)(const char *, struct fuse_file_info *);
    int (*fsync)(const char *, int, struct fuse_file_info *);
    int (*setxattr)(const char *, const char *, const char *, size_t, int);
    int (*getxattr)(const char *, const char *, char *, size_t);
    int (*listxattr)(const char *, char *, size_t);
    int (*removexattr)(const char *, const char *);
    int (*opendir)(const char *, struct fuse_file_info *);
    int (*readdir)(const char *, void *, fuse_fill_dir_t, fuse_off_t, struct fuse_file_info *);
    int (*releasedir)(const char *, struct fuse_file_info *);
    int (*fsyncdir)(const char *, int, struct fuse_file_info *);
    void *(*init)(struct fuse_conn_info *conn);
    void (*destroy)(void *data);
    int (*access)(const char *, int);
    int (*create)(const char *, fuse_mode_t, struct fuse_file_info *);
};
#else
struct fuse_file_info {
    int32_t flags;
    uint32_t writepage : 1;
    uint32_t direct_io : 1;
    uint32_t keep_cache : 1;
    uint32_t flush : 1;
    uint32_t nonseekable : 1;
    uint32_t flock_release : 1;
    uint32_t cache_readdir : 1;
    uint32_t noflush : 1;
    uint32_t parallel_direct_writes : 1;
    uint32_t padding : 23;
    uint32_t padding2 : 32;
    uint32_t padding3 : 32;
    uint64_t fh;
    uint64_t lock_owner;
    uint32_t poll_events;
    int32_t backing_id;
    uint64_t compat_flags;
    uint64_t reserved[2];
};

enum fuse_readdir_flags {
    FUSE_READDIR_DEFAULTS = 0,
    FUSE_READDIR_PLUS = (1 << 0),
};

enum fuse_fill_dir_flags {
    FUSE_FILL_DIR_DEFAULTS = 0,
    FUSE_FILL_DIR_PLUS = (1 << 1),
};

typedef int (*fuse_fill_dir_t)(void *buf, const char *name, const struct stat *stbuf, off_t off, enum fuse_fill_dir_flags flags);

struct fuse_operations {
    int (*getattr)(const char *, struct stat *, struct fuse_file_info *fi);
    int (*readlink)(const char *, char *, size_t);
    int (*mknod)(const char *, mode_t, dev_t);
    int (*mkdir)(const char *, mode_t);
    int (*unlink)(const char *);
    int (*rmdir)(const char *);
    int (*symlink)(const char *, const char *);
    int (*rename)(const char *, const char *, unsigned int flags);
    int (*link)(const char *, const char *);
    int (*chmod)(const char *, mode_t, struct fuse_file_info *fi);
    int (*chown)(const char *, uid_t, gid_t, struct fuse_file_info *fi);
    int (*truncate)(const char *, off_t, struct fuse_file_info *fi);
    int (*open)(const char *, struct fuse_file_info *);
    int (*read)(const char *, char *, size_t, off_t, struct fuse_file_info *);
    int (*write)(const char *, const char *, size_t, off_t, struct fuse_file_info *);
    int (*statfs)(const char *, struct statvfs *);
    int (*flush)(const char *, struct fuse_file_info *);
    int (*release)(const char *, struct fuse_file_info *);
    int (*fsync)(const char *, int, struct fuse_file_info *);
    int (*setxattr)(const char *, const char *, const char *, size_t, int);
    int (*getxattr)(const char *, const char *, char *, size_t);
    int (*listxattr)(const char *, char *, size_t);
    int (*removexattr)(const char *, const char *);
    int (*opendir)(const char *, struct fuse_file_info *);
    int (*readdir)(const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *, enum fuse_readdir_flags);
    int (*releasedir)(const char *, struct fuse_file_info *);
    int (*fsyncdir)(const char *, int, struct fuse_file_info *);
    void *(*init)(struct fuse_conn_info *conn, struct fuse_config *cfg);
    void (*destroy)(void *private_data);
    int (*access)(const char *, int);
    int (*create)(const char *, mode_t, struct fuse_file_info *);
    int (*lock)(const char *, struct fuse_file_info *, int cmd, struct flock *);
    int (*utimens)(const char *, const struct timespec tv[2], struct fuse_file_info *fi);
    int (*bmap)(const char *, size_t blocksize, uint64_t *idx);
    int (*ioctl)(const char *, unsigned int cmd, void *arg, struct fuse_file_info *, unsigned int flags, void *data);
    int (*poll)(const char *, struct fuse_file_info *, struct fuse_pollhandle *ph, unsigned *reventsp);
    int (*write_buf)(const char *, struct fuse_bufvec *buf, off_t off, struct fuse_file_info *);
    int (*read_buf)(const char *, struct fuse_bufvec **bufp, size_t size, off_t off, struct fuse_file_info *);
    int (*flock)(const char *, struct fuse_file_info *, int op);
    int (*fallocate)(const char *, int, off_t, off_t, struct fuse_file_info *);
    ssize_t (*copy_file_range)(const char *path_in, struct fuse_file_info *fi_in, off_t offset_in, const char *path_out, struct fuse_file_info *fi_out, off_t offset_out, size_t size, int flags);
    off_t (*lseek)(const char *, off_t off, int whence, struct fuse_file_info *);
};
#endif

int fuse_main_real_versioned(int argc, char *argv[],
                             const struct fuse_operations *op, size_t op_size,
                             struct libfuse_version *version, void *user_data);

int32_t spiderweb_fi_get_flags(struct fuse_file_info *fi);
uint64_t spiderweb_fi_get_fh(struct fuse_file_info *fi);
void spiderweb_fi_set_fh(struct fuse_file_info *fi, uint64_t fh);

#ifdef __cplusplus
}
#endif

#endif
