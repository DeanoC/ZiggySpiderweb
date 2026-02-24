#ifndef SPIDERWEB_FUSE_COMPAT_H
#define SPIDERWEB_FUSE_COMPAT_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

struct statx;
struct fuse_conn_info;
struct fuse_config;
struct fuse_pollhandle;
struct fuse_bufvec;

struct libfuse_version {
    int major;
    int minor;
    int hotfix;
    int padding;
};

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
