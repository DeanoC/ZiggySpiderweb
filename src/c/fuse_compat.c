#include "fuse_compat.h"

typedef int (*spiderweb_fuse_main_real_versioned_fn)(int argc,
                                                     char *argv[],
                                                     const struct fuse_operations *op,
                                                     size_t op_size,
                                                     struct libfuse_version *version,
                                                     void *user_data);

int spiderweb_call_fuse_main_real_versioned(void *fn,
                                            int argc,
                                            char *argv[],
                                            const struct fuse_operations *op,
                                            size_t op_size,
                                            void *user_data) {
    spiderweb_fuse_main_real_versioned_fn versioned =
        (spiderweb_fuse_main_real_versioned_fn)fn;
    struct libfuse_version version = {
        .major = 3,
        .minor = 17,
        .hotfix = 4,
#ifdef __APPLE__
        .darwin_extensions_enabled = 1,
#endif
        .padding = 0,
    };
    return versioned(argc, argv, op, op_size, &version, user_data);
}

int32_t spiderweb_fi_get_flags(struct fuse_file_info *fi) {
    return fi->flags;
}

uint64_t spiderweb_fi_get_fh(struct fuse_file_info *fi) {
    return fi->fh;
}

void spiderweb_fi_set_fh(struct fuse_file_info *fi, uint64_t fh) {
    fi->fh = fh;
}

void spiderweb_fi_set_nonseekable(struct fuse_file_info *fi, int enabled) {
    fi->nonseekable = enabled ? 1u : 0u;
}

void spiderweb_fi_set_cache_readdir(struct fuse_file_info *fi, int enabled) {
#ifdef _WIN32
    (void)fi;
    (void)enabled;
#else
    fi->cache_readdir = enabled ? 1u : 0u;
#endif
}
