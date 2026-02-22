#include "fuse_compat.h"

int32_t spiderweb_fi_get_flags(struct fuse_file_info *fi) {
    return fi->flags;
}

uint64_t spiderweb_fi_get_fh(struct fuse_file_info *fi) {
    return fi->fh;
}

void spiderweb_fi_set_fh(struct fuse_file_info *fi, uint64_t fh) {
    fi->fh = fh;
}
