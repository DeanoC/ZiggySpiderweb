const shared = @import("spiderweb_node").fs_local_source_adapter;

pub const LockMode = shared.LockMode;
pub const LookupResult = shared.LookupResult;
pub const OpenResult = shared.OpenResult;

pub const init = shared.init;
pub const supportsOperationForKind = shared.supportsOperationForKind;
pub const lookupChildAbsolute = shared.lookupChildAbsolute;
pub const statAbsolute = shared.statAbsolute;
pub const openDirAbsolute = shared.openDirAbsolute;
pub const openAbsolute = shared.openAbsolute;
pub const symlinkAbsolute = shared.symlinkAbsolute;
pub const createExclusiveAbsolute = shared.createExclusiveAbsolute;
pub const realpathAndStatAbsolute = shared.realpathAndStatAbsolute;
pub const truncateAbsolute = shared.truncateAbsolute;
pub const deleteFileAbsolute = shared.deleteFileAbsolute;
pub const makeDirAbsolute = shared.makeDirAbsolute;
pub const deleteDirAbsolute = shared.deleteDirAbsolute;
pub const renameAbsolute = shared.renameAbsolute;
pub const posixErrnoToError = shared.posixErrnoToError;
pub const lockFile = shared.lockFile;
pub const setXattrAbsolute = shared.setXattrAbsolute;
pub const getXattrAbsolute = shared.getXattrAbsolute;
pub const listXattrAbsolute = shared.listXattrAbsolute;
pub const removeXattrAbsolute = shared.removeXattrAbsolute;
