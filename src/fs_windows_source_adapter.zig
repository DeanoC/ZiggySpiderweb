const shared = @import("spiderweb_node").fs_windows_source_adapter;

pub const Win32Error = shared.Win32Error;
pub const LookupResult = shared.LookupResult;
pub const OpenResult = shared.OpenResult;
pub const LockMode = shared.LockMode;

pub const init = shared.init;
pub const normalizePathForWire = shared.normalizePathForWire;
pub const normalizeNameForCache = shared.normalizeNameForCache;
pub const win32ErrorToErrno = shared.win32ErrorToErrno;
pub const lookupChildAbsolute = shared.lookupChildAbsolute;
pub const statAbsolute = shared.statAbsolute;
pub const openDirAbsolute = shared.openDirAbsolute;
pub const openAbsolute = shared.openAbsolute;
pub const createExclusiveAbsolute = shared.createExclusiveAbsolute;
pub const realpathAndStatAbsolute = shared.realpathAndStatAbsolute;
pub const truncateAbsolute = shared.truncateAbsolute;
pub const deleteFileAbsolute = shared.deleteFileAbsolute;
pub const makeDirAbsolute = shared.makeDirAbsolute;
pub const deleteDirAbsolute = shared.deleteDirAbsolute;
pub const renameAbsolute = shared.renameAbsolute;
pub const lockFile = shared.lockFile;
