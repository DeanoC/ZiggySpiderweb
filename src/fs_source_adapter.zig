const shared = @import("spiderweb_node").fs_source_adapter;

pub const SourceKind = shared.SourceKind;
pub const SourceCaps = shared.SourceCaps;
pub const Operation = shared.Operation;
pub const PreparedExport = shared.PreparedExport;
pub const VTable = shared.VTable;
pub const SourceAdapter = shared.SourceAdapter;

pub const defaultSourceKindForHost = shared.defaultSourceKindForHost;
pub const defaultCapsForKind = shared.defaultCapsForKind;
