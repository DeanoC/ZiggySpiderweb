const shared = @import("spiderweb_node").fs_gdrive_backend;

pub const enable_env_var = shared.enable_env_var;
pub const token_env_var = shared.token_env_var;
pub const token_env_var_alt = shared.token_env_var_alt;
pub const token_env_var_google = shared.token_env_var_google;
pub const api_base_env_var = shared.api_base_env_var;
pub const upload_base_env_var = shared.upload_base_env_var;
pub const oauth_base_env_var = shared.oauth_base_env_var;

pub const GdriveFile = shared.GdriveFile;
pub const ListResult = shared.ListResult;
pub const Change = shared.Change;
pub const ChangesPage = shared.ChangesPage;
pub const Error = shared.Error;
pub const HttpMethod = shared.HttpMethod;
pub const MockResponse = shared.MockResponse;
pub const TestTransport = shared.TestTransport;
pub const OAuthRefreshResult = shared.OAuthRefreshResult;

pub const backendEnabled = shared.backendEnabled;
pub const readAccessToken = shared.readAccessToken;
pub const normalizeRootId = shared.normalizeRootId;
pub const setTestTransport = shared.setTestTransport;
pub const listChildren = shared.listChildren;
pub const lookupChildByName = shared.lookupChildByName;
pub const statFile = shared.statFile;
pub const readFileRange = shared.readFileRange;
pub const createFolder = shared.createFolder;
pub const createFile = shared.createFile;
pub const deleteFile = shared.deleteFile;
pub const updateFileMetadata = shared.updateFileMetadata;
pub const readFileAll = shared.readFileAll;
pub const updateFileContent = shared.updateFileContent;
pub const updateFileContentFromFile = shared.updateFileContentFromFile;
pub const getStartPageToken = shared.getStartPageToken;
pub const listChanges = shared.listChanges;
pub const refreshAccessToken = shared.refreshAccessToken;
