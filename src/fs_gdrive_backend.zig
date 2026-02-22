const std = @import("std");

pub const enable_env_var: []const u8 = "SPIDERWEB_GDRIVE_ENABLE_API";
pub const token_env_var: []const u8 = "SPIDERWEB_GDRIVE_ACCESS_TOKEN";
pub const token_env_var_alt: []const u8 = "GDRIVE_ACCESS_TOKEN";
pub const token_env_var_google: []const u8 = "GOOGLE_DRIVE_ACCESS_TOKEN";
pub const api_base_env_var: []const u8 = "SPIDERWEB_GDRIVE_API_BASE_URL";
pub const upload_base_env_var: []const u8 = "SPIDERWEB_GDRIVE_UPLOAD_BASE_URL";
pub const oauth_base_env_var: []const u8 = "SPIDERWEB_GDRIVE_OAUTH_BASE_URL";

pub const GdriveFile = struct {
    id: []u8,
    name: []u8,
    mime_type: []u8,
    primary_parent_id: ?[]u8,
    size: u64,
    mtime_ns: i64,
    generation: u64,
    is_dir: bool,

    pub fn deinit(self: *GdriveFile, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.name);
        allocator.free(self.mime_type);
        if (self.primary_parent_id) |parent_id| allocator.free(parent_id);
        self.* = undefined;
    }
};

pub const ListResult = struct {
    files: []GdriveFile,

    pub fn deinit(self: *ListResult, allocator: std.mem.Allocator) void {
        for (self.files) |*file| file.deinit(allocator);
        allocator.free(self.files);
        self.* = undefined;
    }
};

pub const Change = struct {
    file_id: []u8,
    removed: bool,
    file: ?GdriveFile,

    pub fn deinit(self: *Change, allocator: std.mem.Allocator) void {
        allocator.free(self.file_id);
        if (self.file) |*file| file.deinit(allocator);
        self.* = undefined;
    }
};

pub const ChangesPage = struct {
    changes: []Change,
    next_page_token: ?[]u8,
    new_start_page_token: ?[]u8,

    pub fn deinit(self: *ChangesPage, allocator: std.mem.Allocator) void {
        for (self.changes) |*change| change.deinit(allocator);
        allocator.free(self.changes);
        if (self.next_page_token) |token| allocator.free(token);
        if (self.new_start_page_token) |token| allocator.free(token);
        self.* = undefined;
    }
};

pub const Error = error{
    GdriveAuthMissing,
    GdriveAccessDenied,
    GdriveNotFound,
    GdriveNotDirectory,
    GdriveConflict,
    GdriveRateLimited,
    GdriveInvalidResponse,
    GdriveUnexpectedStatus,
    GdriveTokenRefreshFailed,
};

pub const HttpMethod = enum {
    GET,
    POST,
    PATCH,
    PUT,
    DELETE,
};

pub const MockResponse = struct {
    status: std.http.Status = .ok,
    body: []const u8 = "",
    location: ?[]const u8 = null,
    range: ?[]const u8 = null,
};

pub const TestTransport = struct {
    ctx: ?*anyopaque = null,
    handler: *const fn (
        ctx: ?*anyopaque,
        allocator: std.mem.Allocator,
        method: HttpMethod,
        url: []const u8,
        payload: ?[]const u8,
        headers: []const std.http.Header,
    ) anyerror!MockResponse,
};

var test_transport: ?TestTransport = null;

const HttpResponse = struct {
    status: std.http.Status,
    body: []u8,
    location: ?[]u8 = null,
    range: ?[]u8 = null,

    fn deinit(self: *HttpResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
        if (self.location) |value| allocator.free(value);
        if (self.range) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub const OAuthRefreshResult = struct {
    access_token: []u8,
    refresh_token: ?[]u8,
    expires_at_ms: u64,

    pub fn deinit(self: *OAuthRefreshResult, allocator: std.mem.Allocator) void {
        allocator.free(self.access_token);
        if (self.refresh_token) |token| allocator.free(token);
        self.* = undefined;
    }
};

const drive_files_fields = "files(id,name,mimeType,parents,size,modifiedTime,version),nextPageToken";
const single_file_fields = "id,name,mimeType,parents,size,modifiedTime,version";
const change_fields = "changes(fileId,removed,file(id,name,mimeType,parents,size,modifiedTime,version)),nextPageToken,newStartPageToken";
const gdrive_folder_mime = "application/vnd.google-apps.folder";
const gdrive_default_api_base = "https://www.googleapis.com";
const gdrive_default_upload_base = "https://www.googleapis.com";
const gdrive_default_oauth_base = "https://oauth2.googleapis.com";
const gdrive_resumable_chunk_size: usize = 256 * 1024;

pub fn backendEnabled(allocator: std.mem.Allocator) bool {
    const raw = std.process.getEnvVarOwned(allocator, enable_env_var) catch return false;
    defer allocator.free(raw);
    return parseTruthyEnvFlag(raw);
}

pub fn readAccessToken(allocator: std.mem.Allocator) ?[]u8 {
    return std.process.getEnvVarOwned(allocator, token_env_var) catch
        std.process.getEnvVarOwned(allocator, token_env_var_alt) catch
        std.process.getEnvVarOwned(allocator, token_env_var_google) catch null;
}

pub fn normalizeRootId(raw: []const u8) []const u8 {
    if (raw.len == 0) return "root";
    if (std.mem.eql(u8, raw, "drive:root")) return "root";
    if (std.mem.startsWith(u8, raw, "drive:")) {
        const id = raw["drive:".len..];
        if (id.len == 0) return "root";
        return id;
    }
    return raw;
}

pub fn setTestTransport(transport: ?TestTransport) void {
    test_transport = transport;
}

fn apiBaseUrl(allocator: std.mem.Allocator) ![]u8 {
    return resolveBaseUrl(allocator, api_base_env_var, gdrive_default_api_base);
}

fn uploadBaseUrl(allocator: std.mem.Allocator) ![]u8 {
    return resolveBaseUrl(allocator, upload_base_env_var, gdrive_default_upload_base);
}

fn oauthBaseUrl(allocator: std.mem.Allocator) ![]u8 {
    return resolveBaseUrl(allocator, oauth_base_env_var, gdrive_default_oauth_base);
}

fn resolveBaseUrl(allocator: std.mem.Allocator, env_name: []const u8, fallback: []const u8) ![]u8 {
    const raw = std.process.getEnvVarOwned(allocator, env_name) catch return allocator.dupe(u8, fallback);
    defer allocator.free(raw);
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return allocator.dupe(u8, fallback);

    var end = trimmed.len;
    while (end > 0 and trimmed[end - 1] == '/') : (end -= 1) {}
    if (end == 0) return allocator.dupe(u8, fallback);
    return allocator.dupe(u8, trimmed[0..end]);
}

pub fn listChildren(
    allocator: std.mem.Allocator,
    access_token: []const u8,
    parent_id: []const u8,
) !ListResult {
    if (access_token.len == 0) return error.GdriveAuthMissing;

    var out = std.ArrayListUnmanaged(GdriveFile){};
    errdefer {
        for (out.items) |*file| file.deinit(allocator);
        out.deinit(allocator);
    }

    var next_page_token: ?[]u8 = null;
    defer if (next_page_token) |token| allocator.free(token);

    while (true) {
        const api_base = try apiBaseUrl(allocator);
        defer allocator.free(api_base);
        const query = try buildChildrenQuery(allocator, parent_id);
        defer allocator.free(query);

        const encoded_query = try percentEncodeQueryComponent(allocator, query);
        defer allocator.free(encoded_query);

        const encoded_fields = try percentEncodeQueryComponent(allocator, drive_files_fields);
        defer allocator.free(encoded_fields);

        const url = if (next_page_token) |token| blk: {
            const encoded_page = try percentEncodeQueryComponent(allocator, token);
            defer allocator.free(encoded_page);
            break :blk try std.fmt.allocPrint(
                allocator,
                "{s}/drive/v3/files?supportsAllDrives=true&includeItemsFromAllDrives=true&pageSize=1000&q={s}&fields={s}&pageToken={s}",
                .{ api_base, encoded_query, encoded_fields, encoded_page },
            );
        } else try std.fmt.allocPrint(
            allocator,
            "{s}/drive/v3/files?supportsAllDrives=true&includeItemsFromAllDrives=true&pageSize=1000&q={s}&fields={s}",
            .{ api_base, encoded_query, encoded_fields },
        );
        defer allocator.free(url);

        const body = try httpGet(allocator, access_token, url, null);
        defer allocator.free(body);

        var parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return error.GdriveInvalidResponse;
        defer parsed.deinit();

        if (parsed.value != .object) return error.GdriveInvalidResponse;
        const obj = parsed.value.object;
        const files_value = obj.get("files") orelse return error.GdriveInvalidResponse;
        if (files_value != .array) return error.GdriveInvalidResponse;

        for (files_value.array.items) |entry| {
            var file = try parseFileValue(allocator, entry);
            errdefer file.deinit(allocator);
            try out.append(allocator, file);
        }

        if (next_page_token) |token| {
            allocator.free(token);
            next_page_token = null;
        }
        if (obj.get("nextPageToken")) |next_token| {
            if (next_token == .string and next_token.string.len > 0) {
                next_page_token = try allocator.dupe(u8, next_token.string);
            }
        }

        if (next_page_token == null) break;
    }

    return .{ .files = try out.toOwnedSlice(allocator) };
}

pub fn lookupChildByName(
    allocator: std.mem.Allocator,
    access_token: []const u8,
    parent_id: []const u8,
    name: []const u8,
) !?GdriveFile {
    if (access_token.len == 0) return error.GdriveAuthMissing;
    const api_base = try apiBaseUrl(allocator);
    defer allocator.free(api_base);

    const escaped_name = try escapeQueryLiteral(allocator, name);
    defer allocator.free(escaped_name);

    const query = try std.fmt.allocPrint(
        allocator,
        "'{s}' in parents and trashed = false and name = '{s}'",
        .{ parent_id, escaped_name },
    );
    defer allocator.free(query);

    const encoded_query = try percentEncodeQueryComponent(allocator, query);
    defer allocator.free(encoded_query);

    const encoded_fields = try percentEncodeQueryComponent(allocator, drive_files_fields);
    defer allocator.free(encoded_fields);

    const url = try std.fmt.allocPrint(
        allocator,
        "{s}/drive/v3/files?supportsAllDrives=true&includeItemsFromAllDrives=true&pageSize=2&q={s}&fields={s}",
        .{ api_base, encoded_query, encoded_fields },
    );
    defer allocator.free(url);

    const body = try httpGet(allocator, access_token, url, null);
    defer allocator.free(body);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return error.GdriveInvalidResponse;
    defer parsed.deinit();
    if (parsed.value != .object) return error.GdriveInvalidResponse;
    const files_value = parsed.value.object.get("files") orelse return error.GdriveInvalidResponse;
    if (files_value != .array) return error.GdriveInvalidResponse;
    if (files_value.array.items.len == 0) return null;

    return try parseFileValue(allocator, files_value.array.items[0]);
}

pub fn statFile(
    allocator: std.mem.Allocator,
    access_token: []const u8,
    file_id: []const u8,
) !GdriveFile {
    if (access_token.len == 0) return error.GdriveAuthMissing;
    const api_base = try apiBaseUrl(allocator);
    defer allocator.free(api_base);

    const encoded_fields = try percentEncodeQueryComponent(allocator, single_file_fields);
    defer allocator.free(encoded_fields);

    const url = try std.fmt.allocPrint(
        allocator,
        "{s}/drive/v3/files/{s}?supportsAllDrives=true&fields={s}",
        .{ api_base, file_id, encoded_fields },
    );
    defer allocator.free(url);

    const body = try httpGet(allocator, access_token, url, null);
    defer allocator.free(body);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return error.GdriveInvalidResponse;
    defer parsed.deinit();

    return parseFileValue(allocator, parsed.value);
}

pub fn readFileRange(
    allocator: std.mem.Allocator,
    access_token: []const u8,
    file_id: []const u8,
    off: u64,
    len: u32,
) ![]u8 {
    if (access_token.len == 0) return error.GdriveAuthMissing;
    const api_base = try apiBaseUrl(allocator);
    defer allocator.free(api_base);

    const end_off = if (len == 0) off else off + @as(u64, len) - 1;
    const range_header_value = if (len == 0)
        try std.fmt.allocPrint(allocator, "bytes={d}-", .{off})
    else
        try std.fmt.allocPrint(allocator, "bytes={d}-{d}", .{ off, end_off });
    defer allocator.free(range_header_value);

    const url = try std.fmt.allocPrint(
        allocator,
        "{s}/drive/v3/files/{s}?supportsAllDrives=true&alt=media",
        .{ api_base, file_id },
    );
    defer allocator.free(url);

    const body = try httpGet(allocator, access_token, url, .{
        .name = "range",
        .value = range_header_value,
    });
    return body;
}

pub fn createFolder(
    allocator: std.mem.Allocator,
    access_token: []const u8,
    parent_id: []const u8,
    name: []const u8,
) !GdriveFile {
    if (access_token.len == 0) return error.GdriveAuthMissing;
    if (name.len == 0) return error.GdriveInvalidResponse;
    const api_base = try apiBaseUrl(allocator);
    defer allocator.free(api_base);

    var payload = std.ArrayListUnmanaged(u8){};
    defer payload.deinit(allocator);
    try payload.appendSlice(allocator, "{\"name\":");
    try appendJsonString(&payload, allocator, name);
    try payload.appendSlice(allocator, ",\"mimeType\":\"");
    try payload.appendSlice(allocator, gdrive_folder_mime);
    try payload.appendSlice(allocator, "\",\"parents\":[");
    try appendJsonString(&payload, allocator, parent_id);
    try payload.appendSlice(allocator, "]}");

    const encoded_fields = try percentEncodeQueryComponent(allocator, single_file_fields);
    defer allocator.free(encoded_fields);
    const url = try std.fmt.allocPrint(
        allocator,
        "{s}/drive/v3/files?supportsAllDrives=true&fields={s}",
        .{ api_base, encoded_fields },
    );
    defer allocator.free(url);

    const body = try httpJsonRequest(allocator, access_token, .POST, url, payload.items);
    defer allocator.free(body);
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return error.GdriveInvalidResponse;
    defer parsed.deinit();
    return parseFileValue(allocator, parsed.value);
}

pub fn createFile(
    allocator: std.mem.Allocator,
    access_token: []const u8,
    parent_id: []const u8,
    name: []const u8,
) !GdriveFile {
    if (access_token.len == 0) return error.GdriveAuthMissing;
    if (name.len == 0) return error.GdriveInvalidResponse;
    const api_base = try apiBaseUrl(allocator);
    defer allocator.free(api_base);

    var payload = std.ArrayListUnmanaged(u8){};
    defer payload.deinit(allocator);
    try payload.appendSlice(allocator, "{\"name\":");
    try appendJsonString(&payload, allocator, name);
    try payload.appendSlice(allocator, ",\"parents\":[");
    try appendJsonString(&payload, allocator, parent_id);
    try payload.appendSlice(allocator, "]}");

    const encoded_fields = try percentEncodeQueryComponent(allocator, single_file_fields);
    defer allocator.free(encoded_fields);
    const url = try std.fmt.allocPrint(
        allocator,
        "{s}/drive/v3/files?supportsAllDrives=true&fields={s}",
        .{ api_base, encoded_fields },
    );
    defer allocator.free(url);

    const body = try httpJsonRequest(allocator, access_token, .POST, url, payload.items);
    defer allocator.free(body);
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return error.GdriveInvalidResponse;
    defer parsed.deinit();
    return parseFileValue(allocator, parsed.value);
}

pub fn deleteFile(
    allocator: std.mem.Allocator,
    access_token: []const u8,
    file_id: []const u8,
) !void {
    if (access_token.len == 0) return error.GdriveAuthMissing;
    const api_base = try apiBaseUrl(allocator);
    defer allocator.free(api_base);
    const url = try std.fmt.allocPrint(
        allocator,
        "{s}/drive/v3/files/{s}?supportsAllDrives=true",
        .{ api_base, file_id },
    );
    defer allocator.free(url);

    const body = try httpJsonRequest(allocator, access_token, .DELETE, url, null);
    allocator.free(body);
}

pub fn updateFileMetadata(
    allocator: std.mem.Allocator,
    access_token: []const u8,
    file_id: []const u8,
    new_name: ?[]const u8,
    add_parent_id: ?[]const u8,
    remove_parent_id: ?[]const u8,
) !GdriveFile {
    if (access_token.len == 0) return error.GdriveAuthMissing;
    const api_base = try apiBaseUrl(allocator);
    defer allocator.free(api_base);

    const encoded_fields = try percentEncodeQueryComponent(allocator, single_file_fields);
    defer allocator.free(encoded_fields);

    const add_value = if (add_parent_id) |value|
        try percentEncodeQueryComponent(allocator, value)
    else
        null;
    defer if (add_value) |value| allocator.free(value);
    const remove_value = if (remove_parent_id) |value|
        try percentEncodeQueryComponent(allocator, value)
    else
        null;
    defer if (remove_value) |value| allocator.free(value);

    var url_builder = std.ArrayListUnmanaged(u8){};
    defer url_builder.deinit(allocator);
    try url_builder.writer(allocator).print(
        "{s}/drive/v3/files/{s}?supportsAllDrives=true&fields={s}",
        .{ api_base, file_id, encoded_fields },
    );
    if (add_value) |value| try url_builder.writer(allocator).print("&addParents={s}", .{value});
    if (remove_value) |value| try url_builder.writer(allocator).print("&removeParents={s}", .{value});
    const url = try url_builder.toOwnedSlice(allocator);
    defer allocator.free(url);

    var payload = std.ArrayListUnmanaged(u8){};
    defer payload.deinit(allocator);
    if (new_name) |name| {
        try payload.appendSlice(allocator, "{\"name\":");
        try appendJsonString(&payload, allocator, name);
        try payload.appendSlice(allocator, "}");
    } else {
        try payload.appendSlice(allocator, "{}");
    }

    const body = try httpJsonRequest(allocator, access_token, .PATCH, url, payload.items);
    defer allocator.free(body);
    if (body.len == 0) return statFile(allocator, access_token, file_id);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return error.GdriveInvalidResponse;
    defer parsed.deinit();
    return parseFileValue(allocator, parsed.value);
}

pub fn readFileAll(allocator: std.mem.Allocator, access_token: []const u8, file_id: []const u8) ![]u8 {
    if (access_token.len == 0) return error.GdriveAuthMissing;
    const api_base = try apiBaseUrl(allocator);
    defer allocator.free(api_base);
    const url = try std.fmt.allocPrint(
        allocator,
        "{s}/drive/v3/files/{s}?supportsAllDrives=true&alt=media",
        .{ api_base, file_id },
    );
    defer allocator.free(url);
    return httpGet(allocator, access_token, url, null);
}

pub fn updateFileContent(
    allocator: std.mem.Allocator,
    access_token: []const u8,
    file_id: []const u8,
    content: []const u8,
) !GdriveFile {
    if (access_token.len == 0) return error.GdriveAuthMissing;
    const encoded_fields = try percentEncodeQueryComponent(allocator, single_file_fields);
    defer allocator.free(encoded_fields);
    const upload_base = try uploadBaseUrl(allocator);
    defer allocator.free(upload_base);

    const body = if (content.len == 0) blk: {
        const media_url = try std.fmt.allocPrint(
            allocator,
            "{s}/upload/drive/v3/files/{s}?uploadType=media&supportsAllDrives=true&fields={s}",
            .{ upload_base, file_id, encoded_fields },
        );
        defer allocator.free(media_url);
        break :blk try httpMediaRequest(allocator, access_token, .PATCH, media_url, content);
    } else try uploadFileContentResumable(
        allocator,
        access_token,
        upload_base,
        file_id,
        encoded_fields,
        content,
    );
    defer allocator.free(body);
    if (body.len == 0) return statFile(allocator, access_token, file_id);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return error.GdriveInvalidResponse;
    defer parsed.deinit();
    return parseFileValue(allocator, parsed.value);
}

pub fn updateFileContentFromFile(
    allocator: std.mem.Allocator,
    access_token: []const u8,
    file_id: []const u8,
    file: *std.fs.File,
    content_len: u64,
) !GdriveFile {
    if (access_token.len == 0) return error.GdriveAuthMissing;
    const encoded_fields = try percentEncodeQueryComponent(allocator, single_file_fields);
    defer allocator.free(encoded_fields);
    const upload_base = try uploadBaseUrl(allocator);
    defer allocator.free(upload_base);

    const body = if (content_len == 0) blk: {
        const media_url = try std.fmt.allocPrint(
            allocator,
            "{s}/upload/drive/v3/files/{s}?uploadType=media&supportsAllDrives=true&fields={s}",
            .{ upload_base, file_id, encoded_fields },
        );
        defer allocator.free(media_url);
        break :blk try httpMediaRequest(allocator, access_token, .PATCH, media_url, "");
    } else try uploadFileContentResumableFromFile(
        allocator,
        access_token,
        upload_base,
        file_id,
        encoded_fields,
        file,
        content_len,
    );
    defer allocator.free(body);
    if (body.len == 0) return statFile(allocator, access_token, file_id);

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return error.GdriveInvalidResponse;
    defer parsed.deinit();
    return parseFileValue(allocator, parsed.value);
}

fn uploadFileContentResumable(
    allocator: std.mem.Allocator,
    access_token: []const u8,
    upload_base: []const u8,
    file_id: []const u8,
    encoded_fields: []const u8,
    content: []const u8,
) ![]u8 {
    const init_url = try std.fmt.allocPrint(
        allocator,
        "{s}/upload/drive/v3/files/{s}?uploadType=resumable&supportsAllDrives=true&fields={s}",
        .{ upload_base, file_id, encoded_fields },
    );
    defer allocator.free(init_url);

    const upload_content_len = try std.fmt.allocPrint(allocator, "{d}", .{content.len});
    defer allocator.free(upload_content_len);
    const init_headers = [_]std.http.Header{
        .{ .name = "content-type", .value = "application/json; charset=UTF-8" },
        .{ .name = "x-upload-content-type", .value = "application/octet-stream" },
        .{ .name = "x-upload-content-length", .value = upload_content_len },
    };

    var init_response = try httpRequest(
        allocator,
        access_token,
        .PATCH,
        init_url,
        "{}",
        &init_headers,
    );
    defer init_response.deinit(allocator);
    try ensureStatusSuccess(init_response.status);
    const session_url = init_response.location orelse return error.GdriveInvalidResponse;

    var offset: usize = 0;
    while (offset < content.len) {
        const chunk_end = @min(offset + gdrive_resumable_chunk_size, content.len);
        const chunk = content[offset..chunk_end];

        const content_range = try std.fmt.allocPrint(
            allocator,
            "bytes {d}-{d}/{d}",
            .{ offset, chunk_end - 1, content.len },
        );
        defer allocator.free(content_range);
        const chunk_headers = [_]std.http.Header{
            .{ .name = "content-type", .value = "application/octet-stream" },
            .{ .name = "content-range", .value = content_range },
        };

        var chunk_response = try httpRequest(
            allocator,
            access_token,
            .PUT,
            session_url,
            chunk,
            &chunk_headers,
        );
        errdefer chunk_response.deinit(allocator);

        if (chunk_end < content.len) {
            if (chunk_response.status != .permanent_redirect) {
                const status = chunk_response.status;
                chunk_response.deinit(allocator);
                return mapStatusToError(status);
            }
            chunk_response.deinit(allocator);
            offset = chunk_end;
            continue;
        }

        try ensureStatusSuccess(chunk_response.status);
        const out = try allocator.dupe(u8, chunk_response.body);
        chunk_response.deinit(allocator);
        return out;
    }

    return allocator.alloc(u8, 0);
}

fn uploadFileContentResumableFromFile(
    allocator: std.mem.Allocator,
    access_token: []const u8,
    upload_base: []const u8,
    file_id: []const u8,
    encoded_fields: []const u8,
    file: *std.fs.File,
    content_len: u64,
) ![]u8 {
    const init_url = try std.fmt.allocPrint(
        allocator,
        "{s}/upload/drive/v3/files/{s}?uploadType=resumable&supportsAllDrives=true&fields={s}",
        .{ upload_base, file_id, encoded_fields },
    );
    defer allocator.free(init_url);

    const upload_content_len = try std.fmt.allocPrint(allocator, "{d}", .{content_len});
    defer allocator.free(upload_content_len);
    const init_headers = [_]std.http.Header{
        .{ .name = "content-type", .value = "application/json; charset=UTF-8" },
        .{ .name = "x-upload-content-type", .value = "application/octet-stream" },
        .{ .name = "x-upload-content-length", .value = upload_content_len },
    };

    var init_response = try httpRequest(
        allocator,
        access_token,
        .PATCH,
        init_url,
        "{}",
        &init_headers,
    );
    defer init_response.deinit(allocator);
    try ensureStatusSuccess(init_response.status);
    const session_url = init_response.location orelse return error.GdriveInvalidResponse;

    const chunk_buf = try allocator.alloc(u8, gdrive_resumable_chunk_size);
    defer allocator.free(chunk_buf);

    var offset: u64 = 0;
    while (offset < content_len) {
        const chunk_end = @min(offset + gdrive_resumable_chunk_size, content_len);
        const chunk_len: usize = @intCast(chunk_end - offset);
        const n = file.pread(chunk_buf[0..chunk_len], offset) catch return error.GdriveUnexpectedStatus;
        if (n != chunk_len) return error.GdriveInvalidResponse;
        const chunk = chunk_buf[0..n];

        const content_range = try std.fmt.allocPrint(
            allocator,
            "bytes {d}-{d}/{d}",
            .{ offset, chunk_end - 1, content_len },
        );
        defer allocator.free(content_range);
        const chunk_headers = [_]std.http.Header{
            .{ .name = "content-type", .value = "application/octet-stream" },
            .{ .name = "content-range", .value = content_range },
        };

        var chunk_response = try httpRequest(
            allocator,
            access_token,
            .PUT,
            session_url,
            chunk,
            &chunk_headers,
        );
        errdefer chunk_response.deinit(allocator);

        if (chunk_end < content_len) {
            if (chunk_response.status != .permanent_redirect) {
                const status = chunk_response.status;
                chunk_response.deinit(allocator);
                return mapStatusToError(status);
            }
            chunk_response.deinit(allocator);
            offset = chunk_end;
            continue;
        }

        try ensureStatusSuccess(chunk_response.status);
        const out = try allocator.dupe(u8, chunk_response.body);
        chunk_response.deinit(allocator);
        return out;
    }

    return allocator.alloc(u8, 0);
}

pub fn getStartPageToken(allocator: std.mem.Allocator, access_token: []const u8) ![]u8 {
    if (access_token.len == 0) return error.GdriveAuthMissing;
    const api_base = try apiBaseUrl(allocator);
    defer allocator.free(api_base);
    const url = try std.fmt.allocPrint(allocator, "{s}/drive/v3/changes/startPageToken?supportsAllDrives=true", .{api_base});
    defer allocator.free(url);
    const body = try httpGet(allocator, access_token, url, null);
    defer allocator.free(body);
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return error.GdriveInvalidResponse;
    defer parsed.deinit();
    if (parsed.value != .object) return error.GdriveInvalidResponse;
    const token_v = parsed.value.object.get("startPageToken") orelse return error.GdriveInvalidResponse;
    if (token_v != .string or token_v.string.len == 0) return error.GdriveInvalidResponse;
    return allocator.dupe(u8, token_v.string);
}

pub fn listChanges(
    allocator: std.mem.Allocator,
    access_token: []const u8,
    page_token: []const u8,
) !ChangesPage {
    if (access_token.len == 0) return error.GdriveAuthMissing;
    if (page_token.len == 0) return error.GdriveInvalidResponse;
    const api_base = try apiBaseUrl(allocator);
    defer allocator.free(api_base);

    const encoded_page = try percentEncodeQueryComponent(allocator, page_token);
    defer allocator.free(encoded_page);
    const encoded_fields = try percentEncodeQueryComponent(allocator, change_fields);
    defer allocator.free(encoded_fields);

    const url = try std.fmt.allocPrint(
        allocator,
        "{s}/drive/v3/changes?supportsAllDrives=true&includeItemsFromAllDrives=true&pageSize=200&pageToken={s}&fields={s}",
        .{ api_base, encoded_page, encoded_fields },
    );
    defer allocator.free(url);

    const body = try httpGet(allocator, access_token, url, null);
    defer allocator.free(body);
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return error.GdriveInvalidResponse;
    defer parsed.deinit();
    if (parsed.value != .object) return error.GdriveInvalidResponse;
    const obj = parsed.value.object;
    const changes_v = obj.get("changes") orelse return error.GdriveInvalidResponse;
    if (changes_v != .array) return error.GdriveInvalidResponse;

    var out = std.ArrayListUnmanaged(Change){};
    errdefer {
        for (out.items) |*change| change.deinit(allocator);
        out.deinit(allocator);
    }

    for (changes_v.array.items) |entry| {
        const change = parseChangeValue(allocator, entry) catch continue;
        try out.append(allocator, change);
    }

    const next_page_token = if (obj.get("nextPageToken")) |value|
        if (value == .string and value.string.len > 0)
            try allocator.dupe(u8, value.string)
        else
            null
    else
        null;
    errdefer if (next_page_token) |token| allocator.free(token);
    const new_start_page_token = if (obj.get("newStartPageToken")) |value|
        if (value == .string and value.string.len > 0)
            try allocator.dupe(u8, value.string)
        else
            null
    else
        null;
    errdefer if (new_start_page_token) |token| allocator.free(token);

    return .{
        .changes = try out.toOwnedSlice(allocator),
        .next_page_token = next_page_token,
        .new_start_page_token = new_start_page_token,
    };
}

pub fn refreshAccessToken(
    allocator: std.mem.Allocator,
    client_id: []const u8,
    client_secret: []const u8,
    refresh_token: []const u8,
) !OAuthRefreshResult {
    if (client_id.len == 0 or client_secret.len == 0 or refresh_token.len == 0) return error.GdriveAuthMissing;
    const oauth_base = try oauthBaseUrl(allocator);
    defer allocator.free(oauth_base);

    const enc_client_id = try percentEncodeQueryComponent(allocator, client_id);
    defer allocator.free(enc_client_id);
    const enc_client_secret = try percentEncodeQueryComponent(allocator, client_secret);
    defer allocator.free(enc_client_secret);
    const enc_refresh_token = try percentEncodeQueryComponent(allocator, refresh_token);
    defer allocator.free(enc_refresh_token);

    const payload = try std.fmt.allocPrint(
        allocator,
        "client_id={s}&client_secret={s}&refresh_token={s}&grant_type=refresh_token",
        .{ enc_client_id, enc_client_secret, enc_refresh_token },
    );
    defer allocator.free(payload);

    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    var body_writer: std.Io.Writer.Allocating = .init(allocator);
    defer body_writer.deinit();

    const headers = [_]std.http.Header{
        .{ .name = "content-type", .value = "application/x-www-form-urlencoded" },
        .{ .name = "accept", .value = "application/json" },
    };
    const token_url = try std.fmt.allocPrint(allocator, "{s}/token", .{oauth_base});
    defer allocator.free(token_url);

    const result = client.fetch(.{
        .location = .{ .url = token_url },
        .method = .POST,
        .payload = payload,
        .extra_headers = &headers,
        .response_writer = &body_writer.writer,
    }) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.GdriveTokenRefreshFailed,
    };

    if (result.status != .ok) {
        return switch (result.status) {
            .unauthorized, .forbidden => error.GdriveAccessDenied,
            else => error.GdriveTokenRefreshFailed,
        };
    }

    const body = try body_writer.toOwnedSlice();
    defer allocator.free(body);
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch return error.GdriveTokenRefreshFailed;
    defer parsed.deinit();
    if (parsed.value != .object) return error.GdriveTokenRefreshFailed;
    const obj = parsed.value.object;

    const access_v = obj.get("access_token") orelse return error.GdriveTokenRefreshFailed;
    const expires_v = obj.get("expires_in") orelse return error.GdriveTokenRefreshFailed;
    if (access_v != .string) return error.GdriveTokenRefreshFailed;

    const expires_sec: u64 = switch (expires_v) {
        .integer => |num| if (num <= 0) return error.GdriveTokenRefreshFailed else @intCast(num),
        .string => |text| std.fmt.parseInt(u64, text, 10) catch return error.GdriveTokenRefreshFailed,
        else => return error.GdriveTokenRefreshFailed,
    };

    const now_ms: u64 = currentTimeMs();
    const raw_expiry = now_ms + expires_sec * std.time.ms_per_s;
    const skewed = if (raw_expiry > 300_000) raw_expiry - 300_000 else raw_expiry;

    const refresh_out = if (obj.get("refresh_token")) |refresh_v|
        if (refresh_v == .string and refresh_v.string.len > 0)
            try allocator.dupe(u8, refresh_v.string)
        else
            null
    else
        null;

    return .{
        .access_token = try allocator.dupe(u8, access_v.string),
        .refresh_token = refresh_out,
        .expires_at_ms = skewed,
    };
}

fn httpGet(
    allocator: std.mem.Allocator,
    access_token: []const u8,
    url: []const u8,
    extra_header: ?std.http.Header,
) ![]u8 {
    var header_buf: [1]std.http.Header = undefined;
    const headers: []const std.http.Header = if (extra_header) |value| blk: {
        header_buf[0] = value;
        break :blk header_buf[0..1];
    } else &.{};
    var response = try httpRequest(allocator, access_token, .GET, url, null, headers);
    defer response.deinit(allocator);
    switch (response.status) {
        .ok, .partial_content => return allocator.dupe(u8, response.body),
        else => return mapStatusToError(response.status),
    }
}

fn httpJsonRequest(
    allocator: std.mem.Allocator,
    access_token: []const u8,
    method: std.http.Method,
    url: []const u8,
    payload: ?[]const u8,
) ![]u8 {
    var header_buf: [1]std.http.Header = .{.{ .name = "content-type", .value = "application/json" }};
    const headers: []const std.http.Header = if (payload != null) header_buf[0..1] else &.{};
    var response = try httpRequest(allocator, access_token, httpMethodFromStd(method), url, payload, headers);
    defer response.deinit(allocator);
    try ensureStatusSuccess(response.status);
    return allocator.dupe(u8, response.body);
}

fn httpMediaRequest(
    allocator: std.mem.Allocator,
    access_token: []const u8,
    method: std.http.Method,
    url: []const u8,
    payload: []const u8,
) ![]u8 {
    const headers = [_]std.http.Header{
        .{ .name = "content-type", .value = "application/octet-stream" },
    };
    var response = try httpRequest(allocator, access_token, httpMethodFromStd(method), url, payload, &headers);
    defer response.deinit(allocator);
    try ensureStatusSuccess(response.status);
    return allocator.dupe(u8, response.body);
}

fn httpRequest(
    allocator: std.mem.Allocator,
    access_token: []const u8,
    method: HttpMethod,
    url: []const u8,
    payload: ?[]const u8,
    extra_headers: []const std.http.Header,
) !HttpResponse {
    const auth_header = try std.fmt.allocPrint(allocator, "Bearer {s}", .{access_token});
    defer allocator.free(auth_header);

    var all_headers = std.ArrayListUnmanaged(std.http.Header){};
    defer all_headers.deinit(allocator);
    try all_headers.append(allocator, .{ .name = "authorization", .value = auth_header });
    try all_headers.append(allocator, .{ .name = "accept", .value = "application/json" });
    try all_headers.appendSlice(allocator, extra_headers);

    if (test_transport) |transport| {
        const mock = transport.handler(
            transport.ctx,
            allocator,
            method,
            url,
            payload,
            all_headers.items,
        ) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => return error.GdriveUnexpectedStatus,
        };
        return .{
            .status = mock.status,
            .body = try allocator.dupe(u8, mock.body),
            .location = if (mock.location) |value| try allocator.dupe(u8, value) else null,
            .range = if (mock.range) |value| try allocator.dupe(u8, value) else null,
        };
    }

    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    const uri = std.Uri.parse(url) catch return error.GdriveInvalidResponse;
    var req = client.request(httpMethodToStd(method), uri, .{
        .redirect_behavior = .unhandled,
        .extra_headers = all_headers.items,
    }) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.GdriveUnexpectedStatus,
    };
    defer req.deinit();

    if (payload) |payload_bytes| {
        req.transfer_encoding = .{ .content_length = payload_bytes.len };
        var body = req.sendBodyUnflushed(&.{}) catch return error.GdriveUnexpectedStatus;
        body.writer.writeAll(payload_bytes) catch return error.GdriveUnexpectedStatus;
        body.end() catch return error.GdriveUnexpectedStatus;
        req.connection.?.flush() catch return error.GdriveUnexpectedStatus;
    } else {
        req.sendBodiless() catch return error.GdriveUnexpectedStatus;
    }

    var response = req.receiveHead(&.{}) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.GdriveUnexpectedStatus,
    };

    const location = if (response.head.location) |value|
        try allocator.dupe(u8, value)
    else
        null;
    errdefer if (location) |value| allocator.free(value);
    const range = try headerValueDup(allocator, response.head.bytes, "range");
    errdefer if (range) |value| allocator.free(value);

    var body_writer: std.Io.Writer.Allocating = .init(allocator);
    defer body_writer.deinit();
    _ = response.reader(&.{}).streamRemaining(&body_writer.writer) catch return error.GdriveUnexpectedStatus;

    return .{
        .status = response.head.status,
        .body = try body_writer.toOwnedSlice(),
        .location = location,
        .range = range,
    };
}

fn httpMethodToStd(method: HttpMethod) std.http.Method {
    return switch (method) {
        .GET => .GET,
        .POST => .POST,
        .PATCH => .PATCH,
        .PUT => .PUT,
        .DELETE => .DELETE,
    };
}

fn httpMethodFromStd(method: std.http.Method) HttpMethod {
    return switch (method) {
        .GET => .GET,
        .POST => .POST,
        .PATCH => .PATCH,
        .PUT => .PUT,
        .DELETE => .DELETE,
        else => .POST,
    };
}

fn ensureStatusSuccess(status: std.http.Status) !void {
    switch (status) {
        .ok, .created, .no_content, .partial_content => {},
        else => return mapStatusToError(status),
    }
}

fn mapStatusToError(status: std.http.Status) Error {
    return switch (status) {
        .unauthorized, .forbidden => error.GdriveAccessDenied,
        .not_found => error.GdriveNotFound,
        .too_many_requests => error.GdriveRateLimited,
        .conflict, .precondition_failed => error.GdriveConflict,
        .bad_request, .range_not_satisfiable => error.GdriveInvalidResponse,
        else => error.GdriveUnexpectedStatus,
    };
}

fn headerValueDup(allocator: std.mem.Allocator, head_bytes: []const u8, header_name: []const u8) !?[]u8 {
    var lines = std.mem.splitSequence(u8, head_bytes, "\r\n");
    _ = lines.first();
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon_idx = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const current_name = std.mem.trim(u8, line[0..colon_idx], " \t");
        if (!std.ascii.eqlIgnoreCase(current_name, header_name)) continue;
        const value = std.mem.trim(u8, line[colon_idx + 1 ..], " \t");
        return try allocator.dupe(u8, value);
    }
    return null;
}

fn appendJsonString(out: *std.ArrayListUnmanaged(u8), allocator: std.mem.Allocator, text: []const u8) !void {
    try out.append(allocator, '"');
    for (text) |ch| {
        switch (ch) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => {
                if (ch < 0x20) {
                    try out.writer(allocator).print("\\u00{x:0>2}", .{ch});
                } else {
                    try out.append(allocator, ch);
                }
            },
        }
    }
    try out.append(allocator, '"');
}

fn parseFileValue(allocator: std.mem.Allocator, value: std.json.Value) !GdriveFile {
    if (value != .object) return error.GdriveInvalidResponse;
    const obj = value.object;

    const id = try getRequiredStringDup(allocator, obj, "id");
    errdefer allocator.free(id);
    const name = try getRequiredStringDup(allocator, obj, "name");
    errdefer allocator.free(name);
    const mime_type = try getRequiredStringDup(allocator, obj, "mimeType");
    errdefer allocator.free(mime_type);
    const primary_parent_id = try parsePrimaryParentId(allocator, obj);
    errdefer if (primary_parent_id) |parent_id| allocator.free(parent_id);

    const size = parseOptionalSize(obj.get("size"));
    const mtime_ns = parseOptionalMtime(obj.get("modifiedTime"));
    const is_dir = std.mem.eql(u8, mime_type, gdrive_folder_mime);
    const version = parseOptionalSize(obj.get("version"));

    const generation_seed: u64 = if (version != 0) version else blk: {
        var seed: u64 = std.hash.Wyhash.hash(0x4744_4D45_5441_0001, id);
        seed ^= std.hash.Wyhash.hash(0x4744_4D45_5441_0002, name);
        seed ^= std.hash.Wyhash.hash(0x4744_4D45_5441_0003, mime_type);
        if (primary_parent_id) |parent_id| {
            seed ^= std.hash.Wyhash.hash(0x4744_4D45_5441_0004, parent_id);
        }
        seed ^= size;
        break :blk seed;
    };

    return .{
        .id = id,
        .name = name,
        .mime_type = mime_type,
        .primary_parent_id = primary_parent_id,
        .size = size,
        .mtime_ns = mtime_ns,
        .generation = generation_seed,
        .is_dir = is_dir,
    };
}

fn parseChangeValue(allocator: std.mem.Allocator, value: std.json.Value) !Change {
    if (value != .object) return error.GdriveInvalidResponse;
    const obj = value.object;

    const removed = if (obj.get("removed")) |removed_v|
        if (removed_v == .bool) removed_v.bool else false
    else
        false;

    const file_id = if (obj.get("fileId")) |file_id_v|
        if (file_id_v == .string and file_id_v.string.len > 0)
            try allocator.dupe(u8, file_id_v.string)
        else
            return error.GdriveInvalidResponse
    else if (obj.get("file")) |file_v| blk: {
        if (file_v != .object) return error.GdriveInvalidResponse;
        const id_v = file_v.object.get("id") orelse return error.GdriveInvalidResponse;
        if (id_v != .string or id_v.string.len == 0) return error.GdriveInvalidResponse;
        break :blk try allocator.dupe(u8, id_v.string);
    } else return error.GdriveInvalidResponse;
    errdefer allocator.free(file_id);

    const file = if (!removed)
        if (obj.get("file")) |file_v|
            parseFileValue(allocator, file_v) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => null,
            }
        else
            null
    else
        null;
    errdefer if (file) |*value_file| value_file.deinit(allocator);

    return .{
        .file_id = file_id,
        .removed = removed,
        .file = file,
    };
}

fn parseOptionalSize(maybe_value: ?std.json.Value) u64 {
    const value = maybe_value orelse return 0;
    return switch (value) {
        .string => |text| std.fmt.parseInt(u64, text, 10) catch 0,
        .integer => |num| if (num < 0) 0 else @intCast(num),
        else => 0,
    };
}

fn parseOptionalMtime(maybe_value: ?std.json.Value) i64 {
    const value = maybe_value orelse return 0;
    if (value != .string) return 0;

    // Keep this lightweight for now: use a stable hash-derived timestamp-like value
    // rather than strict RFC3339 parsing until we wire a full timestamp parser.
    const hash = std.hash.Wyhash.hash(0x4744_4D54_494D_4501, value.string);
    return @intCast(@min(hash, @as(u64, std.math.maxInt(i64))));
}

fn getRequiredStringDup(
    allocator: std.mem.Allocator,
    obj: std.json.ObjectMap,
    field: []const u8,
) ![]u8 {
    const value = obj.get(field) orelse return error.GdriveInvalidResponse;
    if (value != .string) return error.GdriveInvalidResponse;
    return allocator.dupe(u8, value.string);
}

fn parsePrimaryParentId(allocator: std.mem.Allocator, obj: std.json.ObjectMap) !?[]u8 {
    const parents_value = obj.get("parents") orelse return null;
    if (parents_value != .array) return null;
    if (parents_value.array.items.len == 0) return null;
    const first_parent = parents_value.array.items[0];
    if (first_parent != .string or first_parent.string.len == 0) return null;
    return try allocator.dupe(u8, first_parent.string);
}

fn buildChildrenQuery(allocator: std.mem.Allocator, parent_id: []const u8) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "'{s}' in parents and trashed = false",
        .{parent_id},
    );
}

fn percentEncodeQueryComponent(allocator: std.mem.Allocator, text: []const u8) std.mem.Allocator.Error![]u8 {
    var writer: std.Io.Writer.Allocating = .init(allocator);
    defer writer.deinit();
    (std.Uri.Component{ .raw = text }).formatQuery(&writer.writer) catch return error.OutOfMemory;
    return writer.toOwnedSlice();
}

fn escapeQueryLiteral(allocator: std.mem.Allocator, raw: []const u8) std.mem.Allocator.Error![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);

    for (raw) |ch| {
        switch (ch) {
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '\'' => try out.appendSlice(allocator, "\\'"),
            else => try out.append(allocator, ch),
        }
    }

    return out.toOwnedSlice(allocator);
}

fn parseTruthyEnvFlag(raw: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(raw, "1")) return true;
    if (std.ascii.eqlIgnoreCase(raw, "true")) return true;
    if (std.ascii.eqlIgnoreCase(raw, "yes")) return true;
    if (std.ascii.eqlIgnoreCase(raw, "on")) return true;
    return false;
}

fn currentTimeMs() u64 {
    const now = std.time.milliTimestamp();
    if (now <= 0) return 0;
    return @intCast(now);
}

test "fs_gdrive_backend: normalizeRootId supports drive prefix" {
    try std.testing.expectEqualStrings("root", normalizeRootId(""));
    try std.testing.expectEqualStrings("root", normalizeRootId("drive:root"));
    try std.testing.expectEqualStrings("abc123", normalizeRootId("drive:abc123"));
    try std.testing.expectEqualStrings("xyz", normalizeRootId("xyz"));
}

test "fs_gdrive_backend: parseChangeValue handles removed and file changes" {
    const allocator = std.testing.allocator;

    {
        var parsed = try std.json.parseFromSlice(
            std.json.Value,
            allocator,
            "{\"fileId\":\"abc\",\"removed\":true}",
            .{},
        );
        defer parsed.deinit();
        var change = try parseChangeValue(allocator, parsed.value);
        defer change.deinit(allocator);
        try std.testing.expectEqualStrings("abc", change.file_id);
        try std.testing.expect(change.removed);
        try std.testing.expect(change.file == null);
    }

    {
        var parsed = try std.json.parseFromSlice(
            std.json.Value,
            allocator,
            "{\"fileId\":\"file-1\",\"removed\":false,\"file\":{\"id\":\"file-1\",\"name\":\"doc.txt\",\"mimeType\":\"text/plain\",\"parents\":[\"parent-1\"],\"size\":\"12\",\"modifiedTime\":\"2026-01-01T00:00:00Z\"}}",
            .{},
        );
        defer parsed.deinit();
        var change = try parseChangeValue(allocator, parsed.value);
        defer change.deinit(allocator);
        try std.testing.expect(!change.removed);
        try std.testing.expect(change.file != null);
        try std.testing.expectEqualStrings("doc.txt", change.file.?.name);
        try std.testing.expect(change.file.?.primary_parent_id != null);
        try std.testing.expectEqualStrings("parent-1", change.file.?.primary_parent_id.?);
    }
}

const ResumableUploadTestCtx = struct {
    content_len: usize,
    init_calls: usize = 0,
    put_calls: usize = 0,
};

fn testHeaderValue(headers: []const std.http.Header, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

fn resumableUploadTestHandler(
    raw_ctx: ?*anyopaque,
    allocator: std.mem.Allocator,
    method: HttpMethod,
    url: []const u8,
    payload: ?[]const u8,
    headers: []const std.http.Header,
) anyerror!MockResponse {
    _ = allocator;
    const ctx: *ResumableUploadTestCtx = @ptrCast(@alignCast(raw_ctx.?));

    if (method == .PATCH and std.mem.indexOf(u8, url, "uploadType=resumable") != null) {
        ctx.init_calls += 1;
        return .{
            .status = .ok,
            .location = "https://upload.mock/session/abc",
        };
    }

    if (method == .PUT and std.mem.eql(u8, url, "https://upload.mock/session/abc")) {
        ctx.put_calls += 1;
        const payload_slice = payload orelse return error.GdriveInvalidResponse;
        const content_range = testHeaderValue(headers, "content-range") orelse return error.GdriveInvalidResponse;

        if (ctx.put_calls == 1) {
            try std.testing.expectEqual(@as(usize, gdrive_resumable_chunk_size), payload_slice.len);
            const expected = try std.fmt.allocPrint(
                std.testing.allocator,
                "bytes 0-{d}/{d}",
                .{ gdrive_resumable_chunk_size - 1, ctx.content_len },
            );
            defer std.testing.allocator.free(expected);
            try std.testing.expectEqualStrings(expected, content_range);
            return .{
                .status = .permanent_redirect,
                .range = "bytes=0-262143",
            };
        }

        if (ctx.put_calls == 2) {
            try std.testing.expectEqual(@as(usize, 17), payload_slice.len);
            const expected = try std.fmt.allocPrint(
                std.testing.allocator,
                "bytes {d}-{d}/{d}",
                .{ gdrive_resumable_chunk_size, ctx.content_len - 1, ctx.content_len },
            );
            defer std.testing.allocator.free(expected);
            try std.testing.expectEqualStrings(expected, content_range);
            return .{
                .status = .ok,
                .body = "{\"id\":\"file-1\",\"name\":\"report.txt\",\"mimeType\":\"text/plain\",\"parents\":[\"root\"],\"size\":\"262161\",\"modifiedTime\":\"2026-01-01T00:00:00Z\",\"version\":\"9\"}",
            };
        }
    }

    return error.GdriveUnexpectedStatus;
}

test "fs_gdrive_backend: updateFileContent uses resumable chunk uploads" {
    const allocator = std.testing.allocator;
    const content_len = gdrive_resumable_chunk_size + 17;
    const content = try allocator.alloc(u8, content_len);
    defer allocator.free(content);
    @memset(content, 'x');

    var ctx = ResumableUploadTestCtx{ .content_len = content_len };
    setTestTransport(.{
        .ctx = &ctx,
        .handler = resumableUploadTestHandler,
    });
    defer setTestTransport(null);

    var updated = try updateFileContent(allocator, "test-token", "file-1", content);
    defer updated.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), ctx.init_calls);
    try std.testing.expectEqual(@as(usize, 2), ctx.put_calls);
    try std.testing.expectEqualStrings("file-1", updated.id);
    try std.testing.expectEqual(@as(u64, 9), updated.generation);
}

test "fs_gdrive_backend: updateFileContentFromFile uses resumable chunk uploads" {
    const allocator = std.testing.allocator;
    const content_len = gdrive_resumable_chunk_size + 17;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const sub_path = "upload.bin";
    const content = try allocator.alloc(u8, content_len);
    defer allocator.free(content);
    @memset(content, 'y');
    try tmp_dir.dir.writeFile(.{ .sub_path = sub_path, .data = content });

    var file = try tmp_dir.dir.openFile(sub_path, .{ .mode = .read_only });
    defer file.close();

    var ctx = ResumableUploadTestCtx{ .content_len = content_len };
    setTestTransport(.{
        .ctx = &ctx,
        .handler = resumableUploadTestHandler,
    });
    defer setTestTransport(null);

    var updated = try updateFileContentFromFile(allocator, "test-token", "file-1", &file, content_len);
    defer updated.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), ctx.init_calls);
    try std.testing.expectEqual(@as(usize, 2), ctx.put_calls);
    try std.testing.expectEqualStrings("file-1", updated.id);
    try std.testing.expectEqual(@as(u64, 9), updated.generation);
}
