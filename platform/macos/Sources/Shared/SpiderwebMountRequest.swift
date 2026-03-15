import Darwin
import FSKit
import Foundation

struct SpiderwebMountRequest: Codable {
    struct Endpoint: Codable {
        let name: String
        let url: String
        let exportName: String?
        let mountPath: String
        let authToken: String?

        private enum CodingKeys: String, CodingKey {
            case name
            case url
            case exportName = "export_name"
            case mountPath = "mount_path"
            case authToken = "auth_token"
        }
    }

    struct Namespace: Codable {
        let namespaceURL: String
        let authToken: String?
        let projectID: String
        let agentID: String
        let sessionKey: String
        let projectToken: String?

        private enum CodingKeys: String, CodingKey {
            case namespaceURL = "namespace_url"
            case authToken = "auth_token"
            case projectID = "project_id"
            case agentID = "agent_id"
            case sessionKey = "session_key"
            case projectToken = "project_token"
        }
    }

    let schema: Int
    let mountpoint: String
    let workspaceSyncIntervalMS: UInt64
    let namespaceKeepaliveIntervalMS: UInt64
    let endpoints: [Endpoint]
    let namespace: Namespace?

    private enum CodingKeys: String, CodingKey {
        case schema
        case mountpoint
        case workspaceSyncIntervalMS = "workspace_sync_interval_ms"
        case namespaceKeepaliveIntervalMS = "namespace_keepalive_interval_ms"
        case endpoints
        case namespace
    }

    static func load(from url: URL) throws -> SpiderwebMountRequest {
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(SpiderwebMountRequest.self, from: data)
    }

    static func load(from resource: FSResource) throws -> SpiderwebMountRequest {
        let resourceObject = resource as AnyObject
        if let url = resourceObject.value(forKey: "url") as? URL {
            return try load(fromMountedResourceURL: url)
        }

        let resourceClass = NSStringFromClass(type(of: resourceObject))
        throw SpiderwebFSKitBridgeError.invalidMountedResourceType(resourceClass)
    }

    static func load(fromMountedResourceURL url: URL) throws -> SpiderwebMountRequest {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let encodedConfig = components.queryItems?.first(where: { $0.name == "config_b64" })?.value,
              let data = Data(urlSafeBase64Encoded: encodedConfig)
        else {
            throw SpiderwebFSKitBridgeError.invalidRPCResponse
        }
        return try JSONDecoder().decode(SpiderwebMountRequest.self, from: data)
    }
}

struct SpiderwebRemoteAttr: Decodable {
    let id: UInt64
    let kindCode: UInt8
    let mode: UInt32
    let linkCount: UInt32
    let uid: UInt32
    let gid: UInt32
    let size: UInt64
    let accessTimeNS: Int64
    let modifyTimeNS: Int64
    let changeTimeNS: Int64

    private enum CodingKeys: String, CodingKey {
        case id
        case kindCode = "k"
        case mode = "m"
        case linkCount = "n"
        case uid = "u"
        case gid = "g"
        case size = "sz"
        case accessTimeNS = "at"
        case modifyTimeNS = "mt"
        case changeTimeNS = "ct"
    }
}

struct SpiderwebRemoteDirectoryListing: Decodable {
    struct Entry: Decodable {
        let name: String
        let attr: SpiderwebRemoteAttr?
    }

    let entries: [Entry]
    let nextCookie: UInt64
    let eof: Bool
    let directoryGeneration: UInt64

    private enum CodingKeys: String, CodingKey {
        case entries = "ents"
        case next
        case nextCookie = "next_cookie"
        case eof
        case directoryGeneration = "dir_gen"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        entries = try container.decodeIfPresent([Entry].self, forKey: .entries) ?? []
        let nextCookieValue = try container.decodeIfPresent(UInt64.self, forKey: .nextCookie)
        let nextValue = try container.decodeIfPresent(UInt64.self, forKey: .next)
        nextCookie = nextCookieValue ?? nextValue ?? 0
        eof = try container.decodeIfPresent(Bool.self, forKey: .eof) ?? (nextCookie == 0)
        directoryGeneration = try container.decodeIfPresent(UInt64.self, forKey: .directoryGeneration) ?? 1
    }
}

struct SpiderwebRemoteStatFS: Decodable {
    let blockSize: UInt64
    let fragmentSize: UInt64
    let totalBlocks: UInt64
    let freeBlocks: UInt64
    let availableBlocks: UInt64
    let totalFiles: UInt64
    let freeFiles: UInt64
    let availableFiles: UInt64
    let maximumNameLength: UInt64

    private enum CodingKeys: String, CodingKey {
        case blockSize = "bsize"
        case fragmentSize = "frsize"
        case totalBlocks = "blocks"
        case freeBlocks = "bfree"
        case availableBlocks = "bavail"
        case totalFiles = "files"
        case freeFiles = "ffree"
        case availableFiles = "favail"
        case maximumNameLength = "namemax"
    }
}

struct SpiderwebOpenHandleResponse {
    let handleID: UInt64
    let writable: Bool
}

enum SpiderwebFSKitBridgeError: LocalizedError {
    case helperExecutableMissing(URL)
    case helperLaunchFailed(String)
    case helperProtocolFailure(String)
    case invalidRPCResponse
    case invalidMountedResourceType(String)
    case invalidFilenameEncoding
    case unsupportedPath(String)

    var errorDescription: String? {
        switch self {
        case .helperExecutableMissing(let url):
            return "Missing spiderweb-fs-helper at \(url.path)"
        case .helperLaunchFailed(let details):
            return "Failed to launch spiderweb-fs-helper: \(details)"
        case .helperProtocolFailure(let details):
            return details
        case .invalidRPCResponse:
            return "spiderweb-fs-helper returned an invalid response"
        case .invalidMountedResourceType(let resourceClass):
            return "SpiderwebFSKit received unsupported mounted resource type \(resourceClass)"
        case .invalidFilenameEncoding:
            return "SpiderwebFSKit currently requires UTF-8 path components"
        case .unsupportedPath(let path):
            return "SpiderwebFSKit cannot translate path \(path)"
        }
    }
}

enum SpiderwebFSKitPaths {
    static let appGroupIdentifier = "group.com.deanoc.spiderweb.fskit"
    static let supportDirectoryName = "SpiderwebFSKit"
    static let activeRequestFileName = "active-request.json"
    static let sharedHelperFileName = "spiderweb-fs-helper"

    static func fallbackContainerURL(fileManager: FileManager = .default) -> URL {
        fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
            .appendingPathComponent(supportDirectoryName, isDirectory: true)
    }

    static func sharedContainerURL() -> URL {
        if let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupIdentifier) {
            do {
                try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
                return url
            } catch {
                NSLog(
                    "SpiderwebFSKit app group unavailable at %@ (%@); falling back to Application Support.",
                    url.path,
                    error.localizedDescription
                )
            }
        }
        return fallbackContainerURL()
    }
}

private extension Data {
    init?(urlSafeBase64Encoded source: String) {
        var value = source
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = value.count % 4
        if remainder != 0 {
            value.append(String(repeating: "=", count: 4 - remainder))
        }
        self.init(base64Encoded: value)
    }
}

final class SpiderwebFSKitStateStore {
    private let fileManager: FileManager
    let baseURL: URL

    init(
        fileManager: FileManager = .default,
        baseURL: URL = SpiderwebFSKitPaths.sharedContainerURL()
    ) {
        self.fileManager = fileManager
        self.baseURL = baseURL
    }

    var requestsDirectoryURL: URL {
        baseURL.appendingPathComponent("Requests", isDirectory: true)
    }

    var helperDirectoryURL: URL {
        baseURL.appendingPathComponent("Helper", isDirectory: true)
    }

    var activeRequestURL: URL {
        baseURL.appendingPathComponent(SpiderwebFSKitPaths.activeRequestFileName, isDirectory: false)
    }

    var sharedHelperURL: URL {
        helperDirectoryURL.appendingPathComponent(SpiderwebFSKitPaths.sharedHelperFileName, isDirectory: false)
    }

    func prepareDirectories() throws {
        try fileManager.createDirectory(at: baseURL, withIntermediateDirectories: true)
        try fileManager.createDirectory(at: requestsDirectoryURL, withIntermediateDirectories: true)
        try fileManager.createDirectory(at: helperDirectoryURL, withIntermediateDirectories: true)
    }

    @discardableResult
    func activateRequest(from sourceURL: URL) throws -> URL {
        try prepareDirectories()
        let stagedRequestURL = requestsDirectoryURL
            .appendingPathComponent(UUID().uuidString, isDirectory: false)
            .appendingPathExtension("json")
        if fileManager.fileExists(atPath: stagedRequestURL.path) {
            try fileManager.removeItem(at: stagedRequestURL)
        }
        try fileManager.copyItem(at: sourceURL, to: stagedRequestURL)
        if fileManager.fileExists(atPath: activeRequestURL.path) {
            try fileManager.removeItem(at: activeRequestURL)
        }
        try fileManager.copyItem(at: stagedRequestURL, to: activeRequestURL)
        return activeRequestURL
    }

    @discardableResult
    func installHelper(from sourceURL: URL) throws -> URL {
        try prepareDirectories()
        if fileManager.fileExists(atPath: sharedHelperURL.path) {
            try fileManager.removeItem(at: sharedHelperURL)
        }
        try fileManager.copyItem(at: sourceURL, to: sharedHelperURL)
        try fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: sharedHelperURL.path)
        return sharedHelperURL
    }

    func loadActiveRequest() throws -> SpiderwebMountRequest {
        try SpiderwebMountRequest.load(from: activeRequestURL)
    }
}

private struct SpiderwebRPCHeader: Decodable {
    let ok: Bool
}

private struct SpiderwebRPCSuccessEnvelope: Decodable {
    let ok: Bool
    let op: String
    let resultJSON: String?
    let dataB64: String?
    let handleID: UInt64?
    let writable: Bool?
    let bytesWritten: UInt32?

    private enum CodingKeys: String, CodingKey {
        case ok
        case op
        case resultJSON = "result_json"
        case dataB64 = "data_b64"
        case handleID = "handle_id"
        case writable
        case bytesWritten = "bytes_written"
    }
}

private struct SpiderwebRPCErrorEnvelope: Decodable {
    let ok: Bool
    let op: String
    let code: String
    let message: String
}

private extension SpiderwebRPCSuccessEnvelope {
    func decodeResult<T: Decodable>(_ type: T.Type) throws -> T {
        guard let resultJSON else {
            throw SpiderwebFSKitBridgeError.invalidRPCResponse
        }
        return try JSONDecoder().decode(type, from: Data(resultJSON.utf8))
    }

    func decodeData() throws -> Data {
        guard let dataB64, let data = Data(base64Encoded: dataB64) else {
            throw SpiderwebFSKitBridgeError.invalidRPCResponse
        }
        return data
    }
}

final class SpiderwebFSHelperBridge {
    let helperExecutableURL: URL
    let launchConfigURL: URL

    private let lock = NSLock()
    private(set) var process: Process?
    private var stdinPipe: Pipe?
    private var stdoutPipe: Pipe?
    private var stderrPipe: Pipe?

    init(helperExecutableURL: URL, launchConfigURL: URL) {
        self.helperExecutableURL = helperExecutableURL
        self.launchConfigURL = launchConfigURL
    }

    func launchIfNeeded() throws {
        lock.lock()
        defer { lock.unlock() }

        if let process, process.isRunning {
            return
        }
        process = nil
        stdinPipe = nil
        stdoutPipe = nil
        stderrPipe = nil

        guard FileManager.default.isExecutableFile(atPath: helperExecutableURL.path) else {
            throw SpiderwebFSKitBridgeError.helperExecutableMissing(helperExecutableURL)
        }

        let process = Process()
        let stdinPipe = Pipe()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()

        process.executableURL = helperExecutableURL
        process.arguments = ["serve", "--config", launchConfigURL.path]
        process.standardInput = stdinPipe
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        do {
            try process.run()
        } catch {
            throw SpiderwebFSKitBridgeError.helperLaunchFailed(error.localizedDescription)
        }

        self.process = process
        self.stdinPipe = stdinPipe
        self.stdoutPipe = stdoutPipe
        self.stderrPipe = stderrPipe
    }

    func stop() {
        lock.lock()
        defer { lock.unlock() }

        stdinPipe?.fileHandleForWriting.closeFile()
        stdoutPipe?.fileHandleForReading.closeFile()
        stderrPipe?.fileHandleForReading.closeFile()
        process?.terminate()
        process = nil
        stdinPipe = nil
        stdoutPipe = nil
        stderrPipe = nil
    }

    func requireMountedRPCBridge() throws {
        _ = try sendRequest([
            "op": "ping",
        ])
    }

    func getattr(path: String) throws -> SpiderwebRemoteAttr {
        let response = try sendRequest([
            "op": "getattr",
            "path": path,
        ])
        return try response.decodeResult(SpiderwebRemoteAttr.self)
    }

    func readdir(path: String, cookie: UInt64, maxEntries: UInt32) throws -> SpiderwebRemoteDirectoryListing {
        let response = try sendRequest([
            "op": "readdir",
            "path": path,
            "cookie": cookie,
            "max_entries": maxEntries,
        ])
        return try response.decodeResult(SpiderwebRemoteDirectoryListing.self)
    }

    func statfs(path: String) throws -> SpiderwebRemoteStatFS {
        let response = try sendRequest([
            "op": "statfs",
            "path": path,
        ])
        return try response.decodeResult(SpiderwebRemoteStatFS.self)
    }

    func open(path: String, flags: UInt32) throws -> SpiderwebOpenHandleResponse {
        let response = try sendRequest([
            "op": "open",
            "path": path,
            "flags": flags,
        ])
        guard let handleID = response.handleID else {
            throw SpiderwebFSKitBridgeError.invalidRPCResponse
        }
        return SpiderwebOpenHandleResponse(handleID: handleID, writable: response.writable ?? false)
    }

    func create(path: String, mode: UInt32, flags: UInt32) throws -> SpiderwebOpenHandleResponse {
        let response = try sendRequest([
            "op": "create",
            "path": path,
            "mode": mode,
            "flags": flags,
        ])
        guard let handleID = response.handleID else {
            throw SpiderwebFSKitBridgeError.invalidRPCResponse
        }
        return SpiderwebOpenHandleResponse(handleID: handleID, writable: response.writable ?? true)
    }

    func read(handleID: UInt64, offset: UInt64, length: UInt32) throws -> Data {
        let response = try sendRequest([
            "op": "read",
            "handle_id": handleID,
            "off": offset,
            "len": length,
        ])
        return try response.decodeData()
    }

    func write(handleID: UInt64, offset: UInt64, contents: Data) throws -> UInt32 {
        let response = try sendRequest([
            "op": "write",
            "handle_id": handleID,
            "off": offset,
            "data_b64": contents.base64EncodedString(),
        ])
        return response.bytesWritten ?? 0
    }

    func release(handleID: UInt64) throws {
        _ = try sendRequest([
            "op": "release",
            "handle_id": handleID,
        ])
    }

    func truncate(path: String, size: UInt64) throws {
        _ = try sendRequest([
            "op": "truncate",
            "path": path,
            "size": size,
        ])
    }

    func unlink(path: String) throws {
        _ = try sendRequest([
            "op": "unlink",
            "path": path,
        ])
    }

    func mkdir(path: String) throws {
        _ = try sendRequest([
            "op": "mkdir",
            "path": path,
        ])
    }

    func rmdir(path: String) throws {
        _ = try sendRequest([
            "op": "rmdir",
            "path": path,
        ])
    }

    func rename(oldPath: String, newPath: String) throws {
        _ = try sendRequest([
            "op": "rename",
            "old_path": oldPath,
            "new_path": newPath,
        ])
    }

    func symlink(target: String, linkPath: String) throws {
        _ = try sendRequest([
            "op": "symlink",
            "target": target,
            "link_path": linkPath,
        ])
    }

    func getXattr(path: String, name: String) throws -> Data {
        let response = try sendRequest([
            "op": "getxattr",
            "path": path,
            "name": name,
        ])
        return try response.decodeData()
    }

    func listXattrs(path: String) throws -> [String] {
        let response = try sendRequest([
            "op": "listxattr",
            "path": path,
        ])
        let rawData = try response.decodeData()
        return rawData
            .split(separator: 0)
            .compactMap { String(data: Data($0), encoding: .utf8) }
    }

    func setXattr(path: String, name: String, value: Data?, policy: UInt32) throws {
        if policy == 3 {
            _ = try sendRequest([
                "op": "removexattr",
                "path": path,
                "name": name,
            ])
            return
        }
        _ = try sendRequest([
            "op": "setxattr",
            "path": path,
            "name": name,
            "value_b64": (value ?? Data()).base64EncodedString(),
            "flags": policy,
        ])
    }

    private func sendRequest(_ request: [String: Any]) throws -> SpiderwebRPCSuccessEnvelope {
        try launchIfNeeded()

        lock.lock()
        defer { lock.unlock() }

        guard
            let process,
            let stdinHandle = stdinPipe?.fileHandleForWriting,
            let stdoutHandle = stdoutPipe?.fileHandleForReading
        else {
            throw SpiderwebFSKitBridgeError.helperProtocolFailure("Helper process is not available")
        }

        if !process.isRunning {
            throw SpiderwebFSKitBridgeError.helperProtocolFailure("Helper process exited before request dispatch")
        }

        let payload = try JSONSerialization.data(withJSONObject: request, options: [])
        try stdinHandle.write(contentsOf: payload)
        try stdinHandle.write(contentsOf: Data([0x0A]))

        let line = try readResponseLineLocked(from: stdoutHandle)
        let header = try JSONDecoder().decode(SpiderwebRPCHeader.self, from: line)
        if header.ok {
            return try JSONDecoder().decode(SpiderwebRPCSuccessEnvelope.self, from: line)
        }

        let errorEnvelope = try JSONDecoder().decode(SpiderwebRPCErrorEnvelope.self, from: line)
        throw makeRPCError(code: errorEnvelope.code, message: errorEnvelope.message)
    }

    private func readResponseLineLocked(from stdoutHandle: FileHandle) throws -> Data {
        var line = Data()
        while true {
            guard let chunk = try stdoutHandle.read(upToCount: 1), !chunk.isEmpty else {
                throw SpiderwebFSKitBridgeError.helperProtocolFailure("Helper process closed stdout")
            }
            if chunk[chunk.startIndex] == 0x0A {
                return line
            }
            line.append(chunk)
        }
    }

    private func makeRPCError(code: String, message: String) -> NSError {
        let posixCode: Int32 = switch code {
        case "enoent":
            ENOENT
        case "eacces":
            EACCES
        case "enotdir":
            ENOTDIR
        case "eisdir":
            EISDIR
        case "eexist":
            EEXIST
        case "enodata":
            ENODATA
        case "enospc":
            ENOSPC
        case "erange":
            ERANGE
        case "eagain":
            EAGAIN
        case "exdev":
            EXDEV
        case "erofs":
            EROFS
        case "enosys":
            ENOSYS
        case "einval":
            EINVAL
        default:
            EIO
        }
        return NSError(
            domain: NSPOSIXErrorDomain,
            code: Int(posixCode),
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }
}
