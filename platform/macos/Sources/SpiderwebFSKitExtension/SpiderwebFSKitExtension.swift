import Darwin
import ExtensionFoundation
import Foundation
import FSKit

@available(macOS 15.4, *)
@main
struct SpiderwebFSKitExtension: UnaryFileSystemExtension {
    let fileSystem = SpiderwebUnaryFileSystem()
}

@available(macOS 15.4, *)
final class SpiderwebUnaryFileSystem: FSUnaryFileSystem, FSUnaryFileSystemOperations {
    private let runtime = SpiderwebFSKitRuntime()

    func probeResource(resource: FSResource, replyHandler: @escaping (FSProbeResult?, (any Error)?) -> Void) {
        do {
            _ = try runtime.ensureBridge(for: resource)
            replyHandler(.usableButLimited, nil)
        } catch {
            replyHandler(nil, error)
        }
    }

    func loadResource(resource: FSResource, options: FSTaskOptions, replyHandler: @escaping (FSVolume?, (any Error)?) -> Void) {
        do {
            let volume = try SpiderwebFSKitVolume(runtime: runtime, volumeName: runtime.currentVolumeName(resource: resource))
            replyHandler(volume, nil)
        } catch {
            replyHandler(nil, error)
        }
    }

    func unloadResource(resource: FSResource, options: FSTaskOptions, replyHandler reply: @escaping ((any Error)?) -> Void) {
        runtime.shutdown()
        reply(nil)
    }

    func didFinishLoading() {
        NSLog("SpiderwebFSKit extension loaded.")
    }
}

@available(macOS 15.4, *)
final class SpiderwebFSKitRuntime {
    private let fileManager = FileManager.default
    private let lock = NSLock()
    private var activeRequest: SpiderwebMountRequest?
    private var activeBridge: SpiderwebFSHelperBridge?
    private var activeConfigURL: URL?

    func ensureBridge(for resource: FSResource? = nil) throws -> SpiderwebFSHelperBridge {
        lock.lock()
        defer { lock.unlock() }

        if let activeBridge {
            try activeBridge.launchIfNeeded()
            try activeBridge.requireMountedRPCBridge()
            return activeBridge
        }

        let request = try resolveRequest(resource: resource)
        let configURL = try stageLaunchConfig(for: request)
        let helperURL = try bundledHelperExecutableURL()
        let bridge = SpiderwebFSHelperBridge(helperExecutableURL: helperURL, launchConfigURL: configURL)
        try bridge.launchIfNeeded()
        try bridge.requireMountedRPCBridge()

        activeRequest = request
        activeConfigURL = configURL
        activeBridge = bridge
        return bridge
    }

    func currentRequest(resource: FSResource? = nil) throws -> SpiderwebMountRequest {
        lock.lock()
        defer { lock.unlock() }

        if let activeRequest {
            return activeRequest
        }
        let request = try resolveRequest(resource: resource)
        activeRequest = request
        return request
    }

    func currentVolumeName(resource: FSResource? = nil) throws -> String {
        let request = try currentRequest(resource: resource)
        let trimmed = request.mountpoint.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let base = URL(fileURLWithPath: "/" + trimmed).lastPathComponent
        return base.isEmpty ? "Spiderweb" : base
    }

    func shutdown() {
        lock.lock()
        defer { lock.unlock() }

        activeBridge?.stop()
        activeBridge = nil
        activeRequest = nil
        if let activeConfigURL, fileManager.fileExists(atPath: activeConfigURL.path) {
            try? fileManager.removeItem(at: activeConfigURL)
        }
        activeConfigURL = nil
    }

    private func resolveRequest(resource: FSResource?) throws -> SpiderwebMountRequest {
        if let activeRequest {
            return activeRequest
        }
        if let resource {
            return try SpiderwebMountRequest.load(from: resource)
        }
        return try SpiderwebMountRequest.load(from: SpiderwebFSKitPaths.sharedContainerURL().appendingPathComponent(SpiderwebFSKitPaths.activeRequestFileName))
    }

    private func stageLaunchConfig(for request: SpiderwebMountRequest) throws -> URL {
        let configURL = fileManager.temporaryDirectory
            .appendingPathComponent("spiderweb-fskit-\(UUID().uuidString)", isDirectory: false)
            .appendingPathExtension("json")
        let encoded = try JSONEncoder().encode(request)
        try encoded.write(to: configURL, options: .atomic)
        return configURL
    }

    private func bundledHelperExecutableURL() throws -> URL {
        let bundleURL = Bundle.main.bundleURL
        let appContentsURL = bundleURL
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let helperURL = appContentsURL
            .appendingPathComponent("MacOS", isDirectory: true)
            .appendingPathComponent("spiderweb-fs-helper", isDirectory: false)
        guard fileManager.isExecutableFile(atPath: helperURL.path) else {
            throw SpiderwebFSKitBridgeError.helperExecutableMissing(helperURL)
        }
        return helperURL
    }
}

@available(macOS 15.4, *)
private struct SpiderwebOpenState {
    var handleID: UInt64
    var modes: FSVolume.OpenModes
    var retainCount: Int
    var writable: Bool
}

@available(macOS 15.4, *)
final class SpiderwebFSKitVolume:
    FSVolume,
    FSVolume.Operations,
    FSVolume.OpenCloseOperations,
    FSVolume.ReadWriteOperations,
    FSVolume.XattrOperations
{
    private let runtime: SpiderwebFSKitRuntime
    private let stateLock = NSLock()

    private var pathToItem: [String: SpiderwebFSKitItem] = [:]
    private var nextItemIdentifier: UInt64 = 1024
    private var openStates: [UInt64: SpiderwebOpenState] = [:]
    private var volumeStatsCache = SpiderwebRemoteStatFS(
        blockSize: 4096,
        fragmentSize: 4096,
        totalBlocks: 1024,
        freeBlocks: 512,
        availableBlocks: 512,
        totalFiles: 16384,
        freeFiles: 16000,
        availableFiles: 16000,
        maximumNameLength: 255
    )

    let supportedVolumeCapabilities: FSVolume.SupportedCapabilities = {
        let capabilities = FSVolume.SupportedCapabilities()
        capabilities.supportsPersistentObjectIDs = true
        capabilities.supportsSymbolicLinks = true
        capabilities.supportsSparseFiles = false
        capabilities.supportsHiddenFiles = true
        capabilities.supportsFastStatFS = true
        capabilities.caseFormat = .sensitive
        return capabilities
    }()

    var volumeStatistics: FSStatFSResult {
        let stats = FSStatFSResult(fileSystemTypeName: "spiderweb")
        stateLock.lock()
        let cached = volumeStatsCache
        stateLock.unlock()
        stats.blockSize = Int(cached.blockSize)
        stats.ioSize = Int(cached.fragmentSize)
        stats.totalBlocks = cached.totalBlocks
        stats.availableBlocks = cached.availableBlocks
        stats.freeBlocks = cached.freeBlocks
        stats.usedBlocks = cached.totalBlocks >= cached.freeBlocks ? cached.totalBlocks - cached.freeBlocks : 0
        stats.totalFiles = cached.totalFiles
        stats.freeFiles = cached.freeFiles
        return stats
    }

    let maximumLinkCount = 1
    let maximumNameLength = 255
    let restrictsOwnershipChanges = false
    let truncatesLongNames = false
    var xattrOperationsInhibited = false
    var isOpenCloseInhibited = false

    private let rootItem: SpiderwebFSKitItem

    init(runtime: SpiderwebFSKitRuntime, volumeName: String) throws {
        self.runtime = runtime
        let bridge = try runtime.ensureBridge()
        let rootAttr = try bridge.getattr(path: "/")
        let rootID = FSItem.Identifier.rootDirectory
        self.rootItem = SpiderwebFSKitItem(path: "/", itemIdentifier: rootID, cachedAttr: rootAttr)
        super.init(volumeID: FSVolume.Identifier(), volumeName: FSFileName(string: volumeName))
        pathToItem["/"] = rootItem
        try refreshVolumeStatistics()
    }

    func mount(options: FSTaskOptions, replyHandler reply: @escaping ((any Error)?) -> Void) {
        do {
            try refreshVolumeStatistics()
            reply(nil)
        } catch {
            reply(error)
        }
    }

    func unmount(replyHandler reply: @escaping () -> Void) {
        releaseAllOpenHandles()
        runtime.shutdown()
        reply()
    }

    func synchronize(flags: FSSyncFlags, replyHandler reply: @escaping ((any Error)?) -> Void) {
        do {
            try refreshVolumeStatistics()
            reply(nil)
        } catch {
            reply(error)
        }
    }

    func getAttributes(_ desiredAttributes: FSItem.GetAttributesRequest, of item: FSItem, replyHandler reply: @escaping (FSItem.Attributes?, (any Error)?) -> Void) {
        do {
            let bridgeItem = try requireBridgeItem(item)
            let attr = try refreshAttributes(for: bridgeItem)
            reply(makeAttributes(for: bridgeItem, attr: attr), nil)
        } catch {
            reply(nil, error)
        }
    }

    func setAttributes(_ newAttributes: FSItem.SetAttributesRequest, on item: FSItem, replyHandler reply: @escaping (FSItem.Attributes?, (any Error)?) -> Void) {
        do {
            let bridgeItem = try requireBridgeItem(item)
            if newAttributes.isValid(.size) {
                try runtime.ensureBridge().truncate(path: bridgeItem.path, size: newAttributes.size)
                newAttributes.consumedAttributes = [.size]
            } else {
                newAttributes.consumedAttributes = []
            }
            let attr = try refreshAttributes(for: bridgeItem)
            reply(makeAttributes(for: bridgeItem, attr: attr), nil)
        } catch {
            reply(nil, error)
        }
    }

    func lookupItem(named name: FSFileName, inDirectory directory: FSItem, replyHandler reply: @escaping (FSItem?, FSFileName?, (any Error)?) -> Void) {
        do {
            let directoryItem = try requireBridgeItem(directory)
            let childPath = try append(name: name, toDirectoryPath: directoryItem.path)
            let attr = try runtime.ensureBridge().getattr(path: childPath)
            let child = itemForPath(childPath, attr: attr)
            reply(child, FSFileName(string: name.string ?? ""), nil)
        } catch {
            reply(nil, nil, error)
        }
    }

    func reclaimItem(_ item: FSItem, replyHandler reply: @escaping ((any Error)?) -> Void) {
        stateLock.lock()
        defer { stateLock.unlock() }

        guard let bridgeItem = item as? SpiderwebFSKitItem else {
            reply(nil)
            return
        }
        if bridgeItem.path != "/" {
            pathToItem.removeValue(forKey: bridgeItem.path)
            openStates.removeValue(forKey: bridgeItem.itemIdentifier.rawValue)
        }
        reply(nil)
    }

    func readSymbolicLink(_ item: FSItem, replyHandler reply: @escaping (FSFileName?, (any Error)?) -> Void) {
        reply(nil, CocoaError(.featureUnsupported))
    }

    func createItem(named name: FSFileName, type: FSItem.ItemType, inDirectory directory: FSItem, attributes newAttributes: FSItem.SetAttributesRequest, replyHandler reply: @escaping (FSItem?, FSFileName?, (any Error)?) -> Void) {
        do {
            let directoryItem = try requireBridgeItem(directory)
            let path = try append(name: name, toDirectoryPath: directoryItem.path)
            switch type {
            case .file:
                let handle = try runtime.ensureBridge().create(
                    path: path,
                    mode: normalizedCreateMode(from: newAttributes, defaultMode: 0o100644),
                    flags: UInt32(O_RDWR | O_CREAT | O_EXCL)
                )
                try runtime.ensureBridge().release(handleID: handle.handleID)
            case .directory:
                try runtime.ensureBridge().mkdir(path: path)
            default:
                throw CocoaError(.featureUnsupported)
            }
            let attr = try runtime.ensureBridge().getattr(path: path)
            let child = itemForPath(path, attr: attr)
            reply(child, FSFileName(string: name.string ?? ""), nil)
        } catch {
            reply(nil, nil, error)
        }
    }

    func createSymbolicLink(named name: FSFileName, inDirectory directory: FSItem, attributes newAttributes: FSItem.SetAttributesRequest, linkContents contents: FSFileName, replyHandler reply: @escaping (FSItem?, FSFileName?, (any Error)?) -> Void) {
        _ = newAttributes
        do {
            guard let target = contents.string else {
                throw SpiderwebFSKitBridgeError.invalidFilenameEncoding
            }
            let directoryItem = try requireBridgeItem(directory)
            let path = try append(name: name, toDirectoryPath: directoryItem.path)
            try runtime.ensureBridge().symlink(target: target, linkPath: path)
            let attr = try runtime.ensureBridge().getattr(path: path)
            let child = itemForPath(path, attr: attr)
            reply(child, FSFileName(string: name.string ?? ""), nil)
        } catch {
            reply(nil, nil, error)
        }
    }

    func createLink(to item: FSItem, named name: FSFileName, inDirectory directory: FSItem, replyHandler reply: @escaping (FSFileName?, (any Error)?) -> Void) {
        _ = item
        _ = name
        _ = directory
        reply(nil, CocoaError(.featureUnsupported))
    }

    func removeItem(_ item: FSItem, named name: FSFileName, fromDirectory directory: FSItem, replyHandler reply: @escaping ((any Error)?) -> Void) {
        _ = name
        _ = directory
        do {
            let bridgeItem = try requireBridgeItem(item)
            let attr = try currentAttributes(for: bridgeItem)
            if itemType(for: attr) == .directory {
                try runtime.ensureBridge().rmdir(path: bridgeItem.path)
            } else {
                try runtime.ensureBridge().unlink(path: bridgeItem.path)
            }
            stateLock.lock()
            pathToItem.removeValue(forKey: bridgeItem.path)
            openStates.removeValue(forKey: bridgeItem.itemIdentifier.rawValue)
            stateLock.unlock()
            reply(nil)
        } catch {
            reply(error)
        }
    }

    func renameItem(_ item: FSItem, inDirectory sourceDirectory: FSItem, named sourceName: FSFileName, to destinationName: FSFileName, inDirectory destinationDirectory: FSItem, overItem: FSItem?, replyHandler reply: @escaping (FSFileName?, (any Error)?) -> Void) {
        _ = sourceDirectory
        _ = sourceName
        _ = overItem
        do {
            let bridgeItem = try requireBridgeItem(item)
            let destinationDirectoryItem = try requireBridgeItem(destinationDirectory)
            let destinationPath = try append(name: destinationName, toDirectoryPath: destinationDirectoryItem.path)
            try runtime.ensureBridge().rename(oldPath: bridgeItem.path, newPath: destinationPath)
            stateLock.lock()
            pathToItem.removeValue(forKey: bridgeItem.path)
            bridgeItem.path = destinationPath
            pathToItem[destinationPath] = bridgeItem
            stateLock.unlock()
            let attr = try runtime.ensureBridge().getattr(path: destinationPath)
            bridgeItem.cachedAttr = attr
            reply(FSFileName(string: destinationName.string ?? ""), nil)
        } catch {
            reply(nil, error)
        }
    }

    func enumerateDirectory(_ directory: FSItem, startingAt cookie: FSDirectoryCookie, verifier: FSDirectoryVerifier, attributes: FSItem.GetAttributesRequest?, packer: FSDirectoryEntryPacker, replyHandler reply: @escaping (FSDirectoryVerifier, (any Error)?) -> Void) {
        _ = verifier
        do {
            let directoryItem = try requireBridgeItem(directory)
            let listing = try runtime.ensureBridge().readdir(
                path: directoryItem.path,
                cookie: UInt64(cookie.rawValue),
                maxEntries: 256
            )
            for entry in listing.entries {
                let childPath = join(directoryPath: directoryItem.path, childName: entry.name)
                let child = itemForPath(childPath, attr: entry.attr)
                let itemAttributes = entry.attr.map { makeAttributes(for: child, attr: $0) }
                let packed = packer.packEntry(
                    name: FSFileName(string: entry.name),
                    itemType: itemType(for: try currentAttributes(for: child)),
                    itemID: child.itemIdentifier,
                    nextCookie: FSDirectoryCookie(rawValue: listing.nextCookie),
                    attributes: attributes == nil ? nil : itemAttributes
                )
                if !packed {
                    break
                }
            }
            reply(FSDirectoryVerifier(rawValue: listing.directoryGeneration), nil)
        } catch {
            reply(verifier, error)
        }
    }

    func activate(options: FSTaskOptions, replyHandler reply: @escaping (FSItem?, (any Error)?) -> Void) {
        _ = options
        do {
            _ = try runtime.ensureBridge()
            let attr = try refreshAttributes(for: rootItem)
            rootItem.cachedAttr = attr
            reply(rootItem, nil)
        } catch {
            reply(nil, error)
        }
    }

    func deactivate(options: FSDeactivateOptions, replyHandler reply: @escaping ((any Error)?) -> Void) {
        _ = options
        releaseAllOpenHandles()
        runtime.shutdown()
        reply(nil)
    }

    func openItem(_ item: FSItem, modes: FSVolume.OpenModes, replyHandler reply: @escaping ((any Error)?) -> Void) {
        do {
            let bridgeItem = try requireBridgeItem(item)
            _ = try ensureHandle(for: bridgeItem, modes: modes)
            reply(nil)
        } catch {
            reply(error)
        }
    }

    func closeItem(_ item: FSItem, modes: FSVolume.OpenModes, replyHandler reply: @escaping ((any Error)?) -> Void) {
        _ = modes
        do {
            let bridgeItem = try requireBridgeItem(item)
            try releaseHandle(for: bridgeItem)
            reply(nil)
        } catch {
            reply(error)
        }
    }

    func read(from item: FSItem, at offset: off_t, length: Int, into buffer: FSMutableFileDataBuffer, replyHandler reply: @escaping (Int, (any Error)?) -> Void) {
        do {
            let bridgeItem = try requireBridgeItem(item)
            let openState = try ensureHandle(for: bridgeItem, modes: [.read])
            let data = try runtime.ensureBridge().read(
                handleID: openState.handleID,
                offset: UInt64(offset),
                length: UInt32(clamping: length)
            )
            try buffer.withUnsafeMutableBytes { rawBuffer in
                guard data.count <= rawBuffer.count else {
                    throw SpiderwebFSKitBridgeError.helperProtocolFailure("Read buffer too small for helper response")
                }
                rawBuffer.copyBytes(from: data)
            }
            reply(data.count, nil)
        } catch {
            reply(0, error)
        }
    }

    func write(contents: Data, to item: FSItem, at offset: off_t, replyHandler reply: @escaping (Int, (any Error)?) -> Void) {
        do {
            let bridgeItem = try requireBridgeItem(item)
            let openState = try ensureHandle(for: bridgeItem, modes: [.read, .write])
            let written = try runtime.ensureBridge().write(
                handleID: openState.handleID,
                offset: UInt64(offset),
                contents: contents
            )
            let attr = try refreshAttributes(for: bridgeItem)
            bridgeItem.cachedAttr = attr
            reply(Int(written), nil)
        } catch {
            reply(0, error)
        }
    }

    func getXattr(named name: FSFileName, of item: FSItem, replyHandler reply: @escaping (Data?, (any Error)?) -> Void) {
        do {
            let bridgeItem = try requireBridgeItem(item)
            let value = try runtime.ensureBridge().getXattr(
                path: bridgeItem.path,
                name: try fsNameString(name)
            )
            reply(value, nil)
        } catch {
            reply(nil, error)
        }
    }

    func setXattr(named name: FSFileName, to value: Data?, on item: FSItem, policy: FSVolume.SetXattrPolicy, replyHandler reply: @escaping ((any Error)?) -> Void) {
        do {
            let bridgeItem = try requireBridgeItem(item)
            try runtime.ensureBridge().setXattr(
                path: bridgeItem.path,
                name: try fsNameString(name),
                value: value,
                policy: UInt32(policy.rawValue)
            )
            reply(nil)
        } catch {
            reply(error)
        }
    }

    func listXattrs(of item: FSItem, replyHandler reply: @escaping ([FSFileName]?, (any Error)?) -> Void) {
        do {
            let bridgeItem = try requireBridgeItem(item)
            let names = try runtime.ensureBridge().listXattrs(path: bridgeItem.path)
            reply(names.map(FSFileName.init(string:)), nil)
        } catch {
            reply(nil, error)
        }
    }

    private func requireBridgeItem(_ item: FSItem) throws -> SpiderwebFSKitItem {
        guard let bridgeItem = item as? SpiderwebFSKitItem else {
            throw SpiderwebFSKitBridgeError.helperProtocolFailure("Received unexpected FSItem subclass")
        }
        return bridgeItem
    }

    private func refreshVolumeStatistics() throws {
        let stats = try runtime.ensureBridge().statfs(path: "/")
        stateLock.lock()
        volumeStatsCache = stats
        stateLock.unlock()
    }

    private func currentAttributes(for item: SpiderwebFSKitItem) throws -> SpiderwebRemoteAttr {
        if let cachedAttr = item.cachedAttr {
            return cachedAttr
        }
        return try refreshAttributes(for: item)
    }

    private func refreshAttributes(for item: SpiderwebFSKitItem) throws -> SpiderwebRemoteAttr {
        let attr = try runtime.ensureBridge().getattr(path: item.path)
        item.cachedAttr = attr
        return attr
    }

    private func itemForPath(_ path: String, attr: SpiderwebRemoteAttr?) -> SpiderwebFSKitItem {
        let normalizedPath = normalize(path: path)
        stateLock.lock()
        defer { stateLock.unlock() }

        if let existing = pathToItem[normalizedPath] {
            if let attr {
                existing.cachedAttr = attr
            }
            return existing
        }

        let identifier: FSItem.Identifier
        if normalizedPath == "/" {
            identifier = .rootDirectory
        } else {
            let rawValue = nextItemIdentifier
            nextItemIdentifier += 1
            identifier = FSItem.Identifier(rawValue: rawValue) ?? .invalid
        }

        let item = SpiderwebFSKitItem(path: normalizedPath, itemIdentifier: identifier, cachedAttr: attr)
        pathToItem[normalizedPath] = item
        return item
    }

    private func ensureHandle(for item: SpiderwebFSKitItem, modes: FSVolume.OpenModes) throws -> SpiderwebOpenState {
        stateLock.lock()
        if var existing = openStates[item.itemIdentifier.rawValue] {
            if handle(existing, satisfies: modes) {
                existing.retainCount += 1
                existing.modes.formUnion(modes)
                openStates[item.itemIdentifier.rawValue] = existing
                stateLock.unlock()
                return existing
            }
        }
        stateLock.unlock()

        let response = try runtime.ensureBridge().open(path: item.path, flags: openFlags(for: modes))
        let state = SpiderwebOpenState(handleID: response.handleID, modes: modes, retainCount: 1, writable: response.writable)

        stateLock.lock()
        openStates[item.itemIdentifier.rawValue] = state
        stateLock.unlock()
        return state
    }

    private func releaseHandle(for item: SpiderwebFSKitItem) throws {
        stateLock.lock()
        guard var existing = openStates[item.itemIdentifier.rawValue] else {
            stateLock.unlock()
            return
        }
        existing.retainCount -= 1
        if existing.retainCount > 0 {
            openStates[item.itemIdentifier.rawValue] = existing
            stateLock.unlock()
            return
        }
        openStates.removeValue(forKey: item.itemIdentifier.rawValue)
        stateLock.unlock()

        try runtime.ensureBridge().release(handleID: existing.handleID)
    }

    private func releaseAllOpenHandles() {
        stateLock.lock()
        let handles = Array(openStates.values)
        openStates.removeAll()
        stateLock.unlock()

        for handle in handles {
            try? runtime.ensureBridge().release(handleID: handle.handleID)
        }
    }

    private func handle(_ state: SpiderwebOpenState, satisfies requestedModes: FSVolume.OpenModes) -> Bool {
        if requestedModes.contains(.write) {
            return state.writable
        }
        return true
    }

    private func openFlags(for modes: FSVolume.OpenModes) -> UInt32 {
        if modes.contains(.write) && modes.contains(.read) {
            return UInt32(O_RDWR)
        }
        if modes.contains(.write) {
            return UInt32(O_WRONLY)
        }
        return UInt32(O_RDONLY)
    }

    private func makeAttributes(for item: SpiderwebFSKitItem, attr: SpiderwebRemoteAttr) -> FSItem.Attributes {
        let attributes = FSItem.Attributes()
        attributes.type = itemType(for: attr)
        attributes.mode = attr.mode
        attributes.linkCount = attr.linkCount
        attributes.uid = attr.uid
        attributes.gid = attr.gid
        attributes.size = attr.size
        attributes.allocSize = attr.size
        attributes.fileID = item.itemIdentifier
        attributes.parentID = parentIdentifier(for: item.path)
        attributes.accessTime = makeTimespec(fromNanoseconds: attr.accessTimeNS)
        attributes.modifyTime = makeTimespec(fromNanoseconds: attr.modifyTimeNS)
        attributes.changeTime = makeTimespec(fromNanoseconds: attr.changeTimeNS)
        attributes.birthTime = makeTimespec(fromNanoseconds: attr.changeTimeNS)
        attributes.backupTime = makeTimespec(fromNanoseconds: attr.changeTimeNS)
        attributes.addedTime = makeTimespec(fromNanoseconds: attr.changeTimeNS)
        return attributes
    }

    private func itemType(for attr: SpiderwebRemoteAttr) -> FSItem.ItemType {
        switch attr.kindCode {
        case 2:
            return .directory
        case 3:
            return .symlink
        case 1:
            return .file
        default:
            let fileTypeBits = attr.mode & UInt32(S_IFMT)
            switch fileTypeBits {
            case UInt32(S_IFDIR):
                return .directory
            case UInt32(S_IFLNK):
                return .symlink
            default:
                return .file
            }
        }
    }

    private func parentIdentifier(for path: String) -> FSItem.Identifier {
        if path == "/" {
            return .parentOfRoot
        }
        let parentPath = parentPath(of: path)
        stateLock.lock()
        defer { stateLock.unlock() }
        return pathToItem[parentPath]?.itemIdentifier ?? .rootDirectory
    }

    private func append(name: FSFileName, toDirectoryPath directoryPath: String) throws -> String {
        let component = try fsNameString(name)
        if component == "." {
            return directoryPath
        }
        if component == ".." {
            return parentPath(of: directoryPath)
        }
        return join(directoryPath: directoryPath, childName: component)
    }

    private func fsNameString(_ name: FSFileName) throws -> String {
        if let string = name.string, !string.isEmpty {
            return string
        }
        throw SpiderwebFSKitBridgeError.invalidFilenameEncoding
    }

    private func normalize(path: String) -> String {
        guard !path.isEmpty, path != "/" else {
            return "/"
        }
        var normalized = path
        if !normalized.hasPrefix("/") {
            normalized = "/" + normalized
        }
        while normalized.count > 1, normalized.hasSuffix("/") {
            normalized.removeLast()
        }
        return normalized
    }

    private func join(directoryPath: String, childName: String) -> String {
        let base = normalize(path: directoryPath)
        if base == "/" {
            return "/" + childName
        }
        return base + "/" + childName
    }

    private func parentPath(of path: String) -> String {
        let normalized = normalize(path: path)
        if normalized == "/" {
            return "/"
        }
        let parent = URL(fileURLWithPath: normalized).deletingLastPathComponent().path
        return parent.isEmpty ? "/" : parent
    }

    private func makeTimespec(fromNanoseconds value: Int64) -> timespec {
        let seconds = value / 1_000_000_000
        var nanoseconds = value % 1_000_000_000
        if nanoseconds < 0 {
            nanoseconds += 1_000_000_000
        }
        return timespec(tv_sec: Int(seconds), tv_nsec: Int(nanoseconds))
    }

    private func normalizedCreateMode(from attributes: FSItem.SetAttributesRequest, defaultMode: UInt32) -> UInt32 {
        if attributes.isValid(.mode) && attributes.mode != 0 {
            return attributes.mode
        }
        return defaultMode
    }
}

@available(macOS 15.4, *)
final class SpiderwebFSKitItem: FSItem {
    var path: String
    let itemIdentifier: FSItem.Identifier
    var cachedAttr: SpiderwebRemoteAttr?

    init(path: String, itemIdentifier: FSItem.Identifier, cachedAttr: SpiderwebRemoteAttr?) {
        self.path = path
        self.itemIdentifier = itemIdentifier
        self.cachedAttr = cachedAttr
        super.init()
    }
}
