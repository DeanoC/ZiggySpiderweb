import Foundation

final class SpiderwebFSKitAppController {
    private let bundle: Bundle
    private let stateStore: SpiderwebFSKitStateStore

    init(bundle: Bundle, stateStore: SpiderwebFSKitStateStore = SpiderwebFSKitStateStore()) {
        self.bundle = bundle
        self.stateStore = stateStore
    }

    func bootstrap(arguments: [String]) throws -> Bool {
        guard let requestURL = parseRequestURL(arguments: arguments) else {
            NSLog("SpiderwebFSKit running without a mount request; waiting for extension startup.")
            return true
        }

        let activeRequestURL = try stateStore.activateRequest(from: requestURL)
        let request = try SpiderwebMountRequest.load(from: activeRequestURL)
        _ = try stateStore.installHelper(from: bundledHelperExecutableURL())

        NSLog(
            "SpiderwebFSKit staged mount request for %@ with %ld endpoint(s).",
            request.mountpoint,
            request.endpoints.count
        )
        return false
    }

    private func parseRequestURL(arguments: [String]) -> URL? {
        guard let commandIndex = arguments.firstIndex(of: "mount-request") else {
            return nil
        }
        let valueIndex = arguments.index(after: commandIndex)
        guard valueIndex < arguments.endIndex else {
            return nil
        }
        return URL(fileURLWithPath: arguments[valueIndex])
    }

    private func bundledHelperExecutableURL() throws -> URL {
        let url = bundle.bundleURL
            .appendingPathComponent("Contents", isDirectory: true)
            .appendingPathComponent("MacOS", isDirectory: true)
            .appendingPathComponent("spiderweb-fs-helper", isDirectory: false)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw SpiderwebFSKitBridgeError.helperExecutableMissing(url)
        }
        return url
    }
}
