import Darwin
import Foundation

@main
enum SpiderwebFSKitAppMain {
    static func main() {
        let controller = SpiderwebFSKitAppController(bundle: .main)
        do {
            let keepRunning = try controller.bootstrap(arguments: CommandLine.arguments)
            if keepRunning {
                RunLoop.main.run()
            }
        } catch {
            fputs("SpiderwebFSKit failed to start: \(error.localizedDescription)\n", stderr)
            Darwin.exit(1)
        }
    }
}
