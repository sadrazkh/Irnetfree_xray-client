import Foundation
import ServiceManagement

@main struct NativeBridge {
    static func main() {
        let action = CommandLine.arguments.dropFirst().first ?? "status"
        let service = SMAppService.daemon(plistName: nativePlistName)
        func registration() -> String {
            switch service.status {
            case .enabled: return "enabled"
            case .requiresApproval: return "requiresApproval"
            case .notRegistered: return "notRegistered"
            case .notFound: return "notFound"
            @unknown default: return "unknown"
            }
        }
        func finish(_ value: [String: Any]) -> Never {
            FileHandle.standardOutput.write(encoded(value)); FileHandle.standardOutput.write(Data([10]))
            exit(value["ok"] as? Bool == true ? 0 : 1)
        }
        do {
            if action == "settings" {
                SMAppService.openSystemSettingsLoginItems()
                finish(["ok": true, "status": registration()])
            }
            if action == "register" {
                try service.register()
                finish(["ok": true, "status": registration()])
            }
            if action == "unregister" && service.status != .enabled {
                try service.unregister()
                finish(["ok": true, "status": registration()])
            }
            guard ["status", "start", "stop", "heartbeat", "unregister"].contains(action) else { throw NativeFailure("Unknown action") }
            if service.status != .enabled {
                finish(["ok": action == "status", "status": registration(), "active": false, "error": "Enable IRNetFree in System Settings > General > Login Items"])
            }
            var request: [String: Any] = [:]
            if action != "status" {
                let input = FileHandle.standardInput.readDataToEndOfFile()
                guard input.count <= 65536 else { throw NativeFailure("Request too large") }
                if !input.isEmpty {
                    guard let object = try JSONSerialization.jsonObject(with: input) as? [String: Any] else { throw NativeFailure("Invalid JSON") }
                    request = object
                }
            }
            // A direct CLI unregister must restore the tunnel too, even when
            // called outside Electron. Never unload a service after failed cleanup.
            request["action"] = action == "unregister" ? "stop" : action
            let connection = NSXPCConnection(machServiceName: nativeServiceName, options: .privileged)
            connection.remoteObjectInterface = NSXPCInterface(with: TunnelRPC.self)
            connection.resume()
            let semaphore = DispatchSemaphore(value: 0)
            let lock = NSLock()
            var result: [String: Any] = ["ok": false, "error": "Native service timed out"]
            let proxy = connection.remoteObjectProxyWithErrorHandler { error in
                lock.lock(); result = ["ok": false, "error": error.localizedDescription]; lock.unlock(); semaphore.signal()
            } as! TunnelRPC
            proxy.request(encoded(request)) { data in
                lock.lock(); result = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? ["ok": false, "error": "Invalid service response"]; lock.unlock(); semaphore.signal()
            }
            _ = semaphore.wait(timeout: .now() + 90)
            connection.invalidate()
            lock.lock(); var output = result; lock.unlock()
            if action == "unregister" && output["ok"] as? Bool == true {
                guard output["active"] as? Bool == false,
                      output["recoveryPending"] as? Bool == false else { throw NativeFailure("Restore the tunnel before disabling the service") }
                try service.unregister()
            }
            output["status"] = registration()
            finish(output)
        } catch { finish(["ok": false, "status": registration(), "error": String(describing: error)]) }
    }
}

