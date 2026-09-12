import Foundation
import CryptoKit
import Darwin

@_silgen_name("proc_pidpath") private func processPath(_ pid: Int32, _ buffer: UnsafeMutableRawPointer, _ size: UInt32) -> Int32
@_silgen_name("proc_listallpids") private func processList(_ buffer: UnsafeMutableRawPointer?, _ size: Int32) -> Int32

private struct Journal: Codable {
    var owner: UInt32
    var sessionId: String
    var pid: Int32?
    var device: String?
    var originalDNS: [String: [String]]
    var changed: [String]
    var error: String?
}

private final class TunnelState {
    let queue = DispatchQueue(label: "com.irnetfree.client.tunnel.state")
    let root = URL(fileURLWithPath: "/Library/Application Support/IRNetFreeNative", isDirectory: true)
    var journal: Journal?
    var child: Process?
    var deadline = Date.distantPast
    var ready = false
    var timer: DispatchSourceTimer?
    var startupError: String?
    var storageReady = false
    var targetDNS: [String] = []
    var dnsServices: [String] = []
    var dnsServiceIndex = 0
    var nextDNSEnumeration = Date.distantPast
    var dnsRepairError: String?
    var journalURL: URL { root.appendingPathComponent("session.json") }
    var binaryURL: URL { root.appendingPathComponent("sing-box") }

    init() {
        do {
            var info = stat()
            if lstat(root.path, &info) == 0 {
                guard (info.st_mode & S_IFMT) == S_IFDIR, info.st_uid == 0, (info.st_mode & 0o077) == 0 else { throw NativeFailure("Unsafe native state directory") }
            } else {
                try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            }
            storageReady = true
            if FileManager.default.fileExists(atPath: journalURL.path) {
                journal = try JSONDecoder().decode(Journal.self, from: Data(contentsOf: journalURL))
                try cleanup()
            }
        } catch { startupError = String(describing: error) }
        let source = DispatchSource.makeTimerSource(queue: queue)
        source.schedule(deadline: .now() + 2, repeating: 2)
        source.setEventHandler { [weak self] in
            guard let self = self, self.journal != nil else { return }
            if !self.ready || Date() > self.deadline || !self.alive() {
                do { try self.cleanup() } catch { self.recordError(error) }
            } else if self.deadline.timeIntervalSinceNow > 5 {
                // Keep each pass short so queued XPC heartbeats/stop requests
                // are not held behind a full scan of every network service.
                do { try self.refreshDNS() } catch { self.dnsRepairError = String(describing: error) }
            }
        }
        source.resume(); timer = source
    }

    func save() throws {
        guard let value = journal else { return }
        try JSONEncoder().encode(value).write(to: journalURL, options: .atomic)
        guard chmod(journalURL.path, 0o600) == 0 else { throw NativeFailure("Cannot protect session journal") }
    }

    func recordError(_ error: Error) {
        journal?.error = String(describing: error)
        try? save()
    }

    // Only fixed OS tools are called. Output goes to a private file to avoid pipe
    // deadlocks; the size and wall time are bounded and no command uses a shell.
    func run(_ path: String, _ args: [String], timeout: TimeInterval = 8) throws -> String {
        let output = root.appendingPathComponent("command-\(UUID().uuidString)")
        guard FileManager.default.createFile(atPath: output.path, contents: nil, attributes: [.posixPermissions: 0o600]) else { throw NativeFailure("Cannot create command output") }
        let handle = try FileHandle(forWritingTo: output)
        defer { try? handle.close(); try? FileManager.default.removeItem(at: output) }
        let process = Process(); process.executableURL = URL(fileURLWithPath: path); process.arguments = args
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"]
        process.standardOutput = handle; process.standardError = handle
        try process.run()
        let limit = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < limit {
            let size = (try? FileManager.default.attributesOfItem(atPath: output.path)[.size] as? NSNumber)?.intValue ?? 0
            if size > 262144 { break }
            Thread.sleep(forTimeInterval: 0.05)
        }
        if process.isRunning { process.terminate(); Thread.sleep(forTimeInterval: 0.1); if process.isRunning { kill(process.processIdentifier, SIGKILL) }; throw NativeFailure("System command timed out") }
        guard process.terminationStatus == 0 else { throw NativeFailure("System command failed: \(URL(fileURLWithPath: path).lastPathComponent)") }
        return String(decoding: try Data(contentsOf: output).prefix(262144), as: UTF8.self)
    }

    func alive() -> Bool {
        guard let pid = journal?.pid else { return false }
        if let process = child { return process.isRunning && process.processIdentifier == pid }
        return ownsProcess(pid)
    }

    func ownsProcess(_ pid: Int32) -> Bool {
        var buffer = [CChar](repeating: 0, count: 4096)
        let count = buffer.withUnsafeMutableBytes { processPath(pid, $0.baseAddress!, UInt32($0.count)) }
        return count > 0 && String(cString: buffer) == binaryURL.path
    }

    func ownedProcesses() throws -> [Int32] {
        // Recover the process even if the daemon died between Process.run and
        // persisting its PID. Only root can execute this private binary.
        let count = processList(nil, 0)
        guard count >= 0, count < 65536 else { throw NativeFailure("Cannot enumerate tunnel processes") }
        var pids = [Int32](repeating: 0, count: max(Int(count) + 1024, 4096))
        let found = pids.withUnsafeMutableBytes { processList($0.baseAddress, Int32($0.count)) }
        guard found >= 0, Int(found) < pids.count else { throw NativeFailure("Cannot enumerate tunnel processes") }
        return pids.prefix(Int(found)).filter { $0 > 1 && ownsProcess($0) }
    }

    func cleanup() throws {
        ready = false
        targetDNS = []; dnsServices = []; dnsServiceIndex = 0
        nextDNSEnumeration = .distantPast; dnsRepairError = nil
        guard storageReady else { throw NativeFailure(startupError ?? "Native state directory is unavailable") }
        guard journal != nil || startupError == nil else { throw NativeFailure(startupError ?? "Native recovery journal cannot be read") }
        for pid in try ownedProcesses() {
            guard ownsProcess(pid) else { continue }
            kill(pid, SIGTERM)
            let until = Date().addingTimeInterval(3)
            while ownsProcess(pid) && Date() < until { Thread.sleep(forTimeInterval: 0.1) }
            if ownsProcess(pid) { kill(pid, SIGKILL) }
            let killed = Date().addingTimeInterval(2)
            while ownsProcess(pid) && Date() < killed { Thread.sleep(forTimeInterval: 0.05) }
            guard !ownsProcess(pid) else { throw NativeFailure("Tunnel process did not stop; recovery journal retained") }
        }
        child = nil
        // Journal each successful restore; retry only entries still outstanding.
        for service in journal?.changed ?? [] {
            let dns = journal?.originalDNS[service] ?? []
            _ = try run("/usr/sbin/networksetup", ["-setdnsservers", service] + (dns.isEmpty ? ["Empty"] : dns))
            journal?.changed.removeAll { $0 == service }; try save()
        }
        if journal != nil { try FileManager.default.removeItem(at: journalURL) }
        journal = nil
        startupError = nil
    }

    func refreshDNS() throws {
        guard ready, journal != nil, !targetDNS.isEmpty else { return }
        if Date() >= nextDNSEnumeration {
            // Enumeration has its own tick. A failed OS command is retried on
            // the next scheduled scan, not on every two-second heartbeat tick.
            nextDNSEnumeration = Date().addingTimeInterval(30)
            dnsServices = try enabledNetworkServices(run("/usr/sbin/networksetup", ["-listallnetworkservices"], timeout: 2))
            dnsServiceIndex = dnsServices.isEmpty ? 0 : dnsServiceIndex % dnsServices.count
            return
        }
        guard !dnsServices.isEmpty else { return }
        let service = dnsServices[dnsServiceIndex]
        dnsServiceIndex = (dnsServiceIndex + 1) % dnsServices.count
        let observed = try networkServiceDNS(run("/usr/sbin/networksetup", ["-getdnsservers", service], timeout: 2))
        let plan = DNSRepairPlan(original: journal?.originalDNS[service], observed: observed, desired: targetDNS)
        if plan.needsWrite {
            journal?.originalDNS[service] = plan.original
            if journal?.changed.contains(service) != true { journal?.changed.append(service) }
            // Persist both a new service's original DNS and mutation intent
            // before networksetup. Failed writes remain recoverable at stop.
            try save()
            _ = try run("/usr/sbin/networksetup", ["-setdnsservers", service] + targetDNS, timeout: 2)
        }
        dnsRepairError = nil
    }

    func status() -> [String: Any] {
        var value: [String: Any] = ["ok": true, "active": ready && alive(), "recoveryPending": journal != nil && !ready]
        if let entry = journal {
            value["sessionId"] = entry.sessionId
            if let device = entry.device { value["device"] = device }
            if let pid = entry.pid { value["pid"] = pid }
            if let error = entry.error { value["error"] = error }
        }
        if let error = startupError { value["error"] = error }
        if let error = dnsRepairError { value["dnsProtectionError"] = error }
        return value
    }

    func start(_ request: [String: Any], owner: UInt32) throws {
        let options = try StartOptions(request)
        guard startupError == nil, journal == nil else { throw NativeFailure("An existing session requires stop/recovery before starting") }
        // Pin actual bytes and execute only the root-owned copy, removing the
        // hash-check/exec race against an application writable by its user.
        let executable = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
        let bundled = executable.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Resources/native/sing-box")
        var binaryInfo = stat()
        guard lstat(bundled.path, &binaryInfo) == 0, (binaryInfo.st_mode & S_IFMT) == S_IFREG, binaryInfo.st_size < 200_000_000 else { throw NativeFailure("Bundled sing-box is missing or unsafe") }
        let data = try Data(contentsOf: bundled)
        let hash = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        guard hash == NativeBuild.singboxSHA256 else { throw NativeFailure("Bundled sing-box integrity check failed") }
        try data.write(to: binaryURL, options: .atomic)
        guard chmod(binaryURL.path, 0o700) == 0 else { throw NativeFailure("Cannot protect tunnel executable") }
        let configURL = root.appendingPathComponent("sing-box.json")
        try encoded(options.config).write(to: configURL, options: .atomic)
        guard chmod(configURL.path, 0o600) == 0 else { throw NativeFailure("Cannot protect tunnel config") }
        let before = try run("/sbin/ifconfig", ["-a"])
        guard !before.contains("inet 172.19.0.1 ") else { throw NativeFailure("Tunnel address is already in use") }
        let services = try enabledNetworkServices(run("/usr/sbin/networksetup", ["-listallnetworkservices"]))
        var original: [String: [String]] = [:]
        for service in services {
            original[service] = try networkServiceDNS(run("/usr/sbin/networksetup", ["-getdnsservers", service]))
        }
        journal = Journal(owner: owner, sessionId: UUID().uuidString, originalDNS: original, changed: [])
        try save()
        do {
            let process = Process(); process.executableURL = binaryURL; process.arguments = ["run", "-c", configURL.path]
            process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": root.path]
            process.standardInput = FileHandle.nullDevice; process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
            try process.run(); child = process; journal?.pid = process.processIdentifier; try save()
            let until = Date().addingTimeInterval(12)
            while Date() < until && alive() {
                let interfaces = try run("/sbin/ifconfig", ["-a"])
                var current = ""
                for line in interfaces.split(separator: "\n") {
                    if !line.hasPrefix("\t") && !line.hasPrefix(" ") { current = String(line.split(separator: ":").first ?? "") }
                    if current.hasPrefix("utun") && line.contains("inet 172.19.0.1 ") { journal?.device = current }
                }
                if journal?.device != nil { break }
                Thread.sleep(forTimeInterval: 0.2)
            }
            guard alive(), journal?.device != nil else { throw NativeFailure("Tunnel interface did not become ready") }
            let route = try run("/sbin/route", ["-n", "get", "172.19.0.2"])
            guard let device = journal?.device,
                  route.split(separator: "\n").contains(where: { $0.trimmingCharacters(in: .whitespaces) == "interface: \(device)" }) else { throw NativeFailure("Tunnel route did not become ready") }
            for service in services {
                // Write intent BEFORE mutation: a crash in networksetup can be recovered.
                journal?.changed.append(service); try save()
                _ = try run("/usr/sbin/networksetup", ["-setdnsservers", service] + options.dnsServers)
            }
            guard alive() else { throw NativeFailure("Tunnel exited while setting DNS") }
            targetDNS = options.dnsServers; dnsServices = services; dnsServiceIndex = 0
            nextDNSEnumeration = Date().addingTimeInterval(30); dnsRepairError = nil
            ready = true; deadline = Date().addingTimeInterval(20); try save()
        } catch {
            let failure = error
            do { try cleanup() } catch { recordError(error) }
            throw failure
        }
    }

    func request(_ data: Data, uid: UInt32) -> Data {
        do {
            guard data.count <= 65536, let request = try JSONSerialization.jsonObject(with: data) as? [String: Any], let action = request["action"] as? String else { throw NativeFailure("Invalid request") }
            if action == "status" { return encoded(status()) }
            var console = stat()
            guard stat("/dev/console", &console) == 0, uid != 0, console.st_uid == uid else { throw NativeFailure("Only the active console user may manage the tunnel") }
            if let entry = journal { guard entry.owner == uid else { throw NativeFailure("Tunnel belongs to another user") } }
            switch action {
            case "start": try start(request, owner: uid)
            case "stop":
                if let id = request["sessionId"] as? String, let entry = journal, id != entry.sessionId { throw NativeFailure("Stale tunnel session") }
                try cleanup()
            case "heartbeat":
                guard ready, alive(), let id = request["sessionId"] as? String, id == journal?.sessionId else { throw NativeFailure("Tunnel session is no longer active") }
                deadline = Date().addingTimeInterval(20)
            default: throw NativeFailure("Unknown action")
            }
            return encoded(status())
        } catch { var value = status(); value["ok"] = false; value["error"] = String(describing: error); return encoded(value) }
    }
}

private final class Client: NSObject, TunnelRPC {
    let state: TunnelState
    let uid: UInt32
    init(_ state: TunnelState, uid: UInt32) { self.state = state; self.uid = uid }
    func request(_ data: Data, withReply reply: @escaping (Data) -> Void) {
        state.queue.async { reply(self.state.request(data, uid: self.uid)) }
    }
}

private final class Listener: NSObject, NSXPCListenerDelegate {
    let state = TunnelState()
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        connection.setCodeSigningRequirement(NativeBuild.clientRequirement)
        connection.exportedInterface = NSXPCInterface(with: TunnelRPC.self)
        connection.exportedObject = Client(state, uid: connection.effectiveUserIdentifier)
        connection.resume()
        return true
    }
}

@main struct TunnelService {
    static func main() {
        guard geteuid() == 0 else { exit(1) }
        let delegate = Listener()
        let listener = NSXPCListener(machServiceName: nativeServiceName)
        listener.delegate = delegate
        listener.resume()
        // launchd sends TERM during unload/update. Restore before exiting.
        signal(SIGTERM, SIG_IGN)
        let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: delegate.state.queue)
        termination.setEventHandler { do { try delegate.state.cleanup() } catch { delegate.state.recordError(error) }; exit(0) }
        termination.resume()
        withExtendedLifetime((delegate, termination)) { RunLoop.current.run() }
    }
}
