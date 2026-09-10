import Foundation
import CoreFoundation
import Darwin

@objc protocol TunnelRPC {
    func request(_ data: Data, withReply reply: @escaping (Data) -> Void)
}

let nativeServiceName = "com.irnetfree.client.tunnel"
let nativePlistName = "com.irnetfree.client.tunnel.plist"

struct NativeFailure: Error, CustomStringConvertible {
    let description: String
    init(_ message: String) { description = message }
}

func encoded(_ value: [String: Any]) -> Data {
    (try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])) ?? Data("{\"ok\":false}".utf8)
}

struct StartOptions {
    let port: Int
    let exclusions: [String]
    let strict: Bool
    let dnsServers: [String]
    init(_ request: [String: Any]) throws {
        let allowed: Set<String> = ["action", "socksPort", "excludeIps", "strict", "ipv6", "dnsServers"]
        guard Set(request.keys).isSubset(of: allowed),
              let number = request["socksPort"] as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              number.doubleValue == Double(number.intValue), (1024...65535).contains(number.intValue),
              let addresses = request["excludeIps"] as? [String], addresses.count <= 512 else {
            throw NativeFailure("Invalid tunnel options")
        }
        for key in ["strict", "ipv6"] {
            if let value = request[key] {
                guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else {
                    throw NativeFailure("Invalid boolean option")
                }
            }
        }
        port = number.intValue
        strict = request["strict"] as? Bool ?? false
        guard !strict else { throw NativeFailure("Native macOS strict kill switch is not supported; select the compatibility backend or explicitly disable strict mode") }
        let dns = request["dnsServers"] ?? ["172.19.0.2", "fdfe:dcba:9876::2"]
        guard let servers = dns as? [String], !servers.isEmpty, servers.count <= 8 else { throw NativeFailure("Invalid DNS servers") }
        for host in servers {
            var v4 = in_addr(); var v6 = in6_addr()
            guard inet_pton(AF_INET, host, &v4) == 1 || inet_pton(AF_INET6, host, &v6) == 1 else { throw NativeFailure("Invalid DNS address") }
        }
        dnsServers = servers
        exclusions = try addresses.map { address in
            let parts = address.split(separator: "/", omittingEmptySubsequences: false)
            guard parts.count <= 2, !parts.isEmpty else { throw NativeFailure("Invalid exclusion") }
            let host = String(parts[0])
            var v4 = in_addr(); var v6 = in6_addr()
            let bits: Int
            if inet_pton(AF_INET, host, &v4) == 1 { bits = 32 }
            else if inet_pton(AF_INET6, host, &v6) == 1 { bits = 128 }
            else { throw NativeFailure("Exclusions must be literal IP addresses") }
            let prefix = parts.count == 2 ? Int(parts[1]) : bits
            guard let prefix = prefix, (0...bits).contains(prefix) else { throw NativeFailure("Invalid prefix") }
            return "\(host)/\(prefix)"
        }
    }
    var config: [String: Any] {
        ["log": ["level": "warn", "timestamp": false],
         "inbounds": [["type": "tun", "tag": "tun-in", "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"], "mtu": 1500, "auto_route": true, "strict_route": strict, "stack": "system", "route_exclude_address": exclusions]],
         "outbounds": [["type": "socks", "tag": "socks-out", "server": "127.0.0.1", "server_port": port, "version": "5"]],
         "route": ["final": "socks-out", "auto_detect_interface": true]]
    }
}
