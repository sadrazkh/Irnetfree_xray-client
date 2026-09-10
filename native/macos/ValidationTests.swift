import Foundation

// Compile/run on macOS: swiftc -parse-as-library Shared.swift ValidationTests.swift -o /tmp/native-validation
@main struct ValidationTests {
    static func main() throws {
        let base: [String: Any] = ["action": "start", "socksPort": 10808, "excludeIps": ["1.2.3.4", "2001:db8::1", "10.0.0.0/8"], "strict": false]
        let options = try StartOptions(base)
        precondition(options.exclusions == ["1.2.3.4/32", "2001:db8::1/128", "10.0.0.0/8"])
        precondition(options.dnsServers == ["172.19.0.2", "fdfe:dcba:9876::2"])
        let inbound = (options.config["inbounds"] as! [[String: Any]])[0]
        precondition(inbound["interface_name"] == nil)
        precondition((inbound["address"] as! [String]).count == 2)
        let outbound = (options.config["outbounds"] as! [[String: Any]])[0]
        precondition(outbound["server"] as! String == "127.0.0.1")
        precondition(outbound["server_port"] as! Int == 10808)
        for patch: [String: Any] in [
            ["socksPort": true], ["socksPort": 80], ["socksPort": 65536], ["socksPort": 10808.5],
            ["excludeIps": ["example.com"]], ["excludeIps": ["1.2.3.4/33"]], ["excludeIps": ["::1/129"]],
            ["excludeIps": ["1.2.3.4;id"]], ["excludeIps": ["fe80::1%en0"]],
            ["strict": true], ["strict": "false"], ["ipv6": 1], ["executable": "/bin/sh"],
            ["dnsServers": []], ["dnsServers": ["example.com"]], ["dnsServers": ["1.1.1.1;id"]]
        ] {
            var request = base; request.merge(patch) { _, new in new }
            do { _ = try StartOptions(request); fatalError("Accepted invalid options: \(patch)") } catch {}
        }
        var customDNS = base; customDNS["dnsServers"] = ["10.8.0.1", "2001:db8::53"]
        let customOptions = try StartOptions(customDNS)
        precondition(customOptions.dnsServers == ["10.8.0.1", "2001:db8::53"])
        print("Native input validation tests passed")
    }
}
