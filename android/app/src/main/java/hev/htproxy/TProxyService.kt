package hev.htproxy

/**
 * JNI binding for hev-socks5-tunnel (libhev-socks5-tunnel.so). The native symbol
 * names are tied to THIS exact package/class path (hev.htproxy.TProxyService), so
 * it must match the prebuilt .so downloaded by scripts/fetch-libs.sh. This is the
 * standard upstream binding used by several Android proxy clients.
 *
 * It reads all IP packets from the VpnService TUN fd and forwards them to a local
 * SOCKS5 server (our in-process Xray socks inbound).
 */
object TProxyService {
    init {
        System.loadLibrary("hev-socks5-tunnel")
    }

    external fun TProxyStartService(configPath: String, fd: Int)
    external fun TProxyStopService()
    external fun TProxyGetStats(): LongArray
}
