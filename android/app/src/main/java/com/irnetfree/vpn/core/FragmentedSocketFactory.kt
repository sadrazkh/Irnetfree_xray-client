package com.irnetfree.vpn.core

import java.io.OutputStream
import java.net.InetAddress
import java.net.Socket
import javax.net.SocketFactory

/**
 * A socket factory that splits the FIRST thing written into several small TCP
 * segments — which, for a TLS connection, is the ClientHello.
 *
 * This is the same trick the app already offers inside a config as `fragment`,
 * applied to the app's own requests: a middlebox that matches on the SNI in
 * the first packet cannot when no single segment holds the whole name.
 *
 * A note on its history, so nobody repeats it. This was written for the
 * subscription fetch that failed with "Handshake failed" on the owner's phone,
 * on the theory that the ClientHello was being killed for its SNI. It was not:
 * the panel's Cloudflare zone requires TLS 1.3 and the phone's platform TLS
 * only had 1.2 (IRApp.installTls13 is the fix). Splitting the ClientHello did
 * nothing for that — nothing could, short of speaking TLS 1.3. It stays
 * because it is cheap and correct for the case it was named after; it is a
 * retry after an SSL failure, never the first attempt.
 */
class FragmentedSocketFactory(
    private val chunkBytes: Int = 48,
    private val delayMs: Long = 12
) : SocketFactory() {

    override fun createSocket(): Socket = FragmentSocket(chunkBytes, delayMs)

    override fun createSocket(host: String, port: Int): Socket =
        FragmentSocket(chunkBytes, delayMs).apply { connect(java.net.InetSocketAddress(host, port)) }

    override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket =
        FragmentSocket(chunkBytes, delayMs).apply {
            bind(java.net.InetSocketAddress(localHost, localPort))
            connect(java.net.InetSocketAddress(host, port))
        }

    override fun createSocket(host: InetAddress, port: Int): Socket =
        FragmentSocket(chunkBytes, delayMs).apply { connect(java.net.InetSocketAddress(host, port)) }

    override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket =
        FragmentSocket(chunkBytes, delayMs).apply {
            bind(java.net.InetSocketAddress(localAddress, localPort))
            connect(java.net.InetSocketAddress(address, port))
        }

    /** Splits its first write; every write after that goes straight through. */
    private class FragmentSocket(private val chunk: Int, private val delay: Long) : Socket() {
        private var wrapper: OutputStream? = null

        // Cached: the TLS engine holds on to the stream it is handed, and a fresh
        // wrapper per call would reset "first write" and split everything.
        override fun getOutputStream(): OutputStream =
            wrapper ?: splitFirstWrite(super.getOutputStream(), chunk, delay).also { wrapper = it }
    }

    companion object {
        /**
         * Wraps [raw] so the first write longer than [chunk] leaves as several
         * writes of [chunk] bytes, [delay] ms apart; everything after it passes
         * through untouched.
         *
         * Separate from the socket so it can be tested against a stream that
         * records calls: through a real socket the receiving TCP stack is free to
         * coalesce the pieces again, so what arrives says nothing about whether
         * they were sent apart.
         */
        fun splitFirstWrite(raw: OutputStream, chunk: Int, delay: Long): OutputStream = object : OutputStream() {
            private var firstDone = false
            override fun write(b: Int) { firstDone = true; raw.write(b) }
            override fun write(b: ByteArray, off: Int, len: Int) {
                if (firstDone || len <= chunk) { firstDone = true; raw.write(b, off, len); return }
                firstDone = true
                var i = off
                val end = off + len
                while (i < end) {
                    val n = minOf(chunk, end - i)
                    raw.write(b, i, n)
                    raw.flush()
                    i += n
                    if (i < end && delay > 0) {
                        // A pause as well as a split: a middlebox that reassembles
                        // segments arriving together would match the SNI anyway.
                        try { Thread.sleep(delay) } catch (e: InterruptedException) {
                            Thread.currentThread().interrupt(); break
                        }
                    }
                }
            }
            override fun flush() = raw.flush()
            override fun close() = raw.close()
        }
    }
}
