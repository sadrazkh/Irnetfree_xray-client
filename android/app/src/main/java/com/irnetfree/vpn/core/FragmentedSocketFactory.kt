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
 * applied to the app's own requests. It exists because of what a subscription
 * fetch runs into on a filtered network:
 *
 *   sub.irnetfree.info -> 188.114.96.3 … (os);
 *   could not read the certificate (Handshake failed)
 *
 * The address is right (Cloudflare) and the probe that reported this had
 * certificate verification switched OFF, so nothing was forged — no
 * certificate arrived at all. The connection is killed while the handshake is
 * in flight, which is what matching on the SNI in the ClientHello looks like
 * from the client: the name travels in the clear in that first packet, a
 * middlebox reads it and injects a reset. A browser escapes because it encrypts
 * the ClientHello; this app cannot, but it can make sure the name is never
 * wholly inside any single segment.
 *
 * Costs nothing when it is not needed — only the first write is split, by a few
 * milliseconds — so it is used as an automatic retry rather than a setting for
 * the user to find.
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
