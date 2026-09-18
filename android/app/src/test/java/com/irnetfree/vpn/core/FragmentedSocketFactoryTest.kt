package com.irnetfree.vpn.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.DataInputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The ClientHello has to actually leave in pieces.
 *
 * Splitting it is the one thing a client can do about a middlebox that reads
 * the SNI out of the first packet, and it is invisible if it silently does
 * nothing: the bytes would still arrive, the connection would still die, and
 * the code would still look right.
 *
 * The splitting is asserted against a stream that records every call, NOT
 * through a socket — the receiving TCP stack is free to coalesce the pieces
 * again, so what arrives says nothing about whether they were sent apart. One
 * loopback test follows to prove the socket really uses the wrapper.
 */
class FragmentedSocketFactoryTest {

    /** Records the length of every write it is given. */
    private class Recorder : OutputStream() {
        val writes = ArrayList<Int>()
        override fun write(b: Int) { writes.add(1) }
        override fun write(b: ByteArray, off: Int, len: Int) { writes.add(len) }
    }

    @Test fun theFirstWriteLeavesInChunks() {
        val rec = Recorder()
        val out = FragmentedSocketFactory.splitFirstWrite(rec, chunk = 16, delay = 0)
        out.write(ByteArray(200))
        assertEquals("every byte is still sent", 200, rec.writes.sum())
        assertEquals("200 bytes in 16-byte chunks", 13, rec.writes.size)
        assertTrue("no chunk is bigger than asked for", rec.writes.all { it <= 16 })
    }

    @Test fun everythingAfterTheFirstWriteGoesStraightThrough() {
        val rec = Recorder()
        val out = FragmentedSocketFactory.splitFirstWrite(rec, chunk = 16, delay = 0)
        out.write(ByteArray(64))
        val afterHello = rec.writes.size
        // The body of the request must not be chopped up for nothing: it is past
        // the handshake, and the cost would be paid on every byte of the response.
        out.write(ByteArray(4096))
        assertEquals("the hello was split", 4, afterHello)
        assertEquals("and the rest was one write", afterHello + 1, rec.writes.size)
        assertEquals(64 + 4096, rec.writes.sum())
    }

    @Test fun aWriteNoLongerThanOneChunkIsLeftAlone() {
        val rec = Recorder()
        val out = FragmentedSocketFactory.splitFirstWrite(rec, chunk = 64, delay = 0)
        out.write(ByteArray(10))
        assertEquals(listOf(10), rec.writes)
    }

    @Test fun aSingleByteWriteCountsAsTheFirstWrite() {
        val rec = Recorder()
        val out = FragmentedSocketFactory.splitFirstWrite(rec, chunk = 16, delay = 0)
        out.write(7)
        out.write(ByteArray(200))
        assertEquals("nothing is split after any first write", listOf(1, 200), rec.writes)
    }

    @Test fun theSocketUsesTheWrapperAndKeepsOneOfThem() {
        // A fresh wrapper per getOutputStream() would reset "first write" and
        // split everything; the TLS engine asks for the stream once, but nothing
        // guarantees that.
        ServerSocket(0).use { server ->
            val reads = ArrayList<Int>()
            val done = CountDownLatch(1)
            Thread {
                runCatching {
                    server.accept().use { s ->
                        val input = DataInputStream(s.getInputStream())
                        val buf = ByteArray(4096)
                        while (true) {
                            val n = input.read(buf)
                            if (n <= 0) break
                            synchronized(reads) { reads.add(n) }
                        }
                    }
                }
                done.countDown()
            }.also { it.isDaemon = true }.start()

            val sock = FragmentedSocketFactory(chunkBytes = 16, delayMs = 5).createSocket()
            sock.connect(InetSocketAddress("127.0.0.1", server.localPort), 2000)
            assertTrue("the same stream every time", sock.getOutputStream() === sock.getOutputStream())
            sock.getOutputStream().write(ByteArray(200))
            sock.getOutputStream().flush()
            sock.close()
            done.await(3, TimeUnit.SECONDS)

            val got = synchronized(reads) { reads.toList() }
            assertEquals("all 200 bytes arrive", 200, got.sum())
            // With 5ms between pieces the loopback stack has no reason to coalesce
            // them all; this is the end-to-end proof, not the precise count.
            assertTrue("arrived in more than one read, got $got", got.size > 1)
        }
    }
}
