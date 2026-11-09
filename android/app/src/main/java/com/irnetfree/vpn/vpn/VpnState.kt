package com.irnetfree.vpn.vpn

import com.irnetfree.vpn.core.LanShare
import com.irnetfree.vpn.core.SettingsApply
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import java.io.File
import java.io.RandomAccessFile
import java.time.LocalTime
import java.time.format.DateTimeFormatter
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.atomic.AtomicInteger

enum class ConnState { DISCONNECTED, CONNECTING, CONNECTED, ERROR }

data class Traffic(val txBytes: Long = 0, val rxBytes: Long = 0, val txSpeed: Long = 0, val rxSpeed: Long = 0)

/** Process-wide connection state + live traffic, observed by the UI. */
object VpnState {
    private val _state = MutableStateFlow(ConnState.DISCONNECTED)
    val state: StateFlow<ConnState> = _state

    private val _label = MutableStateFlow("")
    val label: StateFlow<String> = _label

    private val _lastError = MutableStateFlow("")
    val lastError: StateFlow<String> = _lastError

    private val _traffic = MutableStateFlow(Traffic())
    val traffic: StateFlow<Traffic> = _traffic

    private val _log = MutableStateFlow<List<String>>(emptyList())
    val log: StateFlow<List<String>> = _log

    private val _connectedSince = MutableStateFlow(0L)
    val connectedSince: StateFlow<Long> = _connectedSince

    /** Post-connect verdict shown on Home: is traffic really working, and if not, where it breaks. */
    private val _health = MutableStateFlow<Health?>(null)
    val health: StateFlow<Health?> = _health
    data class Health(val ok: Boolean, val text: String)
    fun setHealth(ok: Boolean, text: String) { _health.value = Health(ok, text) }

    /**
     * The LAN share the running tunnel really opened (null = none): what
     * Settings → LAN sharing holds against it, to say "sharing now" or
     * "applies on the next connect". Only a CONNECTED tunnel has one.
     */
    private val _lanShared = MutableStateFlow<LanShare?>(null)
    val lanShared: StateFlow<LanShare?> = _lanShared
    fun setLanShared(v: LanShare?) { _lanShared.value = v }

    fun set(s: ConnState, label: String? = null, error: String? = null) {
        _state.value = s
        if (label != null) _label.value = label
        if (error != null && error.isNotBlank()) { _lastError.value = error; addLog("⚠ $error") }
        if (s == ConnState.CONNECTED) { if (_connectedSince.value == 0L) _connectedSince.value = System.currentTimeMillis() }
        // ERROR is reached only once the tunnel is down (XrayVpnService.stopAll
        // keeps it through the teardown), so it ends the session like DISCONNECTED.
        if (s == ConnState.DISCONNECTED || s == ConnState.ERROR) { _connectedSince.value = 0L; _traffic.value = Traffic(); _health.value = null }
        if (s == ConnState.CONNECTING) _health.value = null
        if (s != ConnState.CONNECTED) _lanShared.value = null
    }
    fun setTraffic(t: Traffic) { _traffic.value = t }

    /**
     * Is the app on screen (MainActivity between onStart and onStop)? The
     * per-second figures — the service's traffic reading, the screen's
     * "connected for" clock — are only drawn, so they wait while nobody can
     * see them instead of waking the phone every second (battery).
     */
    private val _uiVisible = MutableStateFlow(false)
    val uiVisible: StateFlow<Boolean> = _uiVisible
    fun setUiVisible(v: Boolean) { _uiVisible.value = v }

    /**
     * What the latest connect built its config from (SettingsApply): the
     * screens name every change made since that the running tunnel does not
     * carry, beside a Reconnect. Written by the connect's prepare.
     */
    private val _applied = MutableStateFlow<SettingsApply.Applied?>(null)
    val applied: StateFlow<SettingsApply.Applied?> = _applied
    fun setApplied(a: SettingsApply.Applied?) { _applied.value = a }

    /**
     * Android's "Block connections without VPN" is on (VpnService.isLockdownEnabled,
     * read when the tunnel comes up): an app per-app routing leaves out of the
     * VPN then has no internet at all instead of going direct.
     */
    private val _lockdown = MutableStateFlow(false)
    val lockdown: StateFlow<Boolean> = _lockdown
    fun setLockdown(v: Boolean) { _lockdown.value = v }
    /**
     * One line more, the oldest beyond 300 dropped, with the time of day in
     * front ("14:32:07 …": a report that it "dropped in the middle" can then be
     * matched to the lines around it). Written from every thread there is (the
     * tunnel's worker, the connect threads, the cores' output readers, the
     * self-check, the network watcher): one atomic update. As a
     * read-then-write, two lines written at the same moment lost one of them.
     * Also queued for the file (attachLog), when there is one.
     */
    fun addLog(line: String) {
        val stamped = "${LocalTime.now().format(CLOCK)} $line"
        _log.update { l: List<String> -> (l + stamped).takeLast(LOG_LINES) }
        if (logFile != null) { pending.incrementAndGet(); logQueue.offer(stamped) }
    }
    fun clearLog() { _log.value = emptyList() }

    /**
     * Wait until every line queued so far is in the file, at most
     * [timeoutMs]; true when it is. For the one moment the process ends
     * itself on purpose (XrayVpnService.restartProcess): the lines that say
     * why must reach the disk first. Nothing queued — no file attached — is
     * flushed already.
     */
    fun awaitLogFlushed(timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (pending.get() > 0) {
            if (System.currentTimeMillis() >= deadline) return false
            try { Thread.sleep(20) } catch (e: InterruptedException) { return false }
        }
        return true
    }

    /**
     * The log on disk too. It lived in memory only, so a session that ended
     * with the process — Android killing it for memory, a core crashing in
     * native code, a battery saver — took every line about it along, and a
     * drop "in the middle of use" could never be read afterwards. Now each
     * line is appended to [LOG_FILE] by one background thread (never the
     * caller's: the worker and the main thread never wait on flash), the file
     * cut back to its newer half past [LOG_MAX_BYTES]. At the next start the
     * file of the run before is kept as [PREV_FILE], and its last
     * [PREV_LINES] lines open the on-screen log under a header — what the
     * phone did right before it stopped is the first thing the Logs screen
     * shows. Called once, by the Application, before anything logs.
     */
    fun attachLog(dir: File) {
        if (logFile != null) return
        val cur = File(dir, LOG_FILE)
        val prev = File(dir, PREV_FILE)
        try {
            if (cur.exists()) { prev.delete(); cur.renameTo(prev) }
        } catch (e: Exception) {
            // unreadable storage: this run starts a file of its own all the same
        }
        val tail: List<String> = runCatching {
            if (prev.exists()) String(tailOf(prev, LOG_KEEP_BYTES), Charsets.UTF_8).split('\n').filter { l: String -> l.isNotEmpty() }.takeLast(PREV_LINES) else emptyList()
        }.getOrDefault(emptyList())
        if (tail.isNotEmpty()) {
            _log.update { l: List<String> -> (listOf(PREV_HEADER) + tail + listOf(PREV_FOOTER) + l).takeLast(LOG_LINES + PREV_LINES + 2) }
        }
        logFile = cur
        val writer = Thread({ drain(cur) }, "irnf-log")
        writer.isDaemon = true
        writer.start()
    }

    /** The file of the run before this one (attachLog), or null: what Share sends beside the screen's lines. */
    fun previousLogFile(dir: File): File? = File(dir, PREV_FILE).takeIf { f: File -> f.exists() }

    private fun drain(f: File) {
        while (true) {
            val first: String = try { logQueue.take() } catch (e: InterruptedException) { return }
            var taken = 1
            try {
                val batch = ArrayList<String>()
                batch.add(first)
                logQueue.drainTo(batch, 200)
                taken = batch.size
                f.appendText(batch.joinToString(separator = "\n", postfix = "\n"))
                // the newer half, by bytes: a bounded read however large a run of failed cuts left the file
                if (f.length() > LOG_MAX_BYTES) f.writeBytes(tailOf(f, LOG_KEEP_BYTES))
            } catch (t: Throwable) {
                // a full disk or a removed directory, or an Error (out of memory): the
                // screen's log goes on without these lines. Throwable because an Error
                // ending this thread ends the process; nothing is kept to retry.
            } finally {
                pending.addAndGet(-taken)           // written, or given up on: either way no longer waited for
            }
        }
    }

    /**
     * The end of [f], at most [maxBytes], starting at a whole line. What it reads
     * is bounded whatever size the file has reached.
     */
    internal fun tailOf(f: File, maxBytes: Int): ByteArray = RandomAccessFile(f, "r").use { r: RandomAccessFile ->
        val size = r.length()
        val from = (size - maxBytes).coerceAtLeast(0L)
        val buf = ByteArray((size - from).toInt())
        r.seek(from)
        r.readFully(buf)
        val newline = if (from > 0L) buf.indexOf('\n'.code.toByte()) else -1
        if (newline >= 0) buf.copyOfRange(newline + 1, buf.size) else buf
    }

    @Volatile private var logFile: File? = null
    private val logQueue = LinkedBlockingQueue<String>()
    /** Lines queued for the file and not yet written (awaitLogFlushed). */
    private val pending = AtomicInteger(0)
    private val CLOCK: DateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss")
    const val LOG_LINES = 300
    const val LOG_FILE = "session-log.txt"
    const val PREV_FILE = "session-log.prev.txt"
    private const val PREV_LINES = 150
    private const val LOG_MAX_BYTES = 512L * 1024
    private const val LOG_KEEP_BYTES = 256 * 1024
    private const val PREV_HEADER = "──── before the app last stopped ────"
    private const val PREV_FOOTER = "──── this run ────"

    val isActive: Boolean get() = _state.value == ConnState.CONNECTED || _state.value == ConnState.CONNECTING
}
