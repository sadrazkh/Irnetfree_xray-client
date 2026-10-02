'use strict';
/**
 * A ring of the last `max` log lines, kept in memory by the headless service:
 * the LuCI Log tab and "Copy diagnostics" read it, and syslog on a router is a
 * small buffer that info lines never reach (service.js toSyslog). Pure, tiny,
 * no dependencies — node 18 and 20 on the router.
 */
function createLogRing(max = 500) {
  const n = Number(max);
  const size = Number.isFinite(n) && n >= 1 ? Math.floor(n) : 500;
  const lines = new Array(size);
  let head = 0;      // where the next line goes
  let count = 0;     // lines held (≤ size)
  return {
    /** Keep `line`; the oldest goes once the ring is full. */
    push(line) {
      lines[head] = String(line == null ? '' : line);
      head = (head + 1) % size;
      if (count < size) count++;
    },
    /** The last `n` lines, oldest first. */
    tail(n) {
      const want = Math.max(0, Math.min(count, Number(n) || 0));
      const out = [];
      for (let i = count - want; i < count; i++) out.push(lines[(head - count + i + size) % size]);
      return out;
    },
    get length() { return count; },
    get max() { return size; }
  };
}

module.exports = { createLogRing };
