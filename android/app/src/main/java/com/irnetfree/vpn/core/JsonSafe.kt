package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * JSON read from what nobody here wrote — a link's `fm=` / `extra=` / ECH
 * parameter, a vmess body, an imported config — and written back to the store.
 *
 * Android's org.json (not the library the JVM tests run on) reads `NaN`,
 * `Infinity` and a number past a double's range (`1e999`) inside an ARRAY
 * without a word: JSONTokener.readArray adds the value unchecked. It then
 * cannot write it: JSONObject/JSONArray.toString() returns null. Saved, that
 * null was `putString("servers", null)` — which REMOVES the key — so one such
 * link pasted or fetched emptied the whole server list at the next launch
 * (or, where Kotlin checked the null, every save threw). Such JSON is refused
 * where it comes in ([objectOf], [finite]); the store checks again where it
 * writes ([text]).
 *
 * A text nested deeper than JsonImport.MAX_DEPTH is refused before org.json
 * reads it: its parser recurses, and a link a few KB long ran the thread out
 * of stack — a StackOverflowError that no `catch (e: Exception)` sees.
 */
object JsonSafe {
    /** How deep [finite] walks before it calls a value unsafe — deeper than anything [objectOf] lets in. */
    private const val WALK_LIMIT = 256

    /** [v]'s JSON text, or null where org.json cannot write it (its toString() returns null then). */
    fun text(v: Any): String? = java.util.Objects.toString(v)

    /** No number JSON cannot carry (NaN, ±Infinity) anywhere in [v]. */
    fun finite(v: Any?): Boolean = finite(v, 0)

    private fun finite(v: Any?, depth: Int): Boolean {
        if (depth > WALK_LIMIT) return false
        return when (v) {
            is JSONObject -> v.keys().asSequence().toList().all { k: String -> finite(v.opt(k), depth + 1) }
            is JSONArray -> (0 until v.length()).all { i: Int -> finite(v.opt(i), depth + 1) }
            is Double -> !v.isNaN() && !v.isInfinite()
            is Float -> !v.isNaN() && !v.isInfinite()
            else -> true
        }
    }

    /**
     * [s] as an object, or null: not JSON, not an object, nested deeper than
     * JsonImport.MAX_DEPTH, or holding a number JSON cannot carry.
     */
    fun objectOf(s: String): JSONObject? {
        if (JsonImport.nestingDepth(s) > JsonImport.MAX_DEPTH) return null
        val o: JSONObject = try {
            JSONObject(s)
        } catch (e: Exception) {
            return null
        } catch (e: StackOverflowError) {
            return null
        }
        return if (finite(o)) o else null
    }
}
