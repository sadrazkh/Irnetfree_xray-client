package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * A canonical text for a JSON value: object keys sorted, arrays in order. The
 * org.json JSONObject on the JVM keeps its keys in a HashMap, so two objects
 * with the same content can print in different orders; tests compare this.
 */
object Canon {
    fun of(v: Any?): String = when (v) {
        null, JSONObject.NULL -> "null"
        is JSONObject -> v.keys().asSequence().sorted().joinToString(",", "{", "}") { k -> "\"$k\":" + of(v.get(k)) }
        is JSONArray -> (0 until v.length()).joinToString(",", "[", "]") { of(v.get(it)) }
        is String -> "\"" + v.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
        is Number, is Boolean -> v.toString()
        else -> of(JSONObject(v.toString()))
    }
    fun same(expected: String, actual: Any?): Boolean = of(JSONObject(expected)) == of(actual)
}
