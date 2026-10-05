package com.irnetfree.vpn.core

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdateCheckTest {
    @Test fun newerVersions() {
        assertTrue(UpdateCheck.newer("v1.18.1", "1.18.0"))
        assertTrue(UpdateCheck.newer("v1.19.0", "1.18.9"))
        assertTrue(UpdateCheck.newer("v2.0.0", "1.18.0"))
        assertTrue(UpdateCheck.newer("v1.18.0", "1.18.0-beta.1"))   // a release ranks above its pre-releases
        assertFalse(UpdateCheck.newer("v1.18.0", "1.18.0"))
        assertFalse(UpdateCheck.newer("v1.17.0", "1.18.0"))
        assertFalse(UpdateCheck.newer("v1.18.0-beta.1", "1.18.0"))
        assertFalse(UpdateCheck.newer("garbage", "1.18.0"))
        assertFalse(UpdateCheck.newer("v1.18.1", ""))
    }

    @Test fun dueOncePerDay() {
        assertTrue(UpdateCheck.due(0L, 1_000L))
        assertFalse(UpdateCheck.due(1_000L, 1_000L + UpdateCheck.EVERY_MS - 1))
        assertTrue(UpdateCheck.due(1_000L, 1_000L + UpdateCheck.EVERY_MS))
        assertTrue(UpdateCheck.due(5_000L, 1_000L))   // a clock set back: ask again
    }

    @Test fun downloadUrlPrefersTheApk() {
        val rel = JSONObject().put("html_url", "https://github.com/x/y/releases/tag/v1.18.1")
            .put("assets", JSONArray()
                .put(JSONObject().put("name", "IRNetFree-Setup-1.18.1.exe").put("browser_download_url", "https://e/exe"))
                .put(JSONObject().put("name", "IRNetFree-1.18.1.apk").put("browser_download_url", "https://e/apk")))
        assertEquals("https://e/apk", UpdateCheck.downloadUrl(rel))
        assertEquals("https://github.com/x/y/releases/tag/v1.18.1",
            UpdateCheck.downloadUrl(JSONObject().put("html_url", "https://github.com/x/y/releases/tag/v1.18.1")))
    }
}
