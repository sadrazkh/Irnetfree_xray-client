package com.irnetfree.vpn.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The local ports' move to the 30000s, as the desktop's tests/settingsMigrate.test.js
 * pins it: a store from before on the old defaults reads as the new ones, a port
 * the user chose stays, and once written back the mark keeps a later 10808 a choice.
 */
class PortsTest {
    @Test fun freshDefaultsAreInTheThirtyThousands() {
        val d = AppSettings()
        assertEquals(30808, d.socksPort); assertEquals(30809, d.httpPort); assertEquals(30085, d.apiPort)
        assertEquals(30810, LanShare().socksPort); assertEquals(30811, LanShare().httpPort)
        val empty = AppSettings.fromJson(JSONObject())
        assertEquals(30808, empty.socksPort); assertEquals(30809, empty.httpPort); assertEquals(30085, empty.apiPort)
    }

    @Test fun anOldStoreOnTheOldDefaultsMoves_aChosenPortStays() {
        val old = AppSettings.fromJson(JSONObject().put("socksPort", 10808).put("httpPort", 10809).put("apiPort", 10085))
        assertEquals(30808, old.socksPort); assertEquals(30809, old.httpPort); assertEquals(30085, old.apiPort)
        val chosen = AppSettings.fromJson(JSONObject().put("socksPort", 1080).put("httpPort", 10809).put("apiPort", 12345))
        assertEquals(1080, chosen.socksPort); assertEquals(30809, chosen.httpPort); assertEquals(12345, chosen.apiPort)
    }

    @Test fun writtenBackTheMarkKeepsALater10808AChoice() {
        val json = AppSettings().copy(socksPort = 10808).toJson()
        assertEquals(true, json.getBoolean("portsMoved"))
        assertEquals(10808, AppSettings.fromJson(JSONObject(json.toString())).socksPort)
    }

    @Test fun aStoredLanShareKeepsItsPorts() {
        // the other devices on the network were pointed at them
        val stored = LanShare.fromJson(JSONObject().put("socksPort", 10810).put("httpPort", 10811))
        assertEquals(10810, stored.socksPort); assertEquals(10811, stored.httpPort)
    }
}
