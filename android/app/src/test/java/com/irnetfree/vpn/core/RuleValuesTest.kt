package com.irnetfree.vpn.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** What a core reads of an IP or port rule's values (RuleValues). */
class RuleValuesTest {
    @Test fun ipValues() {
        for (v in listOf("1.2.3.4", "10.0.0.0/8", "0.0.0.0/0", "2001:db8::1", "2001:db8::/32", "::/0", "geoip:ir", "GEOIP:private", "ext:geo.dat:ir", " 8.8.8.8 "))
            assertTrue(v, RuleValues.isIp(v))
        for (v in listOf("google.com", "1.2.3.4/33", "2001:db8::/129", "1.2.3", "256.1.1.1", "1.2.3.4/", "1.2.3.4/x", "geoip:", "", "*.ir"))
            assertFalse(v, RuleValues.isIp(v))
    }

    @Test fun portValues() {
        for (v in listOf("443", "0-65535", "1000-2000", " 53 ", "80-80"))
            assertTrue(v, RuleValues.isPort(v))
        for (v in listOf("abc", "70000", "80-", "-80", "2000-1000", "1-2-3", "", "99999999999"))
            assertFalse(v, RuleValues.isPort(v))
    }

    @Test fun domainValuesAreAnotherOnesToClean() {
        assertEquals(listOf("google.com"), RuleValues.usable("domain", listOf("google.com")))
        assertEquals(emptyList<String>(), RuleValues.unusable("domain", listOf("not a domain")))
        assertEquals(listOf("google.com"), RuleValues.unusable("ip", listOf("1.1.1.1", "google.com")))
    }
}
