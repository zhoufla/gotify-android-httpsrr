package com.github.gotify.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

internal class ConnectionUrlTest {
    @Test
    fun stripsExplicitZeroPort() {
        val url = ConnectionUrl.parse("http://www.ddd.com:0")
        assertEquals("http://www.ddd.com/", url?.retroBaseUrl())
        assertEquals(80, url?.base?.port)
        assertTrue(url!!.dynamicPort)
    }

    @Test
    fun keepsPathWithZeroPort() {
        val url = ConnectionUrl.parse("https://host.test:0/gotify?x=1")
        assertEquals("https://host.test/gotify?x=1", url?.base.toString())
        assertTrue(url!!.dynamicPort)
    }

    @Test
    fun handlesBracketedIpv6ZeroPort() {
        val url = ConnectionUrl.parse("https://[::1]:0")
        assertEquals("https://[::1]/", url?.retroBaseUrl())
        assertTrue(url!!.dynamicPort)
    }

    @Test
    fun ignoresZeroInPathOrQuery() {
        val url = ConnectionUrl.parse("https://host.test/path:0?x=:0")
        assertFalse(url!!.dynamicPort)
    }

    @Test
    fun rejectsUnsupportedUrls() {
        assertNull(ConnectionUrl.parse("not a url"))
        assertNull(ConnectionUrl.parse("http://host.test:0:0"))
        assertNull(ConnectionUrl.parse("http://host.test:65536"))
    }

    @Test
    fun httpsOptionsUseHttpsRr() {
        val url = ConnectionUrl.parse("https://web.test")!!
        val options = url.resolveOptions()
        assertTrue(options.useHttpsRr)
        assertFalse(options.useIp4p)
        assertTrue(options.allowHttpsPort)
        assertEquals("web.test", options.httpsQueryName)
    }

    @Test
    fun explicitNonDefaultPortUsesPortQualifiedHttpsName() {
        val url = ConnectionUrl.parse("https://web.test:8443")!!
        val options = url.resolveOptions()
        assertEquals("_8443._https.web.test", options.httpsQueryName)
        assertFalse(options.allowHttpsPort)
        assertFalse(options.useIp4p)
    }

    @Test
    fun httpZeroPortUsesIp4p() {
        val url = ConnectionUrl.parse("http://www.ddd.com:0")!!
        val options = url.resolveOptions()
        assertFalse(options.useHttpsRr)
        assertTrue(options.useIp4p)
        assertEquals("www.ddd.com", options.httpsQueryName)
    }
}
