package com.github.gotify.dns

import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

internal class Ip4pTest {
    @Test
    fun decodesNatmapIp4p() {
        val decoded = Ip4p.decode(InetAddress.getByAddress(DnsTestData.ip4p(8080, "10.0.0.1")))
        assertEquals("10.0.0.1", decoded?.address?.hostAddress)
        assertEquals(8080, decoded?.port)
    }

    @Test
    fun doesNotDecodeRealIpv6() {
        assertNull(Ip4p.decode(InetAddress.getByName("2001:db8::1")))
        assertNull(Ip4p.decode(InetAddress.getByName("2001::1")))
    }

    @Test
    fun doesNotDecodeZeroPort() {
        assertNull(Ip4p.decode(InetAddress.getByAddress(DnsTestData.ip4p(0, "10.0.0.1"))))
    }

    @Test
    fun doesNotDecodeZeroIpv4() {
        assertNull(Ip4p.decode(InetAddress.getByAddress(DnsTestData.ip4p(8080, "0.0.0.0"))))
    }
}
