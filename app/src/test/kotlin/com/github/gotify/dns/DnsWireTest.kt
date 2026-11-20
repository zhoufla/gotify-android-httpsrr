package com.github.gotify.dns

import java.io.ByteArrayOutputStream
import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

internal class DnsWireTest {
    @Test
    fun parsesServiceModeHttpsRecord() {
        val response = DnsTestData.response(
            "web.test",
            DnsWire.TYPE_HTTPS,
            listOf(
                DnsTestData.https(
                    ttl = 120,
                    priority = 1,
                    target = ".",
                    port = 8443,
                    ipv4Hints = listOf("10.0.0.1"),
                    ipv6Hints = listOf("2001:db8::1")
                )
            )
        )
        val message = DnsWire.parse(response)
        assertEquals(0, message.rcode)
        assertEquals(1, message.answers.size)
        val record = message.answers[0] as DnsRecord.Https
        assertEquals(120L, record.ttlSeconds)
        assertEquals(1, record.binding.priority)
        assertEquals(".", record.binding.target)
        assertEquals(8443, record.binding.port)
        assertEquals("10.0.0.1", record.binding.ipv4Hints[0].hostAddress)
        assertEquals(InetAddress.getByName("2001:db8::1"), record.binding.ipv6Hints[0])
        assertFalse(record.binding.isAlias)
        assertTrue(record.binding.targetIsOwner)
    }

    @Test
    fun parsesAliasModeRecord() {
        val response = DnsTestData.response(
            "web.test",
            DnsWire.TYPE_HTTPS,
            listOf(DnsTestData.aliasHttps(60, "alias.test"))
        )
        val binding = (DnsWire.parse(response).answers[0] as DnsRecord.Https).binding
        assertEquals(0, binding.priority)
        assertEquals("alias.test", binding.target)
        assertTrue(binding.isAlias)
    }

    @Test
    fun parsesCompressedTargetName() {
        val data = ByteArrayOutputStream()
        data.write(0)
        data.write(1)
        data.write(0xc0)
        data.write(0x0c)
        val response = DnsTestData.response(
            "web.test",
            DnsWire.TYPE_HTTPS,
            listOf(DnsTestData.Answer(DnsWire.TYPE_HTTPS, 60, data.toByteArray()))
        )
        val binding = (DnsWire.parse(response).answers[0] as DnsRecord.Https).binding
        assertEquals("web.test", binding.target)
    }

    @Test(expected = DnsFormatException::class)
    fun rejectsOutOfOrderSvcParams() {
        val data = ByteArrayOutputStream()
        data.write(0)
        data.write(1)
        data.write(0)
        DnsTestData.svcParam(data, 4, byteArrayOf(10, 0, 0, 1))
        DnsTestData.svcParam(data, 3, byteArrayOf(0x21, 0x0b))
        val response = DnsTestData.response(
            "web.test",
            DnsWire.TYPE_HTTPS,
            listOf(DnsTestData.Answer(DnsWire.TYPE_HTTPS, 60, data.toByteArray()))
        )
        DnsWire.parse(response)
    }

    @Test(expected = DnsFormatException::class)
    fun rejectsTruncatedSvcParam() {
        val data = ByteArrayOutputStream()
        data.write(0)
        data.write(1)
        data.write(0)
        data.write(3)
        data.write(0)
        data.write(2)
        data.write(0x21)
        // Missing second port byte.
        val response = DnsTestData.response(
            "web.test",
            DnsWire.TYPE_HTTPS,
            listOf(DnsTestData.Answer(DnsWire.TYPE_HTTPS, 60, data.toByteArray()))
        )
        DnsWire.parse(response)
    }

    @Test
    fun parsesAddressRecords() {
        val response = DnsTestData.response(
            "web.test",
            DnsWire.TYPE_A,
            listOf(
                DnsTestData.a(120, "192.0.2.1"),
                DnsTestData.aaaa(240, "2001:db8::2")
            )
        )
        val message = DnsWire.parse(response)
        assertEquals(2, message.answers.size)
        assertEquals("192.0.2.1", (message.answers[0] as DnsRecord.A).address.hostAddress)
        assertEquals(240L, (message.answers[1] as DnsRecord.Aaaa).ttlSeconds)
    }
}
