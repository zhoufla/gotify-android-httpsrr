package com.github.gotify.dns

import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.UnknownHostException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

internal class HostResolverTest {
    private class FakeTransport : DnsTransport {
        val responses = mutableMapOf<Pair<String, Int>, ByteArray?>()
        val queries = mutableMapOf<Pair<String, Int>, Int>()
        val lookups = mutableMapOf<String, List<InetAddress>>()

        override fun query(host: String, type: Int, timeoutMs: Long): ByteArray? {
            val key = host to type
            queries[key] = (queries[key] ?: 0) + 1
            return responses[key]
        }

        override fun lookup(host: String): List<InetAddress> {
            return lookups[host] ?: throw UnknownHostException(host)
        }
    }

    private fun options(
        useHttpsRr: Boolean = true,
        useIp4p: Boolean = false,
        allowHttpsPort: Boolean = true,
        queryName: String = "web.test"
    ): ResolveOptions {
        return ResolveOptions(useHttpsRr, useIp4p, allowHttpsPort, queryName)
    }

    @Test
    fun usesHttpsHintsPortAndTtlThenCaches() {
        var now = 0L
        val transport = FakeTransport()
        transport.responses["web.test" to DnsWire.TYPE_HTTPS] = DnsTestData.response(
            "web.test",
            DnsWire.TYPE_HTTPS,
            listOf(
                DnsTestData.https(
                    120,
                    1,
                    ".",
                    port = 8443,
                    ipv4Hints = listOf("10.0.0.1")
                )
            )
        )
        val resolver = HostResolver(transport, { now })

        val first = resolver.resolve("web.test", options())
        assertEquals("10.0.0.1", first.addresses[0].hostAddress)
        assertEquals(8443, first.port)
        assertEquals(120L, first.ttlSeconds)
        assertEquals(1, transport.queries["web.test" to DnsWire.TYPE_HTTPS])

        resolver.resolve("web.test", options())
        assertEquals(1, transport.queries["web.test" to DnsWire.TYPE_HTTPS])

        now = 120_001
        resolver.resolve("web.test", options())
        assertEquals(2, transport.queries["web.test" to DnsWire.TYPE_HTTPS])
    }

    @Test
    fun fallsBackToAddressRecordsWhenHttpsIsMissing() {
        val transport = FakeTransport()
        transport.responses["web.test" to DnsWire.TYPE_A] = DnsTestData.response(
            "web.test",
            DnsWire.TYPE_A,
            listOf(DnsTestData.a(60, "192.0.2.1"))
        )
        val resolver = HostResolver(transport, { 0 })

        val endpoint = resolver.resolve("web.test", options())
        assertEquals("192.0.2.1", endpoint.addresses[0].hostAddress)
        assertNull(endpoint.port)
        assertEquals(60L, endpoint.ttlSeconds)
    }

    @Test
    fun usesIp4pOnlyWhenEnabled() {
        val transport = FakeTransport()
        transport.responses["web.test" to DnsWire.TYPE_AAAA] = DnsTestData.response(
            "web.test",
            DnsWire.TYPE_AAAA,
            listOf(DnsTestData.Answer(DnsWire.TYPE_AAAA, 120, DnsTestData.ip4p(8080, "10.0.0.1")))
        )
        val resolver = HostResolver(transport, { 0 })

        val endpoint = resolver.resolve("web.test", options(useHttpsRr = false, useIp4p = true))
        assertEquals("10.0.0.1", endpoint.addresses[0].hostAddress)
        assertEquals(8080, endpoint.port)
    }

    @Test
    fun usesIp4pPortWhenHttpsHintsHaveNoPort() {
        val transport = FakeTransport()
        transport.responses["web.test" to DnsWire.TYPE_HTTPS] = DnsTestData.response(
            "web.test",
            DnsWire.TYPE_HTTPS,
            listOf(
                DnsTestData.https(
                    120,
                    1,
                    ".",
                    ipv4Hints = listOf("10.0.0.2")
                )
            )
        )
        transport.responses["web.test" to DnsWire.TYPE_AAAA] = DnsTestData.response(
            "web.test",
            DnsWire.TYPE_AAAA,
            listOf(DnsTestData.Answer(DnsWire.TYPE_AAAA, 90, DnsTestData.ip4p(8080, "10.0.0.1")))
        )
        val resolver = HostResolver(transport, { 0 })

        val endpoint = resolver.resolve(
            "web.test",
            options(useIp4p = true)
        )
        assertEquals("10.0.0.2", endpoint.addresses[0].hostAddress)
        assertEquals(8080, endpoint.port)
        assertEquals(90L, endpoint.ttlSeconds)
    }

    @Test
    fun prefersIp4pOverPlainAddressesWhenEnabled() {
        val transport = FakeTransport()
        transport.responses["web.test" to DnsWire.TYPE_A] = DnsTestData.response(
            "web.test",
            DnsWire.TYPE_A,
            listOf(DnsTestData.a(60, "192.0.2.1"))
        )
        transport.responses["web.test" to DnsWire.TYPE_AAAA] = DnsTestData.response(
            "web.test",
            DnsWire.TYPE_AAAA,
            listOf(DnsTestData.Answer(DnsWire.TYPE_AAAA, 120, DnsTestData.ip4p(8080, "10.0.0.1")))
        )
        val resolver = HostResolver(transport, { 0 })

        val endpoint = resolver.resolve(
            "web.test",
            options(useHttpsRr = false, useIp4p = true)
        )
        assertEquals(1, endpoint.addresses.size)
        assertEquals("10.0.0.1", endpoint.addresses[0].hostAddress)
        assertEquals(8080, endpoint.port)
        assertEquals(120L, endpoint.ttlSeconds)
    }

    @Test
    fun filtersIp4pWhenNotEnabled() {
        val transport = FakeTransport()
        transport.responses["web.test" to DnsWire.TYPE_A] = DnsTestData.response(
            "web.test",
            DnsWire.TYPE_A,
            listOf(DnsTestData.a(60, "192.0.2.1"))
        )
        transport.responses["web.test" to DnsWire.TYPE_AAAA] = DnsTestData.response(
            "web.test",
            DnsWire.TYPE_AAAA,
            listOf(DnsTestData.Answer(DnsWire.TYPE_AAAA, 120, DnsTestData.ip4p(8080, "10.0.0.1")))
        )
        val resolver = HostResolver(transport, { 0 })

        val endpoint = resolver.resolve("web.test", options(useHttpsRr = false, useIp4p = false))
        assertEquals(1, endpoint.addresses.size)
        assertEquals("192.0.2.1", endpoint.addresses[0].hostAddress)
        assertNull(endpoint.port)
    }

    @Test
    fun failsWhenOnlyIp4pExistsAndNotEnabled() {
        val transport = FakeTransport()
        transport.responses["web.test" to DnsWire.TYPE_AAAA] = DnsTestData.response(
            "web.test",
            DnsWire.TYPE_AAAA,
            listOf(DnsTestData.Answer(DnsWire.TYPE_AAAA, 120, DnsTestData.ip4p(8080, "10.0.0.1")))
        )
        val resolver = HostResolver(transport, { 0 })

        assertThrows(UnknownHostException::class.java) {
            resolver.resolve("web.test", options(useHttpsRr = false, useIp4p = false))
        }
    }

    @Test
    fun followsAliasToServiceRecord() {
        val transport = FakeTransport()
        transport.responses["web.test" to DnsWire.TYPE_HTTPS] = DnsTestData.response(
            "web.test",
            DnsWire.TYPE_HTTPS,
            listOf(DnsTestData.aliasHttps(60, "alias.test"))
        )
        transport.responses["alias.test" to DnsWire.TYPE_HTTPS] = DnsTestData.response(
            "alias.test",
            DnsWire.TYPE_HTTPS,
            listOf(
                DnsTestData.https(
                    90,
                    1,
                    ".",
                    port = 9443,
                    ipv4Hints = listOf("10.0.0.2")
                )
            )
        )
        val resolver = HostResolver(transport, { 0 })

        val endpoint = resolver.resolve("web.test", options())
        assertEquals("10.0.0.2", endpoint.addresses[0].hostAddress)
        assertEquals(9443, endpoint.port)
    }

    @Test
    fun keepsPortPrefixWhenFollowingAlias() {
        val transport = FakeTransport()
        transport.responses["_8443._https.web.test" to DnsWire.TYPE_HTTPS] =
            DnsTestData.response(
                "_8443._https.web.test",
                DnsWire.TYPE_HTTPS,
                listOf(DnsTestData.aliasHttps(60, "alias.test"))
            )
        transport.responses["_8443._https.alias.test" to DnsWire.TYPE_HTTPS] =
            DnsTestData.response(
                "_8443._https.alias.test",
                DnsWire.TYPE_HTTPS,
                listOf(
                    DnsTestData.https(
                        90,
                        1,
                        ".",
                        ipv4Hints = listOf("10.0.0.3")
                    )
                )
            )
        val resolver = HostResolver(transport, { 0 })

        val endpoint = resolver.resolve(
            "web.test",
            options(queryName = "_8443._https.web.test")
        )
        assertEquals("10.0.0.3", endpoint.addresses[0].hostAddress)
    }

    @Test
    fun malformedHttpsFallsBack() {
        val data = ByteArrayOutputStream()
        data.write(0)
        data.write(1)
        data.write(0)
        DnsTestData.svcParam(data, 4, byteArrayOf(10, 0, 0, 1))
        DnsTestData.svcParam(data, 3, byteArrayOf(0x21, 0x0b))
        val transport = FakeTransport()
        transport.responses["web.test" to DnsWire.TYPE_HTTPS] = DnsTestData.response(
            "web.test",
            DnsWire.TYPE_HTTPS,
            listOf(DnsTestData.Answer(DnsWire.TYPE_HTTPS, 60, data.toByteArray()))
        )
        transport.responses["web.test" to DnsWire.TYPE_A] = DnsTestData.response(
            "web.test",
            DnsWire.TYPE_A,
            listOf(DnsTestData.a(60, "192.0.2.1"))
        )
        val resolver = HostResolver(transport, { 0 })

        val endpoint = resolver.resolve("web.test", options())
        assertEquals("192.0.2.1", endpoint.addresses[0].hostAddress)
    }

    @Test
    fun negativeCacheAvoidsRepeatedFailures() {
        var now = 0L
        val transport = FakeTransport()
        val resolver = HostResolver(transport, { now })

        fun fail() {
            assertThrows(UnknownHostException::class.java) {
                resolver.resolve("web.test", options(useHttpsRr = false))
            }
        }

        fail()
        assertEquals(2, transport.queries.size)
        fail()
        assertEquals(2, transport.queries.size)

        now = 30_001
        fail()
        assertTrue(transport.queries.values.sum() > 2)
    }

    @Test
    fun systemLookupIsTheLastFallback() {
        val transport = FakeTransport()
        transport.lookups["web.test"] = listOf(InetAddress.getByName("192.0.2.9"))
        val resolver = HostResolver(transport, { 0 })

        val endpoint = resolver.resolve("web.test", options(useHttpsRr = false))
        assertEquals("192.0.2.9", endpoint.addresses[0].hostAddress)
        assertEquals(60L, endpoint.ttlSeconds)
    }
}
