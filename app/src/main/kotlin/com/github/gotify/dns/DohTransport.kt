package com.github.gotify.dns

import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.URL
import org.tinylog.kotlin.Logger

/**
 * Minimal RFC 8484 DNS-over-HTTPS client (POST + application/dns-message).
 *
 * Some mobile networks and DNS filters answer HTTPS (type 65) queries with an
 * empty answer section, which silently removes the dynamic port published by
 * NATMap. When that happens the resolver retries the same query over DoH.
 */
internal class DohTransport(
    private val endpoint: String = DEFAULT_ENDPOINT,
    private val timeoutMs: Int = DEFAULT_TIMEOUT_MILLIS
) {
    fun query(name: String, type: Int): ByteArray? {
        val request = try {
            DnsWire.query(name, type)
        } catch (e: IllegalArgumentException) {
            Logger.warn("DoH $name type=$type: cannot build query: ${e.message}")
            return null
        }
        var connection: HttpURLConnection? = null
        return try {
            connection = URL(endpoint).openConnection() as HttpURLConnection
            connection.requestMethod = "POST"
            connection.connectTimeout = timeoutMs
            connection.readTimeout = timeoutMs
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/dns-message")
            connection.setRequestProperty("Accept", "application/dns-message")
            connection.outputStream.use { it.write(request) }
            val code = connection.responseCode
            if (code != HttpURLConnection.HTTP_OK) {
                Logger.warn("DoH $name type=$type: HTTP $code")
                return null
            }
            connection.inputStream.use { it.readBytes() }
        } catch (e: Exception) {
            Logger.warn("DoH $name type=$type failed: ${e.javaClass.simpleName}: ${e.message}")
            null
        } finally {
            connection?.disconnect()
        }
    }

    companion object {
        const val DEFAULT_ENDPOINT = "https://dns.alidns.com/dns-query"
        const val DEFAULT_TIMEOUT_MILLIS = 4000
    }
}

/**
 * Wraps the system resolver and retries selected record types over DoH when the
 * system answer carries no data (null result, non-zero rcode or zero answers).
 *
 * A/AAAA lookups are never retried: split-horizon LAN DNS must keep working, so
 * only the record types listed in [fallbackTypes] are affected.
 */
internal class DohFallbackTransport(
    private val primary: DnsTransport,
    private val doh: DohTransport,
    private val fallbackTypes: Set<Int> = setOf(DnsWire.TYPE_HTTPS)
) : DnsTransport {
    override fun query(host: String, type: Int, timeoutMs: Long): ByteArray? {
        val systemAnswer = primary.query(host, type, timeoutMs)
        if (!needsFallback(systemAnswer, type)) {
            return systemAnswer
        }
        Logger.info("system DNS has no answer for $host type=$type, retrying over DoH")
        val remote = doh.query(host, type)
        if (remote == null) {
            Logger.warn("DoH fallback for $host type=$type returned nothing")
            return systemAnswer
        }
        val parsed = try {
            DnsWire.parse(remote)
        } catch (e: DnsFormatException) {
            Logger.warn("DoH answer for $host type=$type is malformed: ${e.message}")
            return systemAnswer
        }
        if (parsed.rcode != 0 || parsed.answers.isEmpty()) {
            Logger.warn("DoH answer for $host type=$type has no data (rcode=${parsed.rcode})")
            return systemAnswer
        }
        Logger.info(
            "DoH fallback for $host type=$type succeeded with ${parsed.answers.size} answer(s)"
        )
        return remote
    }

    override fun lookup(host: String): List<InetAddress> = primary.lookup(host)

    private fun needsFallback(answer: ByteArray?, type: Int): Boolean {
        if (type !in fallbackTypes) {
            return false
        }
        if (answer == null) {
            return true
        }
        return try {
            val message = DnsWire.parse(answer)
            message.rcode != 0 || message.answers.isEmpty()
        } catch (e: DnsFormatException) {
            true
        }
    }
}
