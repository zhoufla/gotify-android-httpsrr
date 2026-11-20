package com.github.gotify.dns

import java.net.InetAddress
import java.net.UnknownHostException
import java.util.Locale

internal data class ResolveOptions(
    val useHttpsRr: Boolean,
    val useIp4p: Boolean,
    val allowHttpsPort: Boolean,
    val httpsQueryName: String
)

internal data class Endpoint(val addresses: List<InetAddress>, val port: Int?, val ttlSeconds: Long)

internal interface DnsTransport {
    fun query(host: String, type: Int, timeoutMs: Long): ByteArray?

    fun lookup(host: String): List<InetAddress>
}

internal class SystemDnsTransport : DnsTransport {
    override fun query(host: String, type: Int, timeoutMs: Long): ByteArray? = null

    override fun lookup(host: String): List<InetAddress> = InetAddress.getAllByName(host).toList()
}

/**
 * Resolves a Gotify host to addresses and an optional dynamic port.
 *
 * The HTTPS RR is only queried for https URLs. IP4P is only decoded when the
 * URL explicitly used the `:0` marker. Any failure falls back to ordinary
 * A/AAAA records.
 */
internal class HostResolver(
    private val transport: DnsTransport,
    private val clock: () -> Long = System::currentTimeMillis,
    private val maxEntries: Int = 64
) {
    private data class CacheKey(val host: String, val options: ResolveOptions)

    private data class CacheEntry(val endpoint: Endpoint, val expiresAt: Long)

    private class AddressResult(
        val addresses: List<InetAddress>,
        val port: Int?,
        val ttlSeconds: Long
    )

    private val lock = Any()
    private val keyLocks = mutableMapOf<CacheKey, Any>()
    private val negativeCache = mutableMapOf<CacheKey, Long>()
    private val cache = object : LinkedHashMap<CacheKey, CacheEntry>(16, 0.75f, true) {
        override fun removeEldestEntry(
            eldest: MutableMap.MutableEntry<CacheKey, CacheEntry>?
        ): Boolean {
            return size > maxEntries
        }
    }

    fun resolve(host: String, options: ResolveOptions): Endpoint {
        val key = CacheKey(host.lowercase(Locale.ROOT), options)
        val now = clock()
        synchronized(lock) {
            cache[key]?.let {
                if (it.expiresAt > now) {
                    return it.endpoint
                }
                cache.remove(key)
            }
            negativeCache[key]?.let {
                if (it > now) {
                    throw UnknownHostException(host)
                }
                negativeCache.remove(key)
            }
            keyLocks.getOrPut(key) { Any() }
        }

        val keyLock = synchronized(lock) { keyLocks.getValue(key) }
        return synchronized(keyLock) {
            val current = clock()
            synchronized(lock) {
                cache[key]?.let {
                    if (it.expiresAt > current) {
                        return it.endpoint
                    }
                    cache.remove(key)
                }
                negativeCache[key]?.let {
                    if (it > current) {
                        throw UnknownHostException(host)
                    }
                    negativeCache.remove(key)
                }
            }

            try {
                val endpoint = resolveUncached(host, options)
                if (endpoint.ttlSeconds > 0) {
                    val ttl = endpoint.ttlSeconds.coerceAtMost(MAX_TTL_SECONDS)
                    synchronized(lock) {
                        cache[key] = CacheEntry(endpoint, current + ttl * 1000)
                        negativeCache.remove(key)
                    }
                }
                endpoint
            } catch (e: UnknownHostException) {
                synchronized(lock) {
                    negativeCache[key] = current + NEGATIVE_TTL_MILLIS
                }
                throw e
            }
        }
    }

    fun invalidate(host: String) {
        val normalized = host.lowercase(Locale.ROOT)
        synchronized(lock) {
            cache.keys.removeAll { it.host == normalized }
            negativeCache.keys.removeAll { it.host == normalized }
        }
    }

    fun clear() {
        synchronized(lock) {
            cache.clear()
            negativeCache.clear()
        }
    }

    private fun resolveUncached(host: String, options: ResolveOptions): Endpoint {
        if (options.useHttpsRr) {
            val https = try {
                resolveHttps(host, options, 0)
            } catch (e: UnknownHostException) {
                null
            }
            if (https != null) {
                return https
            }
        }
        return resolveAddresses(host, options.useIp4p).toEndpoint()
    }

    private fun resolveHttps(host: String, options: ResolveOptions, depth: Int): Endpoint? {
        val bindings = queryHttps(options.httpsQueryName)
        if (bindings.isEmpty()) {
            return null
        }

        val alias = bindings.firstOrNull { it.isAlias }
        if (alias != null) {
            if (alias.targetIsOwner || alias.target.equals(host, ignoreCase = true) || depth >= 1) {
                return null
            }
            val targetOptions = options.copy(
                httpsQueryName = rewriteQueryName(options.httpsQueryName, alias.target)
            )
            val target = resolveHttps(alias.target, targetOptions, depth + 1)
            if (target != null) {
                return target
            }
            return resolveAddresses(alias.target, options.useIp4p).toEndpoint()
        }

        val service = bindings
            .filter { it.priority > 0 }
            .minByOrNull { it.priority }
            ?: return null
        val targetHost = if (service.targetIsOwner) host else service.target
        val port = if (options.allowHttpsPort) service.port else null
        val hints = service.ipv4Hints + service.ipv6Hints
        if (hints.isNotEmpty()) {
            var effectivePort = port
            var ttl = service.ttlSeconds
            if (effectivePort == null && options.useIp4p) {
                val addressRecords = resolveAddresses(targetHost, true)
                effectivePort = addressRecords.port
                if (effectivePort != null) {
                    ttl = minOf(ttl, addressRecords.ttlSeconds)
                }
            }
            return Endpoint(hints, effectivePort, ttl)
        }

        val resolved = resolveAddresses(targetHost, options.useIp4p)
        return Endpoint(
            addresses = resolved.addresses,
            port = port ?: resolved.port,
            ttlSeconds = minOf(service.ttlSeconds, resolved.ttlSeconds)
        )
    }

    /**
     * An HTTPS RR for a non-default port lives at `_port._https.host`; when an
     * AliasMode record points at another name, that service prefix must be kept
     * so the alias is queried at `_port._https.alias`.
     */
    private fun rewriteQueryName(queryName: String, target: String): String {
        val marker = "._https."
        val index = queryName.indexOf(marker)
        return if (queryName.startsWith("_") && index >= 0) {
            queryName.substring(0, index + marker.length) + target
        } else {
            target
        }
    }

    private fun queryHttps(name: String): List<HttpsBinding> {
        val bytes =
            transport.query(name, DnsWire.TYPE_HTTPS, HTTPS_TIMEOUT_MILLIS) ?: return emptyList()
        val message = try {
            DnsWire.parse(bytes)
        } catch (e: DnsFormatException) {
            return emptyList()
        }
        if (message.rcode != 0) {
            return emptyList()
        }
        return message.answers
            .filterIsInstance<DnsRecord.Https>()
            .filter { it.name.equals(name, ignoreCase = true) }
            .map { it.binding }
    }

    private fun resolveAddresses(host: String, useIp4p: Boolean): AddressResult {
        val plainAddresses = mutableListOf<Pair<InetAddress, Long>>()
        val ip4pAddresses = mutableListOf<Pair<InetAddress, Long>>()
        var port: Int? = null

        for (record in queryRecords(host, DnsWire.TYPE_A)) {
            if (record is DnsRecord.A) {
                plainAddresses.add(record.address to record.ttlSeconds)
            }
        }
        for (record in queryRecords(host, DnsWire.TYPE_AAAA)) {
            if (record !is DnsRecord.Aaaa) {
                continue
            }
            val decoded = if (useIp4p) Ip4p.decode(record.address) else null
            if (decoded != null) {
                ip4pAddresses.add(decoded.address to record.ttlSeconds)
                if (port == null) {
                    port = decoded.port
                }
            } else if (!useIp4p && Ip4p.isIp4p(record.address)) {
                // An IP4P AAAA must only be used when the user opted in with :0.
                continue
            } else {
                plainAddresses.add(record.address to record.ttlSeconds)
            }
        }

        // When the user explicitly asked for IP4P, the encoded IPv4 address is
        // the mapped endpoint. Plain A/AAAA records cannot be reached on that
        // mapped port, so do not mix them into the result.
        val selected = if (useIp4p && ip4pAddresses.isNotEmpty()) {
            ip4pAddresses
        } else {
            plainAddresses + ip4pAddresses
        }
        if (selected.isEmpty()) {
            return systemLookup(host, useIp4p)
        }
        val ttl = selected.minOf { it.second }.coerceIn(0, MAX_TTL_SECONDS)
        return AddressResult(deduplicate(selected.map { it.first }), port, ttl)
    }

    private fun systemLookup(host: String, useIp4p: Boolean): AddressResult {
        val addresses = try {
            transport.lookup(host)
        } catch (e: UnknownHostException) {
            throw e
        } catch (e: Exception) {
            throw UnknownHostException(host)
        }
        val plain = mutableListOf<InetAddress>()
        val ip4p = mutableListOf<InetAddress>()
        var port: Int? = null
        for (address in addresses) {
            val decoded = if (useIp4p) Ip4p.decode(address) else null
            if (decoded != null) {
                ip4p.add(decoded.address)
                if (port == null) {
                    port = decoded.port
                }
            } else if (!useIp4p && Ip4p.isIp4p(address)) {
                continue
            } else {
                plain.add(address)
            }
        }
        val selected = if (useIp4p && ip4p.isNotEmpty()) ip4p else plain + ip4p
        val deduplicated = deduplicate(selected)
        if (deduplicated.isEmpty()) {
            throw UnknownHostException(host)
        }
        return AddressResult(deduplicated, port, SYSTEM_TTL_SECONDS)
    }

    private fun queryRecords(host: String, type: Int): List<DnsRecord> {
        val bytes = transport.query(host, type, ADDRESS_TIMEOUT_MILLIS) ?: return emptyList()
        val message = try {
            DnsWire.parse(bytes)
        } catch (e: DnsFormatException) {
            return emptyList()
        }
        if (message.rcode != 0) {
            return emptyList()
        }
        return message.answers
    }

    private fun deduplicate(addresses: List<InetAddress>): List<InetAddress> {
        val result = LinkedHashMap<String, InetAddress>()
        for (address in addresses) {
            val key = address.hostAddress ?: address.toString()
            result.putIfAbsent(key, address)
        }
        return result.values.toList()
    }

    private fun AddressResult.toEndpoint(): Endpoint {
        return Endpoint(addresses, port, ttlSeconds)
    }

    private companion object {
        const val HTTPS_TIMEOUT_MILLIS = 4000L
        const val ADDRESS_TIMEOUT_MILLIS = 2000L
        const val SYSTEM_TTL_SECONDS = 60L
        const val MAX_TTL_SECONDS = 3600L
        const val NEGATIVE_TTL_MILLIS = 30_000L
    }
}
