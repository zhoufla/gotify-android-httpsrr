package com.github.gotify.dns

import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/**
 * A Gotify URL with support for the NATMap convention of appending `:0` to the
 * authority. Port 0 is a marker meaning "take the port from the IP4P AAAA
 * record", it is never passed to OkHttp.
 */
internal data class ConnectionUrl(val raw: String, val base: HttpUrl, val dynamicPort: Boolean) {
    fun retroBaseUrl(): String {
        val value = base.toString()
        return if (value.endsWith("/")) value else "$value/"
    }

    fun resolveOptions(): ResolveOptions {
        val defaultPort = if (base.isHttps) 443 else 80
        val explicitNonDefaultPort = base.port != defaultPort
        val queryName = if (base.isHttps && explicitNonDefaultPort && !dynamicPort) {
            "_${base.port}._https.${base.host}"
        } else {
            base.host
        }
        return ResolveOptions(
            useHttpsRr = base.isHttps,
            useIp4p = dynamicPort,
            allowHttpsPort = !explicitNonDefaultPort,
            httpsQueryName = queryName
        )
    }

    companion object {
        fun parse(raw: String): ConnectionUrl? {
            val trimmed = raw.trim()
            if (trimmed.isEmpty()) {
                return null
            }
            val withoutZeroPort = stripZeroPort(trimmed)
            val dynamicPort = withoutZeroPort != trimmed
            val parsed = withoutZeroPort.toHttpUrlOrNull() ?: return null
            return ConnectionUrl(trimmed, parsed, dynamicPort)
        }

        /**
         * Removes a trailing `:0` from the authority only. This must not touch
         * `:0` in user-info, paths, queries or fragments.
         */
        private fun stripZeroPort(url: String): String {
            val schemeEnd = url.indexOf("://")
            if (schemeEnd < 0) {
                return url
            }
            val authorityStart = schemeEnd + 3
            val authorityEnd = url.indexOfAny(charArrayOf('/', '?', '#'), authorityStart)
                .let { if (it < 0) url.length else it }
            if (authorityEnd - 2 <= authorityStart) {
                return url
            }
            if (url.substring(authorityEnd - 2, authorityEnd) != ":0") {
                return url
            }
            val hostPort = url.substring(authorityStart, authorityEnd).substringAfterLast('@')
            val host = hostPort.dropLast(2)
            if (host.isEmpty()) {
                return url
            }
            // Unbracketed strings with colons are not valid host names. Only
            // bracketed IPv6 literals may contain a colon.
            if (host.contains(':') && !(host.startsWith("[") && host.endsWith("]"))) {
                return url
            }
            return url.removeRange(authorityEnd - 2, authorityEnd)
        }
    }
}
