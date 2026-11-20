package com.github.gotify.dns

import java.net.InetAddress
import okhttp3.Dns
import okhttp3.HttpUrl
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Response

internal class OkHttpHostDns(
    private val resolver: HostResolver,
    private val configuredHost: String,
    private val options: ResolveOptions
) : Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        if (!hostname.equals(configuredHost, ignoreCase = true)) {
            return Dns.SYSTEM.lookup(hostname)
        }
        return resolver.resolve(hostname, options).addresses
    }
}

internal class DynamicPortInterceptor(
    private val resolver: HostResolver,
    private val configuredHost: String,
    private val options: ResolveOptions
) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val url = request.url
        if (!url.host.equals(configuredHost, ignoreCase = true)) {
            return chain.proceed(request)
        }

        val endpoint = resolver.resolve(configuredHost, options)
        val port = endpoint.port
        if (port == null || port !in 1..65535 || url.port != defaultPort(url)) {
            return chain.proceed(request)
        }

        val hostHeader = if (url.host.contains(':')) {
            "[${url.host}]"
        } else {
            url.host
        }
        return chain.proceed(
            request.newBuilder()
                .url(url.newBuilder().port(port).build())
                .header("Host", hostHeader)
                .build()
        )
    }

    private fun defaultPort(url: HttpUrl): Int = if (url.isHttps) 443 else 80
}

/**
 * Installs the HTTPS-RR/IP4P-aware resolver and dynamic-port interceptor for
 * one configured Gotify origin. Other hosts keep the system DNS.
 */
internal fun OkHttpClient.Builder.enableHttpsDns(
    connectionUrl: ConnectionUrl,
    resolver: HostResolver
): OkHttpClient.Builder {
    val host = connectionUrl.base.host
    if (isIpLiteral(host)) {
        return this
    }
    val options = connectionUrl.resolveOptions()
    dns(OkHttpHostDns(resolver, host, options))
    addInterceptor(DynamicPortInterceptor(resolver, host, options))
    return this
}

private fun isIpLiteral(host: String): Boolean {
    return host.contains(':') || host.all { it.isDigit() || it == '.' }
}
