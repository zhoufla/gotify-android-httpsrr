package com.github.gotify.dns

import android.content.Context
import android.os.Build

internal object HostResolverProvider {
    @Volatile
    private var resolver: HostResolver? = null

    @Synchronized
    fun initialize(context: Context) {
        if (resolver != null) {
            return
        }
        val appContext = context.applicationContext
        val transport = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            AndroidDnsTransport(appContext)
        } else {
            SystemDnsTransport()
        }
        resolver = HostResolver(transport)
    }

    fun get(): HostResolver {
        return resolver
            ?: throw IllegalStateException("HostResolverProvider was not initialized")
    }
}
