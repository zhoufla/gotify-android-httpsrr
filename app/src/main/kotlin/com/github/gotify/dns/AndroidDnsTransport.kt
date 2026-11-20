package com.github.gotify.dns

import android.content.Context
import android.net.ConnectivityManager
import android.net.DnsResolver
import android.os.Build
import android.os.CancellationSignal
import androidx.annotation.RequiresApi
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit

@RequiresApi(Build.VERSION_CODES.Q)
internal class AndroidDnsTransport(context: Context) : DnsTransport {
    private val connectivityManager =
        context.applicationContext.getSystemService(ConnectivityManager::class.java)
    private val executor = Executor { it.run() }

    override fun query(host: String, type: Int, timeoutMs: Long): ByteArray? {
        val latch = CountDownLatch(1)
        val signal = CancellationSignal()
        var result: ByteArray? = null
        try {
            DnsResolver.getInstance().rawQuery(
                connectivityManager.activeNetwork,
                host,
                DnsResolver.CLASS_IN,
                type,
                DnsResolver.FLAG_EMPTY,
                executor,
                signal,
                object : DnsResolver.Callback<ByteArray> {
                    override fun onAnswer(answer: ByteArray, rcode: Int) {
                        result = answer
                        latch.countDown()
                    }

                    override fun onError(error: DnsResolver.DnsException) {
                        latch.countDown()
                    }
                }
            )
        } catch (e: Exception) {
            return null
        }
        return try {
            if (!latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                signal.cancel()
                null
            } else {
                result
            }
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            signal.cancel()
            null
        }
    }

    override fun lookup(host: String): List<InetAddress> = InetAddress.getAllByName(host).toList()
}
