package com.github.gotify.dns

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/**
 * NATMap encodes an IPv4 address and port in a AAAA record as:
 *
 *   2001::<port16>:<ipv4-hi16>:<ipv4-lo16>
 *
 * bytes[0..1] = 0x2001, bytes[2..9] = 0, bytes[10..11] = port,
 * bytes[12..15] = IPv4 address.
 */
internal object Ip4p {
    data class Decoded(val address: Inet4Address, val port: Int)

    fun decode(address: InetAddress): Decoded? {
        if (address !is Inet6Address) {
            return null
        }
        val bytes = address.address
        if (bytes.size != 16) {
            return null
        }
        if (bytes[0] != 0x20.toByte() || bytes[1] != 0x01.toByte()) {
            return null
        }
        for (index in 2..9) {
            if (bytes[index] != 0.toByte()) {
                return null
            }
        }
        val port = ((bytes[10].toInt() and 0xff) shl 8) or (bytes[11].toInt() and 0xff)
        if (port !in 1..65535) {
            return null
        }
        val ipv4 = bytes.copyOfRange(12, 16)
        if (ipv4.all { it == 0.toByte() } || ipv4[0] == 0.toByte()) {
            return null
        }
        return Decoded(InetAddress.getByAddress(ipv4) as Inet4Address, port)
    }

    fun isIp4p(address: InetAddress): Boolean = decode(address) != null
}
