package com.github.gotify.dns

import java.io.ByteArrayOutputStream
import java.net.InetAddress

internal object DnsTestData {
    data class Answer(val type: Int, val ttl: Long, val data: ByteArray)

    fun response(
        question: String,
        questionType: Int,
        answers: List<Answer>,
        rcode: Int = 0
    ): ByteArray {
        val out = ByteArrayOutputStream()
        writeU16(out, 0)
        writeU16(out, 0x8180 or rcode)
        writeU16(out, 1)
        writeU16(out, answers.size)
        writeU16(out, 0)
        writeU16(out, 0)
        out.write(encodeName(question))
        writeU16(out, questionType)
        writeU16(out, DnsWire.CLASS_IN)
        for (answer in answers) {
            out.write(0xc0)
            out.write(0x0c)
            writeU16(out, answer.type)
            writeU16(out, DnsWire.CLASS_IN)
            writeU32(out, answer.ttl)
            writeU16(out, answer.data.size)
            out.write(answer.data)
        }
        return out.toByteArray()
    }

    fun a(ttl: Long, ipv4: String): Answer {
        val address = InetAddress.getByName(ipv4).address
        return Answer(DnsWire.TYPE_A, ttl, address)
    }

    fun aaaa(ttl: Long, ipv6: String): Answer {
        val address = InetAddress.getByName(ipv6).address
        return Answer(DnsWire.TYPE_AAAA, ttl, address)
    }

    fun https(
        ttl: Long,
        priority: Int,
        target: String,
        port: Int? = null,
        ipv4Hints: List<String> = emptyList(),
        ipv6Hints: List<String> = emptyList()
    ): Answer {
        val data = ByteArrayOutputStream()
        writeU16(data, priority)
        data.write(encodeName(target))
        if (port != null) {
            val value = ByteArrayOutputStream().also { writeU16(it, port) }.toByteArray()
            svcParam(data, 3, value)
        }
        if (ipv4Hints.isNotEmpty()) {
            val value = ByteArrayOutputStream()
            for (hint in ipv4Hints) {
                value.write(InetAddress.getByName(hint).address)
            }
            svcParam(data, 4, value.toByteArray())
        }
        if (ipv6Hints.isNotEmpty()) {
            val value = ByteArrayOutputStream()
            for (hint in ipv6Hints) {
                value.write(InetAddress.getByName(hint).address)
            }
            svcParam(data, 6, value.toByteArray())
        }
        return Answer(DnsWire.TYPE_HTTPS, ttl, data.toByteArray())
    }

    fun aliasHttps(ttl: Long, target: String): Answer {
        return https(ttl, 0, target)
    }

    fun svcParam(out: ByteArrayOutputStream, key: Int, value: ByteArray) {
        writeU16(out, key)
        writeU16(out, value.size)
        out.write(value)
    }

    fun encodeName(name: String): ByteArray {
        if (name == "." || name.isEmpty()) {
            return byteArrayOf(0)
        }
        val out = ByteArrayOutputStream()
        for (label in name.trimEnd('.').split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.write(bytes.size)
            out.write(bytes)
        }
        out.write(0)
        return out.toByteArray()
    }

    fun ip4p(port: Int, ipv4: String): ByteArray {
        val bytes = ByteArray(16)
        bytes[0] = 0x20
        bytes[1] = 0x01
        bytes[10] = ((port shr 8) and 0xff).toByte()
        bytes[11] = (port and 0xff).toByte()
        val address = InetAddress.getByName(ipv4).address
        address.copyInto(bytes, 12)
        return bytes
    }

    private fun writeU16(out: ByteArrayOutputStream, value: Int) {
        out.write((value shr 8) and 0xff)
        out.write(value and 0xff)
    }

    private fun writeU32(out: ByteArrayOutputStream, value: Long) {
        out.write(((value shr 24) and 0xff).toInt())
        out.write(((value shr 16) and 0xff).toInt())
        out.write(((value shr 8) and 0xff).toInt())
        out.write((value and 0xff).toInt())
    }
}
