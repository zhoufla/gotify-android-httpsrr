package com.github.gotify.dns

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

internal class DnsFormatException(message: String) : IOException(message)

internal data class DnsMessage(val rcode: Int, val truncated: Boolean, val answers: List<DnsRecord>)

internal sealed class DnsRecord {
    abstract val name: String
    abstract val ttlSeconds: Long

    data class A(
        override val name: String,
        override val ttlSeconds: Long,
        val address: Inet4Address
    ) : DnsRecord()

    data class Aaaa(
        override val name: String,
        override val ttlSeconds: Long,
        val address: Inet6Address
    ) : DnsRecord()

    data class Https(
        override val name: String,
        override val ttlSeconds: Long,
        val binding: HttpsBinding
    ) : DnsRecord()
}

internal data class HttpsBinding(
    val priority: Int,
    val target: String,
    val port: Int?,
    val ipv4Hints: List<Inet4Address>,
    val ipv6Hints: List<Inet6Address>,
    val ttlSeconds: Long
) {
    val isAlias: Boolean get() = priority == 0
    val targetIsOwner: Boolean get() = target == "." || target.isEmpty()
}

/**
 * Minimal DNS wire encoder/decoder for A, AAAA and HTTPS (RFC 9460) records.
 * The system resolver is used as transport, so no third-party DNS library is
 * needed.
 */
internal object DnsWire {
    const val TYPE_A = 1
    const val TYPE_AAAA = 28
    const val TYPE_HTTPS = 65
    const val CLASS_IN = 1

    fun query(host: String, type: Int): ByteArray {
        val name = encodeName(host)
        val out = ByteArrayOutputStream(name.size + 16)
        val id = (System.nanoTime() and 0xffff).toInt()
        out.write(id shr 8)
        out.write(id and 0xff)
        out.write(0x01) // recursion desired
        out.write(0x00)
        out.write(0)
        out.write(1) // one question
        repeat(6) { out.write(0) }
        out.write(name)
        out.write(type shr 8)
        out.write(type and 0xff)
        out.write(CLASS_IN shr 8)
        out.write(CLASS_IN and 0xff)
        return out.toByteArray()
    }

    fun parse(bytes: ByteArray): DnsMessage {
        if (bytes.size < 12) {
            throw DnsFormatException("DNS message is too short")
        }
        val flags = u16(bytes, 2)
        if (flags and 0x8000 == 0) {
            throw DnsFormatException("DNS message is not a response")
        }
        val truncated = flags and 0x0200 != 0
        val rcode = flags and 0x000f
        if (truncated) {
            return DnsMessage(rcode = rcode, truncated = true, answers = emptyList())
        }

        val questionCount = u16(bytes, 4)
        val answerCount = u16(bytes, 6)
        val authorityCount = u16(bytes, 8)
        val additionalCount = u16(bytes, 10)
        if (questionCount > 64 ||
            answerCount > 1024 ||
            authorityCount > 1024 ||
            additionalCount > 1024
        ) {
            throw DnsFormatException("DNS message has too many records")
        }

        var position = 12
        repeat(questionCount) {
            val question = readName(bytes, position)
            position = question.next
            if (position + 4 > bytes.size) {
                throw DnsFormatException("DNS question is truncated")
            }
            position += 4
        }

        val answers = mutableListOf<DnsRecord>()
        repeat(answerCount) {
            val result = readRecord(bytes, position)
            position = result.next
            result.record?.let { answers.add(it) }
        }
        repeat(authorityCount + additionalCount) {
            val result = readRecord(bytes, position)
            position = result.next
        }
        return DnsMessage(rcode = rcode, truncated = false, answers = answers)
    }

    private fun readRecord(bytes: ByteArray, start: Int): RecordResult {
        val name = readName(bytes, start)
        var position = name.next
        if (position + 10 > bytes.size) {
            throw DnsFormatException("DNS record header is truncated")
        }
        val type = u16(bytes, position)
        val recordClass = u16(bytes, position + 2)
        val ttl = u32(bytes, position + 4)
        val length = u16(bytes, position + 8)
        position += 10
        if (position + length > bytes.size) {
            throw DnsFormatException("DNS record data is truncated")
        }
        val dataStart = position
        val dataEnd = position + length

        val record = when {
            type == TYPE_A && recordClass == CLASS_IN -> {
                if (length != 4) {
                    throw DnsFormatException("A record has invalid length")
                }
                DnsRecord.A(
                    name = name.value,
                    ttlSeconds = ttl,
                    address = InetAddress.getByAddress(
                        bytes.copyOfRange(dataStart, dataEnd)
                    ) as Inet4Address
                )
            }
            type == TYPE_AAAA && recordClass == CLASS_IN -> {
                if (length != 16) {
                    throw DnsFormatException("AAAA record has invalid length")
                }
                DnsRecord.Aaaa(
                    name = name.value,
                    ttlSeconds = ttl,
                    address = InetAddress.getByAddress(
                        bytes.copyOfRange(dataStart, dataEnd)
                    ) as Inet6Address
                )
            }
            type == TYPE_HTTPS && recordClass == CLASS_IN -> {
                DnsRecord.Https(
                    name = name.value,
                    ttlSeconds = ttl,
                    binding = parseHttps(bytes, dataStart, dataEnd, ttl)
                )
            }
            else -> null
        }
        return RecordResult(record, dataEnd)
    }

    private fun parseHttps(bytes: ByteArray, start: Int, end: Int, ttl: Long): HttpsBinding {
        if (start + 2 > end) {
            throw DnsFormatException("HTTPS record is truncated")
        }
        val priority = u16(bytes, start)
        val target = readName(bytes, start + 2)
        if (target.next > end) {
            throw DnsFormatException("HTTPS target is truncated")
        }

        var port: Int? = null
        val ipv4Hints = mutableListOf<Inet4Address>()
        val ipv6Hints = mutableListOf<Inet6Address>()
        var position = target.next
        var previousKey = -1
        while (position < end) {
            if (position + 4 > end) {
                throw DnsFormatException("SvcParam header is truncated")
            }
            val key = u16(bytes, position)
            val length = u16(bytes, position + 2)
            position += 4
            if (key <= previousKey) {
                throw DnsFormatException("SvcParam keys are not strictly increasing")
            }
            if (position + length > end) {
                throw DnsFormatException("SvcParam value is truncated")
            }
            val valueStart = position
            val valueEnd = position + length
            when (key) {
                3 -> {
                    if (length != 2) {
                        throw DnsFormatException("port SvcParam has invalid length")
                    }
                    val value = u16(bytes, valueStart)
                    if (value != 0) {
                        port = value
                    }
                }
                4 -> {
                    if (length == 0 || length % 4 != 0) {
                        throw DnsFormatException("ipv4hint SvcParam has invalid length")
                    }
                    var hint = valueStart
                    while (hint < valueEnd) {
                        ipv4Hints.add(
                            InetAddress.getByAddress(
                                bytes.copyOfRange(hint, hint + 4)
                            ) as Inet4Address
                        )
                        hint += 4
                    }
                }
                6 -> {
                    if (length == 0 || length % 16 != 0) {
                        throw DnsFormatException("ipv6hint SvcParam has invalid length")
                    }
                    var hint = valueStart
                    while (hint < valueEnd) {
                        ipv6Hints.add(
                            InetAddress.getByAddress(
                                bytes.copyOfRange(hint, hint + 16)
                            ) as Inet6Address
                        )
                        hint += 16
                    }
                }
            }
            previousKey = key
            position = valueEnd
        }
        if (position != end) {
            throw DnsFormatException("HTTPS record has trailing data")
        }
        return HttpsBinding(
            priority = priority,
            target = target.value.ifEmpty { "." },
            port = port,
            ipv4Hints = ipv4Hints,
            ipv6Hints = ipv6Hints,
            ttlSeconds = ttl
        )
    }

    private data class NameResult(val value: String, val next: Int)

    private data class RecordResult(val record: DnsRecord?, val next: Int)

    private fun readName(bytes: ByteArray, start: Int): NameResult {
        var position = start
        var next = -1
        var jumps = 0
        val labels = mutableListOf<String>()
        while (true) {
            if (position >= bytes.size) {
                throw DnsFormatException("DNS name is truncated")
            }
            val length = bytes[position].toInt() and 0xff
            when {
                length == 0 -> {
                    position++
                    if (next < 0) {
                        next = position
                    }
                    break
                }
                length and 0xc0 == 0xc0 -> {
                    if (position + 1 >= bytes.size) {
                        throw DnsFormatException("DNS compression pointer is truncated")
                    }
                    val pointer = ((bytes[position].toInt() and 0x3f) shl 8) or
                        (bytes[position + 1].toInt() and 0xff)
                    if (next < 0) {
                        next = position + 2
                    }
                    if (pointer >= bytes.size) {
                        throw DnsFormatException("DNS compression pointer is out of range")
                    }
                    jumps++
                    if (jumps > 16) {
                        throw DnsFormatException("DNS compression pointer loop")
                    }
                    position = pointer
                }
                length and 0xc0 != 0 -> throw DnsFormatException("Invalid DNS label length")
                else -> {
                    if (length > 63 || position + 1 + length > bytes.size) {
                        throw DnsFormatException("DNS label is truncated")
                    }
                    labels.add(String(bytes, position + 1, length, Charsets.US_ASCII))
                    position += length + 1
                }
            }
        }
        return NameResult(labels.joinToString("."), next)
    }

    private fun encodeName(host: String): ByteArray {
        val name = host.trimEnd('.')
        val out = ByteArrayOutputStream()
        if (name.isEmpty()) {
            out.write(0)
            return out.toByteArray()
        }
        for (label in name.split('.')) {
            if (label.isEmpty() || label.length > 63) {
                throw IllegalArgumentException("Invalid DNS label: $label")
            }
            val encoded = label.toByteArray(Charsets.US_ASCII)
            if (encoded.size > 63) {
                throw IllegalArgumentException("Invalid DNS label: $label")
            }
            out.write(encoded.size)
            out.write(encoded)
        }
        out.write(0)
        return out.toByteArray()
    }

    private fun u16(bytes: ByteArray, offset: Int): Int {
        if (offset + 2 > bytes.size) {
            throw DnsFormatException("DNS message is truncated")
        }
        return ((bytes[offset].toInt() and 0xff) shl 8) or
            (bytes[offset + 1].toInt() and 0xff)
    }

    private fun u32(bytes: ByteArray, offset: Int): Long {
        if (offset + 4 > bytes.size) {
            throw DnsFormatException("DNS message is truncated")
        }
        return ((bytes[offset].toLong() and 0xff) shl 24) or
            ((bytes[offset + 1].toLong() and 0xff) shl 16) or
            ((bytes[offset + 2].toLong() and 0xff) shl 8) or
            (bytes[offset + 3].toLong() and 0xff)
    }
}
