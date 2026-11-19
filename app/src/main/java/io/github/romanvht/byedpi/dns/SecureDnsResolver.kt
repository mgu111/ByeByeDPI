package io.github.romanvht.byedpi.dns

import android.os.Build
import android.util.Log
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URL
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Настройки DNS, которые передаются в нативный процесс.
 *
 * mode: "system" | "udp" | "doh" | "dot"
 * server:
 *   udp -> "1.1.1.1" или "1.1.1.1:53"
 *   doh -> "https://1.1.1.1/dns-query" (хост лучше задавать IP-адресом, чтобы не нужен был bootstrap)
 *   dot -> "1.1.1.1" или "dns.google@8.8.8.8" (имя для проверки сертификата @ IP для подключения)
 * fallback: запасной сервер в том же формате (опционально)
 * hosts: строки "домен ip" (по одной на строку), имеют приоритет над DNS
 * viaProxy: пускать DoH/DoT через SOCKS5 ByeDPI, чтобы к DNS-серверу применялся обход DPI
 */
data class DnsSettings(
    val mode: String = "system",
    val server: String = "",
    val fallback: String = "",
    val hosts: String = "",
    val ipv4Only: Boolean = true,
    val viaProxy: Boolean = true,
) {
    val secure: Boolean get() = mode != "system"
}

class SecureDnsResolver(
    private val settings: DnsSettings,
    private val proxyHost: String,
    private val proxyPort: Int,
) {
    companion object {
        private const val TAG = "SecureDnsResolver"
        private const val TIMEOUT_MS = 5000
        private const val MIN_TTL = 30
        private const val MAX_TTL = 3600
        private const val MAX_CACHE = 2000
        private val random = SecureRandom()
    }

    private class CacheEntry(val addresses: List<InetAddress>, val expires: Long)

    private val cache = ConcurrentHashMap<String, CacheEntry>()
    private val hosts: Map<String, InetAddress> = parseHosts(settings.hosts)

    /** Возвращает IPv4-адреса домена (при ipv4Only=false добавляются и IPv6). Бросает исключение, если не удалось. */
    fun resolve(rawName: String): List<InetAddress> {
        val name = rawName.trim().trimEnd('.').lowercase()
        require(name.isNotEmpty()) { "empty name" }

        hosts[name]?.let { return listOf(it) }

        val now = System.currentTimeMillis()
        cache[name]?.let { if (it.expires > now) return it.addresses }

        val servers = listOf(settings.server, settings.fallback).filter { it.isNotBlank() }
        var lastError: Exception? = null
        for (server in servers) {
            try {
                val result = queryServer(server, name)
                if (result.first.isNotEmpty()) {
                    store(name, result.first, result.second)
                    return result.first
                }
            } catch (e: Exception) {
                Log.w(TAG, "DNS server $server failed for $name: ${e.message}")
                lastError = e
            }
        }
        throw lastError ?: java.net.UnknownHostException(name)
    }

    private fun store(name: String, addresses: List<InetAddress>, ttl: Int) {
        if (cache.size > MAX_CACHE) cache.clear()
        val seconds = ttl.coerceIn(MIN_TTL, MAX_TTL)
        cache[name] = CacheEntry(addresses, System.currentTimeMillis() + seconds * 1000L)
    }

    private fun queryServer(server: String, name: String): Pair<List<InetAddress>, Int> {
        val addresses = ArrayList<InetAddress>()
        var ttl = MAX_TTL
        val types = if (settings.ipv4Only) listOf(1) else listOf(1, 28)
        var error: Exception? = null
        for (type in types) {
            try {
                val query = buildQuery(name, type)
                val response = when (settings.mode) {
                    "doh" -> queryDoh(server, query)
                    "dot" -> queryDot(server, query)
                    else -> queryUdp(server, query)
                }
                val parsed = parseResponse(response, type)
                addresses.addAll(parsed.first)
                if (parsed.first.isNotEmpty()) ttl = minOf(ttl, parsed.second)
            } catch (e: Exception) {
                error = e
            }
        }
        if (addresses.isEmpty() && error != null) throw error
        return addresses to ttl
    }

    // ---------- транспорты ----------

    private fun proxy(): Proxy =
        if (settings.viaProxy && proxyPort > 0)
            Proxy(Proxy.Type.SOCKS, InetSocketAddress(proxyHost, proxyPort))
        else Proxy.NO_PROXY

    private fun queryDoh(server: String, query: ByteArray): ByteArray {
        val url = URL(server)
        val connection = url.openConnection(proxy()) as HttpURLConnection
        try {
            connection.connectTimeout = TIMEOUT_MS
            connection.readTimeout = TIMEOUT_MS
            connection.requestMethod = "POST"
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/dns-message")
            connection.setRequestProperty("Accept", "application/dns-message")
            connection.setFixedLengthStreamingMode(query.size)
            connection.outputStream.use { it.write(query) }
            if (connection.responseCode != 200) throw java.io.IOException("DoH HTTP ${connection.responseCode}")
            return connection.inputStream.use { it.readBytes() }
        } finally {
            connection.disconnect()
        }
    }

    private fun queryDot(server: String, query: ByteArray): ByteArray {
        val sni = if ('@' in server) server.substringBefore('@') else null
        val (host, port) = splitHostPort(server.substringAfter('@'), 853)
        val verifyName = sni ?: host

        val raw = Socket(proxy())
        try {
            raw.soTimeout = TIMEOUT_MS
            raw.connect(InetSocketAddress(host, port), TIMEOUT_MS)
            val factory = javax.net.ssl.SSLSocketFactory.getDefault() as SSLSocketFactory
            val ssl = factory.createSocket(raw, verifyName, port, true) as SSLSocket
            val params = SSLParameters()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N && !isIpLiteral(verifyName)) {
                params.serverNames = listOf(SNIHostName(verifyName))
            }
            ssl.sslParameters = params
            ssl.startHandshake()
            val verifier = HttpsURLConnection.getDefaultHostnameVerifier()
            if (!verifier.verify(verifyName, ssl.session)) throw javax.net.ssl.SSLPeerUnverifiedException("DoT host mismatch")

            val out = DataOutputStream(ssl.outputStream)
            out.writeShort(query.size)
            out.write(query)
            out.flush()
            val input = DataInputStream(ssl.inputStream)
            val length = input.readUnsignedShort()
            val response = ByteArray(length)
            input.readFully(response)
            return response
        } finally {
            try { raw.close() } catch (_: Exception) {}
        }
    }

    private fun queryUdp(server: String, query: ByteArray): ByteArray {
        val (host, port) = splitHostPort(server, 53)
        DatagramSocket().use { socket ->
            socket.soTimeout = TIMEOUT_MS
            socket.connect(InetSocketAddress(host, port))
            socket.send(DatagramPacket(query, query.size))
            val buffer = ByteArray(4096)
            val packet = DatagramPacket(buffer, buffer.size)
            socket.receive(packet)
            return buffer.copyOf(packet.length)
        }
    }

    // ---------- формат DNS ----------

    private fun buildQuery(name: String, type: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val data = DataOutputStream(out)
        data.writeShort(random.nextInt(0x10000)) // id
        data.writeShort(0x0100)                  // recursion desired
        data.writeShort(1)                       // QDCOUNT
        data.writeShort(0)
        data.writeShort(0)
        data.writeShort(0)
        for (label in name.split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            require(bytes.size in 1..63) { "bad label" }
            data.writeByte(bytes.size)
            data.write(bytes)
        }
        data.writeByte(0)
        data.writeShort(type)
        data.writeShort(1) // IN
        return out.toByteArray()
    }

    /** Возвращает (адреса нужного типа, минимальный TTL). */
    private fun parseResponse(r: ByteArray, wantedType: Int): Pair<List<InetAddress>, Int> {
        require(r.size >= 12) { "short response" }
        val rcode = r[3].toInt() and 0x0F
        if (rcode != 0) throw java.net.UnknownHostException("rcode=$rcode")
        val qd = u16(r, 4)
        val an = u16(r, 6)
        var pos = 12
        repeat(qd) { pos = skipName(r, pos) + 4 }
        val result = ArrayList<InetAddress>()
        var ttl = MAX_TTL
        repeat(an) {
            pos = skipName(r, pos)
            val type = u16(r, pos)
            val recordTtl = u32(r, pos + 4)
            val length = u16(r, pos + 8)
            pos += 10
            if (type == wantedType && ((type == 1 && length == 4) || (type == 28 && length == 16))) {
                result.add(InetAddress.getByAddress(r.copyOfRange(pos, pos + length)))
                ttl = minOf(ttl, recordTtl.coerceAtMost(Int.MAX_VALUE.toLong()).toInt())
            }
            pos += length
        }
        return result to ttl
    }

    private fun skipName(r: ByteArray, start: Int): Int {
        var pos = start
        while (true) {
            val length = r[pos].toInt() and 0xFF
            if (length == 0) return pos + 1
            if (length and 0xC0 == 0xC0) return pos + 2
            pos += length + 1
        }
    }

    private fun u16(r: ByteArray, p: Int) = ((r[p].toInt() and 0xFF) shl 8) or (r[p + 1].toInt() and 0xFF)
    private fun u32(r: ByteArray, p: Int) =
        (u16(r, p).toLong() shl 16) or u16(r, p + 2).toLong()

    /** "host", "host:port" или "[v6]:port" -> (host, port). Голый IPv6 без скобок считается хостом. */
    private fun splitHostPort(spec: String, defaultPort: Int): Pair<String, Int> {
        if (spec.startsWith("[")) {
            val end = spec.indexOf(']')
            val host = spec.substring(1, end)
            val port = spec.substring(end + 1).removePrefix(":").toIntOrNull() ?: defaultPort
            return host to port
        }
        if (spec.count { it == ':' } == 1) {
            return spec.substringBefore(':') to (spec.substringAfter(':').toIntOrNull() ?: defaultPort)
        }
        return spec to defaultPort
    }

    private fun isIpLiteral(value: String) =
        value.matches(Regex("^[0-9.]+$")) || ':' in value

    private fun parseHosts(text: String): Map<String, InetAddress> {
        val map = HashMap<String, InetAddress>()
        for (line in text.lines()) {
            val parts = line.substringBefore('#').trim().split(Regex("\\s+"))
            if (parts.size < 2) continue
            val (domain, ip) = parts[0].lowercase() to parts[1]
            if (!isIpLiteral(ip)) continue
            try { map[domain] = InetAddress.getByName(ip) } catch (_: Exception) {}
        }
        return map
    }
}
