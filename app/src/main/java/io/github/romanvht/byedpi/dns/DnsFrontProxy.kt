package io.github.romanvht.byedpi.dns

import android.util.Log
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors

/**
 * Локальный SOCKS5-прокси между hev-socks5-tunnel и ByeDPI.
 *
 * hev (режим mapdns) сам отвечает приложениям поддельными IP и присылает сюда CONNECT с именем домена.
 * Здесь имя резолвится через DoH/DoT, и дальше ByeDPI получает CONNECT уже с настоящим IP.
 * DPI-обход ByeDPI от этого не меняется: он смотрит на SNI в TLS, а не на способ получения IP.
 *
 * UDP ASSOCIATE отклоняется: приложения (в том числе YouTube) откатываются с QUIC на TCP.
 */
class DnsFrontProxy(
    private val resolver: SecureDnsResolver,
    private val upstreamHost: String,
    private val upstreamPort: Int,
) {
    companion object {
        private const val TAG = "DnsFrontProxy"
        private const val CONNECT_TIMEOUT_MS = 10_000
    }

    private val pool = Executors.newCachedThreadPool()
    private var server: ServerSocket? = null
    @Volatile private var running = false

    /** Запускает прокси и возвращает порт, на котором он слушает (127.0.0.1). */
    fun start(): Int {
        val socket = ServerSocket()
        socket.reuseAddress = true
        socket.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
        server = socket
        running = true
        pool.execute {
            while (running) {
                try {
                    val client = socket.accept()
                    pool.execute { handle(client) }
                } catch (e: IOException) {
                    if (running) Log.w(TAG, "accept failed: ${e.message}")
                }
            }
        }
        return socket.localPort
    }

    fun stop() {
        running = false
        try { server?.close() } catch (_: IOException) {}
        pool.shutdownNow()
    }

    private fun handle(client: Socket) {
        var upstream: Socket? = null
        try {
            client.tcpNoDelay = true
            client.soTimeout = CONNECT_TIMEOUT_MS
            val input = client.getInputStream()
            val output = client.getOutputStream()

            // --- приветствие клиента ---
            if (input.readByteStrict() != 5) return
            val methods = input.readByteStrict()
            input.skipFully(methods)
            output.write(byteArrayOf(5, 0))
            output.flush()

            // --- запрос ---
            val header = ByteArray(4)
            input.readFully(header)
            if (header[0].toInt() != 5) return
            val command = header[1].toInt()
            val addressType = header[3].toInt()

            val host: String?
            val addressBytes: ByteArray?
            when (addressType) {
                1 -> { addressBytes = ByteArray(4).also { input.readFully(it) }; host = null }
                4 -> { addressBytes = ByteArray(16).also { input.readFully(it) }; host = null }
                3 -> {
                    val length = input.readByteStrict()
                    val raw = ByteArray(length).also { input.readFully(it) }
                    host = String(raw, Charsets.US_ASCII)
                    addressBytes = null
                }
                else -> { reply(output, 8); return }
            }
            val portBytes = ByteArray(2).also { input.readFully(it) }
            val port = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)

            if (command != 1) { // только CONNECT
                reply(output, 7)
                return
            }

            val target: InetAddress = try {
                if (host != null) {
                    val all = resolver.resolve(host)
                    all.firstOrNull { it.address.size == 4 } ?: all.first()
                } else InetAddress.getByAddress(addressBytes!!)
            } catch (e: Exception) {
                Log.w(TAG, "resolve failed for $host: ${e.message}")
                reply(output, 4)
                return
            }

            // --- подключение к ByeDPI как SOCKS5-клиент ---
            upstream = Socket()
            upstream.tcpNoDelay = true
            upstream.connect(InetSocketAddress(upstreamHost, upstreamPort), CONNECT_TIMEOUT_MS)
            upstream.soTimeout = CONNECT_TIMEOUT_MS
            val upIn = upstream.getInputStream()
            val upOut = upstream.getOutputStream()

            upOut.write(byteArrayOf(5, 1, 0))
            upOut.flush()
            val auth = ByteArray(2).also { upIn.readFully(it) }
            if (auth[0].toInt() != 5 || auth[1].toInt() != 0) { reply(output, 1); return }

            val raw = target.address
            val request = ByteArray(4 + raw.size + 2)
            request[0] = 5
            request[1] = 1
            request[3] = if (raw.size == 4) 1 else 4
            System.arraycopy(raw, 0, request, 4, raw.size)
            request[4 + raw.size] = portBytes[0]
            request[5 + raw.size] = portBytes[1]
            upOut.write(request)
            upOut.flush()

            // ответ ByeDPI: пересылаем клиенту как есть
            val replyHead = ByteArray(4).also { upIn.readFully(it) }
            val replyType = replyHead[3].toInt()
            val addressLength = when (replyType) {
                1 -> 4
                4 -> 16
                3 -> upIn.readByteStrict()
                else -> 0
            }
            val replyTail = ByteArray(addressLength + 2).also { upIn.readFully(it) }
            output.write(replyHead)
            if (replyType == 3) output.write(addressLength)
            output.write(replyTail)
            output.flush()
            if (replyHead[1].toInt() != 0) return

            // --- двусторонняя пересылка ---
            client.soTimeout = 0
            upstream.soTimeout = 0
            val finalUpstream = upstream
            val forward = Thread { pipe(input, upOut, finalUpstream, client) }
            forward.isDaemon = true
            forward.start()
            pipe(upIn, output, client, finalUpstream)
            forward.join(1000)
        } catch (e: Exception) {
            Log.d(TAG, "connection closed: ${e.message}")
        } finally {
            try { upstream?.close() } catch (_: IOException) {}
            try { client.close() } catch (_: IOException) {}
        }
    }

    private fun pipe(from: InputStream, to: OutputStream, toSocket: Socket, fromSocket: Socket) {
        val buffer = ByteArray(16 * 1024)
        try {
            while (true) {
                val count = from.read(buffer)
                if (count < 0) break
                to.write(buffer, 0, count)
                to.flush()
            }
        } catch (_: IOException) {
        } finally {
            try { toSocket.shutdownOutput() } catch (_: IOException) {}
            try { fromSocket.shutdownInput() } catch (_: IOException) {}
        }
    }

    private fun reply(output: OutputStream, code: Int) {
        output.write(byteArrayOf(5, code.toByte(), 0, 1, 0, 0, 0, 0, 0, 0))
        output.flush()
    }

    private fun InputStream.readByteStrict(): Int {
        val value = read()
        if (value < 0) throw IOException("eof")
        return value
    }

    private fun InputStream.readFully(buffer: ByteArray) {
        var offset = 0
        while (offset < buffer.size) {
            val count = read(buffer, offset, buffer.size - offset)
            if (count < 0) throw IOException("eof")
            offset += count
        }
    }

    private fun InputStream.skipFully(count: Int) {
        if (count > 0) readFully(ByteArray(count))
    }
}
