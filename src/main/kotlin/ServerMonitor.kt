package org.example

import kotlinx.serialization.Serializable
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import kotlin.math.roundToLong

@Serializable
data class ServerStatus(
    val id: Long,
    val name: String,
    val location: String,
    val hostReachable: Boolean,
    val latencyMs: Long?,
    val checkedAt: Long,
    val probeUrl: String?,
    val pingReachable: Boolean?,
    val pingLatencyMs: Long?
)

class ServerMonitor {
    private data class Sample(
        val host: String,
        val port: Int,
        val checkedAt: Long,
        val sshMs: Long?,
        val ping: PingResult
    )

    private val cache = ConcurrentHashMap<Long, Sample>()

    fun check(server: Server): ServerStatus {
        val (host, port) = server.connection.let { it.host to it.port }
        val sample = cache.compute(server.id) { _, cached ->
            val now = System.currentTimeMillis()
            if (cached != null && cached.host == host && cached.port == port &&
                now - cached.checkedAt in 0 until 25_000
            ) cached else measure(host, port)
        }!!
        return ServerStatus(
            server.id, server.name, server.location, sample.sshMs != null, sample.sshMs,
            sample.checkedAt, browserProbeUrl(host), sample.ping.reachable, sample.ping.latencyMs
        )
    }

    private fun measure(host: String, port: Int): Sample {
        val address = try {
            InetAddress.getByName(host)
        } catch (_: IOException) {
            return Sample(host, port, System.currentTimeMillis(), null, PingResult(null))
        }
        val started = System.nanoTime()
        val sshMs = try {
            Socket().use { it.connect(InetSocketAddress(address, port), 2_500) }
            (System.nanoTime() - started) / 1_000_000
        } catch (_: IOException) {
            null
        }
        val ping = ping(address)
        return Sample(host, port, System.currentTimeMillis(), sshMs, ping)
    }

    private data class PingResult(val reachable: Boolean?, val latencyMs: Long? = null)

    private fun ping(address: InetAddress): PingResult {
        val process = try {
            ProcessBuilder("ping", "-n", "-c", "1", "-W", "1", "-w", "2", "--", address.hostAddress)
                .redirectErrorStream(true)
                .apply { environment()["LC_ALL"] = "C" }
                .start()
        } catch (_: IOException) {
            return PingResult(null)
        }
        try {
            if (!process.waitFor(3, TimeUnit.SECONDS)) return PingResult(null)
            return when (process.exitValue()) {
                0 -> {
                    val output = process.inputStream.bufferedReader().use { it.readText() }
                    val ms = pingTime.find(output)?.groupValues?.get(1)?.toDoubleOrNull()?.roundToLong()
                    PingResult(true, ms)
                }
                1 -> PingResult(false)
                else -> PingResult(null)
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            return PingResult(null)
        } finally {
            if (process.isAlive) process.destroyForcibly()
            process.inputStream.close()
        }
    }

    private companion object {
        val pingTime = Regex("""time[=<]([0-9]+(?:\.[0-9]+)?)\s*ms""")
    }
}

internal fun browserProbeUrl(host: String): String? {
    val octets = host.split('.').map { part ->
        if (part.length !in 1..3 || part.any { it !in '0'..'9' }) return null
        part.toInt().takeIf { it in 0..255 && it.toString() == part } ?: return null
    }
    if (octets.size != 4) return null
    val (a, b, c) = octets
    // Do not direct a user's browser to non-public networks or infrastructure addresses.
    if (a !in 1..223 || a in setOf(10, 127) || a == 100 && b in 64..127 ||
        a == 169 && b == 254 || a == 172 && b in 16..31 ||
        a == 192 && (b == 168 || b == 0 && c in setOf(0, 2)) ||
        a == 198 && (b in 18..19 || b == 51 && c == 100) ||
        a == 203 && b == 0 && c == 113
    ) return null
    return "https://${octets.joinToString("-")}.sslip.io/_inoagent/health"
}
