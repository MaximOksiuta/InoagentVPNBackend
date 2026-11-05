package org.example

import kotlinx.serialization.Serializable
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap

@Serializable data class ServerStatus(val id: Long, val name: String, val location: String, val hostReachable: Boolean, val latencyMs: Long?, val checkedAt: Long, val probeUrl: String?)

class ServerMonitor {
    private val cache = ConcurrentHashMap<Long, ServerStatus>()
    fun check(server: Server): ServerStatus {
        val now = System.currentTimeMillis()
        cache[server.id]?.takeIf { now - it.checkedAt < 25_000 }?.let { return it }
        val started = System.nanoTime()
        val up = runCatching { Socket().use { it.connect(InetSocketAddress(server.connection.host, server.connection.port), 2500) } }.isSuccess
        val host = server.connection.host
        // Only explicitly provisioned HTTPS endpoints can be tested by browsers.
        val configured = System.getenv("SERVER_PROBE_HOSTS").orEmpty().split(',').map(String::trim)
        val probe = if (host in configured && host.matches(Regex("[0-9.]+"))) "https://${host.replace('.', '-')}.sslip.io/_inoagent/health" else null
        return ServerStatus(server.id, server.name, server.location, up, if (up) (System.nanoTime() - started) / 1_000_000 else null, now, probe).also { cache[server.id] = it }
    }
}
