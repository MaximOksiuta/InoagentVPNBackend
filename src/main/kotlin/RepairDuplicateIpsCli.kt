package org.example

import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.connection.channel.direct.Session
import net.schmizz.sshj.transport.verification.PromiscuousVerifier
import java.util.Base64

private const val DEFAULT_REPAIR_SQLITE_PATH = "data/app.db"

data class RepairDuplicateIpsCommand(
    val databasePath: String,
    val serverIds: Set<Long>,
    val dryRun: Boolean
)

data class RepairDuplicateIpsSummary(
    val inspectedServers: Int,
    val changedServers: Int,
    val changedPeers: Int,
    val updatedConfigs: Int,
    val warnings: List<String>
)

fun main(args: Array<String>) {
    val command = RepairDuplicateIpsCli.parse(args)
    val result = RepairDuplicateIpsCli.execute(command)

    println(
        buildString {
            append("Inspected servers: ").append(result.inspectedServers)
            append(", changed servers: ").append(result.changedServers)
            append(", changed peers: ").append(result.changedPeers)
            append(", updated DB configs: ").append(result.updatedConfigs)
            if (command.dryRun) append(" (dry-run)")
        }
    )
    result.warnings.forEach { println("WARNING: $it") }
}

object RepairDuplicateIpsCli {
    fun parse(args: Array<String>): RepairDuplicateIpsCommand {
        if (args.any { it == "--help" || it == "-h" }) {
            error(usage())
        }

        var databasePath = System.getenv("SQLITE_PATH")?.takeIf { it.isNotBlank() } ?: DEFAULT_REPAIR_SQLITE_PATH
        val serverIds = linkedSetOf<Long>()
        var dryRun = false

        var index = 0
        while (index < args.size) {
            when (val arg = args[index]) {
                "--db", "--database", "--sqlite-path" -> {
                    databasePath = args.getOrNull(++index)?.takeIf { it.isNotBlank() }
                        ?: error("Missing value for $arg\n${usage()}")
                }

                "--server-id" -> {
                    val serverId = args.getOrNull(++index)?.toLongOrNull()
                        ?: error("Missing or invalid value for --server-id\n${usage()}")
                    require(serverId > 0) { "Server id must be positive" }
                    serverIds += serverId
                }

                "--dry-run" -> dryRun = true

                else -> error("Unknown argument: $arg\n${usage()}")
            }
            index++
        }

        return RepairDuplicateIpsCommand(
            databasePath = databasePath,
            serverIds = serverIds,
            dryRun = dryRun
        )
    }

    fun execute(command: RepairDuplicateIpsCommand): RepairDuplicateIpsSummary {
        val databaseFactory = DatabaseFactory(command.databasePath)
        databaseFactory.initialize()

        val serverRepository = SqliteServerRepository(databaseFactory)

        val servers = serverRepository.listServers()
            .filter { command.serverIds.isEmpty() || it.id in command.serverIds }

        if (command.serverIds.isNotEmpty() && servers.size != command.serverIds.size) {
            val foundIds = servers.mapTo(mutableSetOf(), Server::id)
            val missing = command.serverIds.filterNot(foundIds::contains)
            error("Server(s) not found: ${missing.joinToString(", ")}")
        }

        var changedServers = 0
        var changedPeers = 0
        var updatedConfigs = 0
        val warnings = mutableListOf<String>()

        for (server in servers) {
            val repair = DuplicateIpRepairService(databaseFactory).repairServer(server, command.dryRun)
            if (repair.changedPeers > 0) {
                changedServers += 1
                changedPeers += repair.changedPeers
                updatedConfigs += repair.updatedConfigs
            }
            warnings += repair.warnings
        }

        return RepairDuplicateIpsSummary(
            inspectedServers = servers.size,
            changedServers = changedServers,
            changedPeers = changedPeers,
            updatedConfigs = updatedConfigs,
            warnings = warnings
        )
    }

    fun usage(): String {
        return """
            Usage:
              repair_duplicate_ips [--db /path/to/app.db] [--server-id 1] [--server-id 2] [--dry-run]

            Options:
              --db            SQLite database path
              --server-id     Repair only one specific server id, may be repeated
              --dry-run       Print what would change without writing to server or database

            Defaults:
              SQLITE_PATH env var or $DEFAULT_REPAIR_SQLITE_PATH is used when --db is omitted
        """.trimIndent()
    }
}

private class DuplicateIpRepairService(
    private val databaseFactory: DatabaseFactory
) {
    fun repairServer(server: Server, dryRun: Boolean): ServerRepairResult {
        val remote = RemoteAwgAccess(server.connection)
        val currentConfig = remote.readServerConfig()
        val plan = DuplicateIpRepairPlanner.plan(currentConfig)
        if (plan.reassignments.isEmpty()) {
            return ServerRepairResult(0, 0, emptyList())
        }

        val warnings = mutableListOf<String>()
        val updatedConfig = DuplicateIpRepairPlanner.applyPeerIpReassignments(currentConfig, plan.reassignments)
        val updatedConfigs = updateStoredConfigs(server.id, plan.reassignments, warnings, dryRun)

        if (!dryRun) {
            remote.writeBackup(currentConfig)
            remote.writeServerConfig(updatedConfig)
            remote.reloadWireGuard()
        }

        return ServerRepairResult(
            changedPeers = plan.reassignments.size,
            updatedConfigs = updatedConfigs,
            warnings = warnings
        )
    }

    private fun updateStoredConfigs(
        serverId: Long,
        reassignments: Map<String, String>,
        warnings: MutableList<String>,
        dryRun: Boolean
    ): Int {
        if (reassignments.isEmpty()) return 0

        return databaseFactory.connection().use { connection ->
            val rows = connection.prepareStatement(
                """
                SELECT id, config
                FROM device_servers
                WHERE server_id = ?
                ORDER BY id ASC
                """.trimIndent()
            ).use { statement ->
                statement.setLong(1, serverId)
                statement.executeQuery().use { resultSet ->
                    buildList {
                        while (resultSet.next()) {
                            add(resultSet.getLong("id") to resultSet.getString("config"))
                        }
                    }
                }
            }

            var updatedCount = 0
            for ((configId, config) in rows) {
                val clientId = AwgConfigClientIdExtractor.extractClientId(config)
                if (clientId.isBlank()) {
                    warnings += "Config id=$configId serverId=$serverId: failed to extract clientId from stored config"
                    continue
                }

                val newIp = reassignments[clientId] ?: continue
                val updatedConfig = DuplicateIpRepairPlanner.replaceClientAddress(config, newIp)
                if (updatedConfig == config) {
                    warnings += "Config id=$configId serverId=$serverId clientId=$clientId: Address line was not updated"
                    continue
                }

                if (!dryRun) {
                    connection.prepareStatement(
                        """
                        UPDATE device_servers
                        SET config = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                        """.trimIndent()
                    ).use { statement ->
                        statement.setString(1, updatedConfig)
                        statement.setLong(2, configId)
                        statement.executeUpdate()
                    }
                }
                updatedCount += 1
            }
            updatedCount
        }
    }
}

private data class ServerRepairResult(
    val changedPeers: Int,
    val updatedConfigs: Int,
    val warnings: List<String>
)

private data class PeerEntry(
    val publicKey: String,
    val presharedKey: String?,
    val allowedIp: String,
    val blockText: String
)

internal data class DuplicateIpRepairPlan(
    val reassignments: LinkedHashMap<String, String>
)

internal object DuplicateIpRepairPlanner {
    private val peerRegex = Regex("""\[Peer\]\n(.*?)(?=\n\[|\z)""", RegexOption.DOT_MATCHES_ALL)
    private val publicKeyRegex = Regex("""^PublicKey\s*=\s*(.+)$""", RegexOption.MULTILINE)
    private val allowedIpRegex = Regex("""^AllowedIPs\s*=\s*([0-9.]+)\/32\s*$""", RegexOption.MULTILINE)
    private val clientAddressRegex = Regex("""(?m)^Address\s*=\s*[0-9.]+/32\s*$""")

    fun plan(config: String): DuplicateIpRepairPlan {
        val subnet = parseInterfaceSubnet(config)
        val peers = parsePeers(config)
        val uniqueIps = linkedSetOf<String>()
        val duplicatePeers = mutableListOf<PeerEntry>()

        for (peer in peers) {
            if (!uniqueIps.add(peer.allowedIp)) {
                duplicatePeers += peer
            }
        }

        if (duplicatePeers.isEmpty()) {
            return DuplicateIpRepairPlan(linkedMapOf())
        }

        val reservedIps = linkedSetOf<String>()
        reservedIps += uniqueIps
        val allocated = linkedMapOf<String, String>()
        for (peer in duplicatePeers) {
            val nextIp = nextAvailableIp(subnet, reservedIps)
            reservedIps += nextIp
            allocated[peer.publicKey] = nextIp
        }

        return DuplicateIpRepairPlan(LinkedHashMap(allocated))
    }

    fun applyPeerIpReassignments(config: String, reassignments: Map<String, String>): String {
        if (reassignments.isEmpty()) return config

        return peerRegex.replace(config) { match ->
            val fullBlock = match.value
            val publicKey = publicKeyRegex.find(fullBlock)?.groupValues?.get(1)?.trim()
            val newIp = publicKey?.let(reassignments::get)
            if (newIp == null) {
                fullBlock
            } else {
                allowedIpRegex.replace(fullBlock, "AllowedIPs = $newIp/32")
            }
        }
    }

    fun replaceClientAddress(config: String, newIp: String): String {
        val match = clientAddressRegex.find(config) ?: return config
        return buildString {
            append(config, 0, match.range.first)
            append("Address = $newIp/32")
            append(config, match.range.last + 1, config.length)
        }
    }

    private fun parsePeers(config: String): List<PeerEntry> {
        return peerRegex.findAll(config).mapNotNull { match ->
            val blockText = match.value
            val publicKey = publicKeyRegex.find(blockText)?.groupValues?.get(1)?.trim()
            val allowedIp = allowedIpRegex.find(blockText)?.groupValues?.get(1)?.trim()
            if (publicKey.isNullOrBlank() || allowedIp.isNullOrBlank()) {
                null
            } else {
                PeerEntry(
                    publicKey = publicKey,
                    presharedKey = null,
                    allowedIp = allowedIp,
                    blockText = blockText
                )
            }
        }.toList()
    }

    private fun parseInterfaceSubnet(config: String): String {
        val addressLine = Regex("""Address\s*=\s*([0-9.]+)\/(\d+)""").find(config)
            ?: error("Failed to parse interface Address from server config")
        val ip = addressLine.groupValues[1]
        val prefix = addressLine.groupValues[2].toInt()
        val mask = if (prefix == 0) 0 else (-1 shl (32 - prefix))
        val network = ipv4ToInt(ip) and mask
        return "${intToIpv4(network)}/$prefix"
    }

    private fun nextAvailableIp(subnetCidr: String, usedIps: Set<String>): String {
        val (networkIp, prefix) = subnetCidr.split("/", limit = 2)
        val network = ipv4ToInt(networkIp)
        val maskBits = prefix.toInt()
        val hostCount = (1 shl (32 - maskBits)) - 2
        val reserved = usedIps.toMutableSet()
        reserved += networkIp
        reserved += intToIpv4(network + 1)

        for (offset in 1..hostCount) {
            val candidate = intToIpv4(network + offset)
            if (candidate !in reserved) return candidate
        }

        error("No free IP addresses left in subnet $subnetCidr")
    }

    private fun ipv4ToInt(ip: String): Int {
        return ip.split('.')
            .map(String::toInt)
            .fold(0) { acc, octet -> (acc shl 8) or (octet and 0xFF) }
    }

    private fun intToIpv4(value: Int): String {
        return listOf(
            value ushr 24 and 0xFF,
            value ushr 16 and 0xFF,
            value ushr 8 and 0xFF,
            value and 0xFF
        ).joinToString(".")
    }
}

private class RemoteAwgAccess(
    private val connection: AwgConnection
) {
    private val wgConfigPath: String
        get() = "${connection.containerConfigDir}/${connection.interfaceName}.conf"

    fun readServerConfig(): String {
        val content = runDocker("cat $wgConfigPath 2>/dev/null || true")
        require(content.isNotBlank()) { "Failed to read container file: $wgConfigPath" }
        return content
    }

    fun writeBackup(content: String) {
        val timestamp = System.currentTimeMillis()
        writeContainerFile("$wgConfigPath.bak.$timestamp", content)
    }

    fun writeServerConfig(content: String) {
        writeContainerFile(wgConfigPath, content)
    }

    fun reloadWireGuard() {
        runDocker("sh -lc ${shellQuote("ip link del ${connection.interfaceName} 2>/dev/null || true; wg-quick up $wgConfigPath 2>&1")}")
    }

    private fun writeContainerFile(path: String, content: String) {
        val encoded = Base64.getEncoder().encodeToString(content.toByteArray(Charsets.UTF_8))
        val script = """
            cat <<'EOF' > /tmp/amnezia_payload.b64
            $encoded
            EOF
            base64 -d /tmp/amnezia_payload.b64 > ${shellQuote(path)}
            rm -f /tmp/amnezia_payload.b64
        """.trimIndent()
        runDocker("sh -lc ${shellQuote(script)}")
    }

    private fun runDocker(command: String): String {
        return ssh("docker exec -i ${connection.containerName} $command", sudo = true)
    }

    private fun ssh(command: String, sudo: Boolean = false): String {
        val remoteCommand = buildString {
            append("export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:\$PATH; ")
            if (sudo && connection.username != "root") {
                val password = connection.password ?: error("password is required for sudo when username is not root")
                append("echo ${shellQuote(password)} | sudo -S -p '' ")
            }
            append(command)
        }

        val client = SSHClient()
        client.addHostKeyVerifier(PromiscuousVerifier())

        try {
            client.connect(connection.host, connection.port)

            if (!connection.sshKeyPath.isNullOrBlank()) {
                client.authPublickey(connection.username, connection.sshKeyPath)
            } else {
                val password = connection.password ?: error("Either password or sshKeyPath must be provided")
                client.authPassword(connection.username, password)
            }

            client.startSession().use { session ->
                return executeRemoteCommand(session, remoteCommand)
            }
        } finally {
            try {
                client.disconnect()
            } finally {
                client.close()
            }
        }
    }

    private fun executeRemoteCommand(session: Session, command: String): String {
        val cmd = session.exec(command)
        val stdout = cmd.inputStream.bufferedReader(Charsets.UTF_8).readText()
        val stderr = cmd.errorStream.bufferedReader(Charsets.UTF_8).readText()
        cmd.join()

        val exitStatus = cmd.exitStatus ?: -1
        val output = (stdout + stderr).trimEnd()
        require(exitStatus == 0) { "SSH command failed with exit code $exitStatus\n$output" }
        return output
    }

    private fun shellQuote(value: String): String = "'" + value.replace("'", "'\\''") + "'"
}
