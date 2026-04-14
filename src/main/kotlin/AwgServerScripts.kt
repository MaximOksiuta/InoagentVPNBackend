package org.example

import java.net.InetAddress
import java.util.Base64
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.connection.channel.direct.Session
import net.schmizz.sshj.transport.verification.PromiscuousVerifier

// Important: here clientId means AWG clientId from clientsTable, which for AWG equals the peer public key.

data class AwgConnection(
    val host: String,
    val port: Int = 22,
    val username: String,
    val password: String? = null,
    val sshKeyPath: String? = null,
    val containerName: String = "amnezia-awg2",
    val containerConfigDir: String = "/opt/amnezia/awg",
    val interfaceName: String = "awg0"
)

data class AwgUser(
    val clientId: String,
    val name: String,
    val clientIp: String? = null,
    val creationDate: String? = null
)

data class AwgCreatedUser(
    val clientId: String,
    val name: String,
    val clientIp: String,
    val privateKey: String,
    val publicKey: String,
    val config: String
)

class AwgServerScripts(private val connection: AwgConnection) {

    private val wgConfigPath: String
        get() = "${connection.containerConfigDir}/${connection.interfaceName}.conf"

    private val clientsTablePath: String
        get() = "${connection.containerConfigDir}/clientsTable"

    private val wireguardPskPath: String
        get() = "${connection.containerConfigDir}/wireguard_psk.key"

    private data class ClientsTableEntry(
        val clientId: String,
        val clientName: String,
        val creationDate: String?
    )

    private data class ServerState(
        val publicKey: String,
        val presharedKey: String,
        val listenPort: Int,
        val dnsServers: String,
        val subnetCidr: String,
        val awgParams: Map<String, String>,
        val wgConfig: String,
        val clientsTable: List<ClientsTableEntry>
    )

    fun listUsers(): List<AwgUser> {
        val state = readServerState()
        val ipByPublicKey = parsePeerIps(state.wgConfig)

        return state.clientsTable.map { entry ->
            AwgUser(
                clientId = entry.clientId,
                name = entry.clientName,
                clientIp = ipByPublicKey[entry.clientId],
                creationDate = entry.creationDate
            )
        }
    }

    fun addUser(name: String): AwgCreatedUser {
        require(name.isNotBlank()) { "name must not be blank" }

        val state = readServerState()
        val nextIp = getNextClientIp(state.subnetCidr, state.wgConfig)
        val keys = generateClientKeys()

        val config = buildClientConfig(
            privateKey = keys.first,
            clientIp = nextIp,
            serverPublicKey = state.publicKey,
            presharedKey = state.presharedKey,
            serverHost = connection.host,
            serverPort = state.listenPort,
            dnsServers = state.dnsServers,
            awgParams = state.awgParams
        )

        addPeerToServer(
            publicKey = keys.second,
            clientIp = nextIp,
            presharedKey = state.presharedKey
        )

        val updatedTable = state.clientsTable + ClientsTableEntry(
            clientId = keys.second,
            clientName = name,
            creationDate = java.util.Date().toString()
        )
        writeClientsTable(updatedTable)
        reloadWireGuard()

        return AwgCreatedUser(
            clientId = keys.second,
            name = name,
            clientIp = nextIp,
            privateKey = keys.first,
            publicKey = keys.second,
            config = config
        )
    }

    fun deleteUser(clientId: String) {
        require(clientId.isNotBlank()) { "clientId must not be blank" }

        val state = readServerState()
        runDocker("wg set ${connection.interfaceName} peer ${shellQuote(clientId)} remove")

        val newConfig = removePeerFromConfig(state.wgConfig, clientId)
        writeContainerFile(wgConfigPath, newConfig)
        runDocker("wg-quick save ${connection.interfaceName} || true")

        val updatedTable = state.clientsTable.filterNot { it.clientId == clientId }
        writeClientsTable(updatedTable)
    }

    fun renameUser(clientId: String, newName: String) {
        require(clientId.isNotBlank()) { "clientId must not be blank" }
        require(newName.isNotBlank()) { "newName must not be blank" }

        val state = readServerState()
        val updated = state.clientsTable.map { entry ->
            if (entry.clientId == clientId) entry.copy(clientName = newName) else entry
        }

        if (updated == state.clientsTable) {
            error("Client with clientId=$clientId was not found in clientsTable")
        }

        writeClientsTable(updated)
    }

    private fun readServerState(): ServerState {
        val wgConfig = readContainerFile(wgConfigPath)
        val clientsTableRaw = readContainerFileOrEmpty(clientsTablePath)
        val publicKey = runDocker("wg show ${connection.interfaceName} 2>/dev/null | grep 'public key:' | awk '{print \$3}'").trim()
        val listenPortRaw = runDocker("wg show ${connection.interfaceName} 2>/dev/null | grep 'listening port:' | awk '{print \$3}'").trim()
        val presharedKey = runDocker(
            "sh -lc ${shellQuote("cat $wireguardPskPath 2>/dev/null || grep -E '^[[:space:]]*PresharedKey[[:space:]]*=' $wgConfigPath 2>/dev/null | head -1 | sed -E 's/^[[:space:]]*PresharedKey[[:space:]]*=[[:space:]]*//' | tr -d '\\r'")}"
        ).trim()

        require(publicKey.isNotBlank()) { "Failed to read server public key from container ${connection.containerName}" }
        require(listenPortRaw.isNotBlank()) { "Failed to read listening port from container ${connection.containerName}" }
        require(presharedKey.isNotBlank()) { "Failed to read preshared key from container ${connection.containerName}" }

        val subnetCidr = parseInterfaceSubnet(wgConfig)
        val dnsServers = parseDnsServers(wgConfig) ?: "1.1.1.1, 1.0.0.1"
        val awgParams = parseAwgParams(wgConfig)
        val clientsTable = parseClientsTable(clientsTableRaw)

        return ServerState(
            publicKey = publicKey,
            presharedKey = presharedKey,
            listenPort = listenPortRaw.toInt(),
            dnsServers = dnsServers,
            subnetCidr = subnetCidr,
            awgParams = awgParams,
            wgConfig = wgConfig,
            clientsTable = clientsTable
        )
    }

    private fun generateClientKeys(): Pair<String, String> {
        val output = runDocker(
            "sh -lc ${
                shellQuote(
                    "set -e; " +
                        "umask 077; " +
                        "priv=\$(wg genkey | tr -d '\\r\\n'); " +
                        "[ -n \"\$priv\" ] || { echo empty_private_key; exit 1; }; " +
                        "pub=\$(printf '%s\\n' \"\$priv\" | wg pubkey | tr -d '\\r\\n'); " +
                        "[ -n \"\$pub\" ] || { echo empty_public_key; exit 1; }; " +
                        "printf '%s\\n---\\n%s\\n' \"\$priv\" \"\$pub\""
                )
            }"
        ).trim()

        val parts = output.split("\n---\n")
        require(parts.size == 2) { "Failed to generate client keys: $output" }

        val privateKey = parts[0].trim()
        val publicKey = parts[1].trim()
        require(privateKey.isNotBlank() && publicKey.isNotBlank()) { "Generated empty client keys" }

        return privateKey to publicKey
    }

    private fun addPeerToServer(publicKey: String, clientIp: String, presharedKey: String) {
        val pskFile = "/tmp/${System.currentTimeMillis()}.psk"

        runDocker("sh -lc ${shellQuote("echo ${shellQuote(presharedKey)} > $pskFile")}")
        runDocker("wg set ${connection.interfaceName} peer ${shellQuote(publicKey)} preshared-key $pskFile allowed-ips $clientIp/32")
        runDocker("rm -f $pskFile")

        val peerBlock = buildString {
            append("\n[Peer]\n")
            append("PublicKey = ").append(publicKey).append('\n')
            append("PresharedKey = ").append(presharedKey).append('\n')
            append("AllowedIPs = ").append(clientIp).append("/32\n")
        }

        runDocker("sh -lc ${shellQuote("echo ${shellQuote(peerBlock)} >> $wgConfigPath")}")
    }

    private fun reloadWireGuard() {
        runDocker("sh -lc ${shellQuote("ip link del ${connection.interfaceName} 2>/dev/null || true; wg-quick up $wgConfigPath 2>&1")}")
    }

    private fun readContainerFile(path: String): String {
        val content = readContainerFileOrEmpty(path)
        require(content.isNotBlank()) { "Failed to read container file: $path" }
        return content
    }

    private fun readContainerFileOrEmpty(path: String): String {
        return runDocker("cat $path 2>/dev/null || true")
    }

    private fun writeClientsTable(entries: List<ClientsTableEntry>) {
        writeContainerFile(clientsTablePath, serializeClientsTable(entries))
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

    private fun parseClientsTable(json: String): List<ClientsTableEntry> {
        val trimmed = json.trim()
        if (trimmed.isEmpty()) return emptyList()

        val entries = mutableListOf<ClientsTableEntry>()
        val pattern = Regex(
            """\{\s*"clientId"\s*:\s*"((?:\\.|[^"\\])*)"\s*,\s*"userData"\s*:\s*\{\s*"clientName"\s*:\s*"((?:\\.|[^"\\])*)"(?:\s*,\s*"creationDate"\s*:\s*"((?:\\.|[^"\\])*)")?""",
            setOf(RegexOption.DOT_MATCHES_ALL)
        )

        for (match in pattern.findAll(trimmed)) {
            entries += ClientsTableEntry(
                clientId = jsonUnescape(match.groupValues[1]),
                clientName = jsonUnescape(match.groupValues[2]),
                creationDate = match.groupValues.getOrNull(3)?.takeIf { it.isNotEmpty() }?.let(::jsonUnescape)
            )
        }

        return entries
    }

    private fun serializeClientsTable(entries: List<ClientsTableEntry>): String {
        return buildString {
            append("[\n")
            entries.forEachIndexed { index, entry ->
                append("  {\n")
                append("    \"clientId\": \"").append(jsonEscape(entry.clientId)).append("\",\n")
                append("    \"userData\": {\n")
                append("      \"clientName\": \"").append(jsonEscape(entry.clientName)).append("\"")
                if (!entry.creationDate.isNullOrBlank()) {
                    append(",\n")
                    append("      \"creationDate\": \"").append(jsonEscape(entry.creationDate)).append("\"\n")
                } else {
                    append('\n')
                }
                append("    }\n")
                append("  }")
                if (index != entries.lastIndex) append(',')
                append('\n')
            }
            append("]\n")
        }
    }

    private fun parsePeerIps(config: String): Map<String, String> {
        val peers = linkedMapOf<String, String>()
        val regex = Regex("""\[Peer\](.*?)(?=\n\[|\$)""", RegexOption.DOT_MATCHES_ALL)

        regex.findAll(config).forEach { match ->
            val block = match.groupValues[1]
            val publicKey = Regex("""PublicKey\s*=\s*([^\r\n]+)""").find(block)?.groupValues?.get(1)?.trim()
            val clientIp = Regex("""AllowedIPs\s*=\s*([0-9.]+)\/32""").find(block)?.groupValues?.get(1)?.trim()
            if (!publicKey.isNullOrBlank() && !clientIp.isNullOrBlank()) {
                peers[publicKey] = clientIp
            }
        }

        return peers
    }

    private fun getNextClientIp(subnetCidr: String, wgConfig: String): String {
        val (networkIp, prefix) = subnetCidr.split("/", limit = 2)
        val network = ipv4ToInt(networkIp)
        val maskBits = prefix.toInt()
        val hostCount = (1 shl (32 - maskBits)) - 2

        val used = mutableSetOf<String>()
        used += networkIp
        used += intToIpv4(network + 1)
        used += parsePeerIps(wgConfig).values

        for (offset in 1..hostCount) {
            val candidate = intToIpv4(network + offset)
            if (candidate !in used) return candidate
        }

        error("No free IP addresses left in subnet $subnetCidr")
    }

    private fun parseInterfaceSubnet(config: String): String {
        val addressLine = Regex("""Address\s*=\s*([0-9.]+)\/(\d+)""").find(config)
            ?: error("Failed to parse interface Address from ${connection.interfaceName} config")
        val ip = addressLine.groupValues[1]
        val prefix = addressLine.groupValues[2].toInt()
        val mask = if (prefix == 0) 0 else (-1 shl (32 - prefix))
        val network = ipv4ToInt(ip) and mask
        return "${intToIpv4(network)}/$prefix"
    }

    private fun parseDnsServers(config: String): String? {
        return Regex("""^DNS\s*=\s*(.+)$""", RegexOption.MULTILINE)
            .find(config)
            ?.groupValues
            ?.get(1)
            ?.trim()
    }

    private fun parseAwgParams(config: String): Map<String, String> {
        val params = linkedMapOf<String, String>()
        val keys = listOf("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4")
        for (key in keys) {
            val value = Regex("""^$key\s*=\s*(.+)$""", RegexOption.MULTILINE)
                .find(config)
                ?.groupValues
                ?.get(1)
                ?.trim()
            if (!value.isNullOrBlank()) {
                params[key] = value
            }
        }
        return params
    }

    private fun buildClientConfig(
        privateKey: String,
        clientIp: String,
        serverPublicKey: String,
        presharedKey: String,
        serverHost: String,
        serverPort: Int,
        dnsServers: String,
        awgParams: Map<String, String>
    ): String {
        return buildString {
            appendLine("[Interface]")
            appendLine("PrivateKey = $privateKey")
            appendLine("Address = $clientIp/32")
            appendLine("DNS = $dnsServers")
            for ((key, value) in awgParams) {
                appendLine("$key = $value")
            }
            appendLine()
            appendLine("[Peer]")
            appendLine("PublicKey = $serverPublicKey")
            appendLine("PresharedKey = $presharedKey")
            appendLine("Endpoint = $serverHost:$serverPort")
            appendLine("AllowedIPs = 0.0.0.0/0, ::/0")
            appendLine("PersistentKeepalive = 25")
        }.trimEnd() + "\n"
    }

    private fun removePeerFromConfig(config: String, publicKey: String): String {
        val lines = config.lines()
        val result = mutableListOf<String>()
        var inPeerBlock = false
        var skipBlock = false

        for (line in lines) {
            val trimmed = line.trim()

            if (trimmed.startsWith("[")) {
                inPeerBlock = trimmed == "[Peer]"
                skipBlock = false
            }

            if (inPeerBlock && trimmed.startsWith("PublicKey")) {
                val currentKey = trimmed.substringAfter("=").trim()
                if (currentKey == publicKey) {
                    skipBlock = true
                    if (result.isNotEmpty() && result.last().trim() == "[Peer]") {
                        result.removeAt(result.lastIndex)
                    }
                    continue
                }
            }

            if (skipBlock && inPeerBlock) {
                if (trimmed.isEmpty()) {
                    skipBlock = false
                    inPeerBlock = false
                }
                continue
            }

            result += line
        }

        return result.joinToString("\n").trimEnd() + "\n"
    }

    private fun shellQuote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

    private fun jsonEscape(value: String): String = buildString {
        for (ch in value) {
            when (ch) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\b' -> append("\\b")
                '\u000c' -> append("\\f")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> {
                    if (ch.code < 32) {
                        append("\\u%04x".format(ch.code))
                    } else {
                        append(ch)
                    }
                }
            }
        }
    }

    private fun jsonUnescape(value: String): String {
        val out = StringBuilder()
        var i = 0
        while (i < value.length) {
            val ch = value[i]
            if (ch != '\\') {
                out.append(ch)
                i++
                continue
            }

            require(i + 1 < value.length) { "Invalid JSON escape in: $value" }
            when (val next = value[i + 1]) {
                '\\' -> out.append('\\')
                '"' -> out.append('"')
                '/' -> out.append('/')
                'b' -> out.append('\b')
                'f' -> out.append('\u000c')
                'n' -> out.append('\n')
                'r' -> out.append('\r')
                't' -> out.append('\t')
                'u' -> {
                    require(i + 5 < value.length) { "Invalid unicode escape in: $value" }
                    val hex = value.substring(i + 2, i + 6)
                    out.append(hex.toInt(16).toChar())
                    i += 4
                }
                else -> out.append(next)
            }
            i += 2
        }
        return out.toString()
    }

    private fun ipv4ToInt(ip: String): Int {
        val bytes = InetAddress.getByName(ip).address
        require(bytes.size == 4) { "Only IPv4 is supported: $ip" }
        return ((bytes[0].toInt() and 0xff) shl 24) or
            ((bytes[1].toInt() and 0xff) shl 16) or
            ((bytes[2].toInt() and 0xff) shl 8) or
            (bytes[3].toInt() and 0xff)
    }

    private fun intToIpv4(value: Int): String {
        return listOf(
            value ushr 24 and 0xff,
            value ushr 16 and 0xff,
            value ushr 8 and 0xff,
            value and 0xff
        ).joinToString(".")
    }
}
