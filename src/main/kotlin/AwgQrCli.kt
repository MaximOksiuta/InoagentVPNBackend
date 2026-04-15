package org.example

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.client.j2se.MatrixToImageWriter
import com.google.zxing.qrcode.QRCodeWriter
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.bouncycastle.math.ec.rfc7748.X25519
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.Base64
import java.util.EnumMap
import java.util.zip.Deflater

@OptIn(ExperimentalSerializationApi::class)
private val prettyJson = Json {
    prettyPrint = true
    prettyPrintIndent = "    "
    explicitNulls = false
}

private const val DEFAULT_PORT = 51820
private const val DEFAULT_MTU = 1280
private const val DEFAULT_KEEPALIVE = 25
private const val MAGIC_VERSION = 0x07C00100
private const val DEFAULT_QR_SIZE = 300
private const val DEFAULT_QR_MARGIN = 1

fun main(args: Array<String>) {
    if (args.any { it == "--help" || it == "-h" }) {
        println(AwgQrCli.usage())
        return
    }

    val cli = AwgQrCli.parse(args)
    val configText = Files.readString(cli.configPath)
    val payload = AwgQrPayloadEncoder.encodeOldPayloadFromConf(configText, cli.descriptionOverride)
    AwgQrPngWriter.write(payload, cli.outputPath, cli.size, cli.margin)

    if (cli.printDataUri) {
        val pngBytes = Files.readAllBytes(cli.outputPath)
        println("data:image/png;base64," + Base64.getEncoder().encodeToString(pngBytes))
    } else {
        println("QR saved to ${cli.outputPath.toAbsolutePath()}")
    }
}

private data class AwgQrCli(
    val configPath: Path,
    val outputPath: Path,
    val size: Int,
    val margin: Int,
    val descriptionOverride: String?,
    val printDataUri: Boolean
) {
    companion object {
        fun usage(): String = """
            Usage:
              ./gradlew awgQrFromConfig --args="--config /path/to/client.conf --out /path/to/qr.png"

            Options:
              --config <path>         Path to final AWG/WireGuard client config
              --out <path>            Output PNG path (default: <config>.qr.png)
              --size <px>             QR image size in pixels, default 300
              --margin <modules>      QR margin, default 1
              --description <text>    Override envelope description
              --print-data-uri        Print data:image/png;base64,... after writing the file
        """.trimIndent()

        fun parse(args: Array<String>): AwgQrCli {
            require(args.isNotEmpty()) {
                usage()
            }

            var configPath: Path? = null
            var outputPath: Path? = null
            var size = 300
            var margin = 1
            var descriptionOverride: String? = null
            var printDataUri = false

            var index = 0
            while (index < args.size) {
                when (val arg = args[index]) {
                    "--config" -> {
                        index += 1
                        configPath = Paths.get(args.getOrElse(index) { error("Missing value for --config") })
                    }
                    "--out" -> {
                        index += 1
                        outputPath = Paths.get(args.getOrElse(index) { error("Missing value for --out") })
                    }
                    "--size" -> {
                        index += 1
                        size = args.getOrElse(index) { error("Missing value for --size") }.toInt()
                    }
                    "--margin" -> {
                        index += 1
                        margin = args.getOrElse(index) { error("Missing value for --margin") }.toInt()
                    }
                    "--description" -> {
                        index += 1
                        descriptionOverride = args.getOrElse(index) { error("Missing value for --description") }
                    }
                    "--print-data-uri" -> {
                        printDataUri = true
                    }
                    "--help", "-h" -> error(usage())
                    else -> {
                        if (configPath == null && !arg.startsWith("--")) {
                            configPath = Paths.get(arg)
                        } else if (outputPath == null && !arg.startsWith("--")) {
                            outputPath = Paths.get(arg)
                        } else {
                            error("Unknown argument: $arg\n${usage()}")
                        }
                    }
                }
                index += 1
            }

            val finalConfigPath = requireNotNull(configPath) { usage() }
            val finalOutputPath = outputPath ?: defaultOutputPath(finalConfigPath)

            require(size > 0) { "size must be > 0" }
            require(margin >= 0) { "margin must be >= 0" }

            return AwgQrCli(
                configPath = finalConfigPath,
                outputPath = finalOutputPath,
                size = size,
                margin = margin,
                descriptionOverride = descriptionOverride,
                printDataUri = printDataUri
            )
        }

        private fun defaultOutputPath(configPath: Path): Path {
            val fileName = configPath.fileName.toString()
            val baseName = fileName.substringBeforeLast('.', fileName)
            val parent = configPath.toAbsolutePath().parent ?: Paths.get(".").toAbsolutePath().normalize()
            return parent.resolve("$baseName.qr.png")
        }
    }
}

private object AwgQrPayloadEncoder {
    fun encodeOldPayloadFromConf(confText: String, descriptionOverride: String? = null): String {
        val payload = buildOldEnvelopeFromConf(confText, descriptionOverride)
        val json = prettyJson.encodeToString(payload)
        return encodeOldPayloadFromJson(json)
    }

    private fun encodeOldPayloadFromJson(jsonText: String): String {
        val compressed = deflateZlib(jsonText.toByteArray(Charsets.UTF_8))
        val header = ByteArray(12)
        putInt32(header, 0, MAGIC_VERSION)
        putInt32(header, 4, compressed.size + 4)
        putInt32(header, 8, jsonText.toByteArray(Charsets.UTF_8).size)
        val binary = header + compressed
        return Base64.getUrlEncoder().withoutPadding().encodeToString(binary)
    }

    private fun buildOldEnvelopeFromConf(confText: String, descriptionOverride: String?): JsonObject {
        val parsed = AwgConfigParser.parse(confText)
        val description = descriptionOverride?.takeIf { it.isNotBlank() } ?: (parsed.endpointHost ?: "")

        val lastConfig = jsonObject(
            "H1" to str(parsed.awgParams["H1"]),
            "H2" to str(parsed.awgParams["H2"]),
            "H3" to str(parsed.awgParams["H3"]),
            "H4" to str(parsed.awgParams["H4"]),
            "Jc" to str(parsed.awgParams["Jc"]),
            "Jmax" to str(parsed.awgParams["Jmax"]),
            "Jmin" to str(parsed.awgParams["Jmin"]),
            "S1" to str(parsed.awgParams["S1"]),
            "S2" to str(parsed.awgParams["S2"]),
            "allowed_ips" to JsonArray(parsed.allowedIps.ifEmpty { listOf("0.0.0.0/0", "::/0") }.map(::JsonPrimitive)),
            "clientId" to str(parsed.clientPublicKey),
            "client_ip" to str(parsed.clientIp),
            "client_priv_key" to str(parsed.privateKey),
            "client_pub_key" to str(parsed.clientPublicKey),
            "config" to str(confText),
            "hostName" to str(parsed.endpointHost),
            "mtu" to str(parsed.mtu.toString()),
            "persistent_keep_alive" to str(parsed.keepAlive.toString()),
            "port" to JsonPrimitive(parsed.endpointPort),
            "psk_key" to str(parsed.presharedKey),
            "server_pub_key" to str(parsed.serverPublicKey)
        )

        val awg = jsonObject(
            "H1" to str(parsed.awgParams["H1"]),
            "H2" to str(parsed.awgParams["H2"]),
            "H3" to str(parsed.awgParams["H3"]),
            "H4" to str(parsed.awgParams["H4"]),
            "Jc" to str(parsed.awgParams["Jc"]),
            "Jmax" to str(parsed.awgParams["Jmax"]),
            "Jmin" to str(parsed.awgParams["Jmin"]),
            "S1" to str(parsed.awgParams["S1"]),
            "S2" to str(parsed.awgParams["S2"]),
            "last_config" to str(prettyJson.encodeToString(lastConfig)),
            "port" to str(parsed.endpointPort.toString()),
            "transport_proto" to str("udp")
        )

        return jsonObject(
            "containers" to JsonArray(
                listOf(
                    jsonObject(
                        "awg" to awg,
                        "container" to str("amnezia-awg")
                    )
                )
            ),
            "defaultContainer" to str("amnezia-awg"),
            "description" to str(description),
            "dns1" to str(parsed.dnsServers.getOrElse(0) { "1.1.1.1" }),
            "dns2" to str(parsed.dnsServers.getOrElse(1) { "1.0.0.1" }),
            "hostName" to str(parsed.endpointHost)
        )
    }

    private fun deflateZlib(input: ByteArray): ByteArray {
        val deflater = Deflater(9)
        deflater.setInput(input)
        deflater.finish()

        val buffer = ByteArray(input.size + 256)
        val written = deflater.deflate(buffer)
        deflater.end()
        return buffer.copyOf(written)
    }

    private fun putInt32(target: ByteArray, offset: Int, value: Int) {
        target[offset] = ((value ushr 24) and 0xFF).toByte()
        target[offset + 1] = ((value ushr 16) and 0xFF).toByte()
        target[offset + 2] = ((value ushr 8) and 0xFF).toByte()
        target[offset + 3] = (value and 0xFF).toByte()
    }

    private fun jsonObject(vararg pairs: Pair<String, kotlinx.serialization.json.JsonElement>): JsonObject =
        JsonObject(linkedMapOf(*pairs))

    private fun str(value: String?): JsonPrimitive = JsonPrimitive(value ?: "")
}

object AwgQrCodeService {
    fun generatePng(confText: String, descriptionOverride: String? = null): ByteArray {
        val payload = AwgQrPayloadEncoder.encodeOldPayloadFromConf(confText, descriptionOverride)
        return AwgQrPngWriter.render(payload, DEFAULT_QR_SIZE, DEFAULT_QR_MARGIN)
    }
}

private data class ParsedAwgConfig(
    val endpointHost: String?,
    val endpointPort: Int,
    val mtu: Int,
    val keepAlive: Int,
    val dnsServers: List<String>,
    val privateKey: String?,
    val serverPublicKey: String?,
    val presharedKey: String?,
    val clientIp: String?,
    val allowedIps: List<String>,
    val awgParams: Map<String, String>,
    val clientPublicKey: String
)

private object AwgConfigParser {
    private val endpointRegex = Regex("""^\[?([^\]]+)\]?:([0-9]{2,5})$""")
    private val keyValueRegex = Regex("""^\s*([^=]+?)\s*=\s*(.*?)\s*$""")

    fun parse(confText: String): ParsedAwgConfig {
        var endpointHost: String? = null
        var endpointPort: Int? = null
        var mtu: Int? = null
        var keepAlive: Int? = null
        var privateKey: String? = null
        var serverPublicKey: String? = null
        var presharedKey: String? = null
        var clientIp: String? = null
        var allowedIps: List<String> = emptyList()
        var dnsServers: List<String> = emptyList()
        val awgParams = linkedMapOf<String, String>()

        confText.lineSequence().forEach { rawLine ->
            val line = rawLine.trim()
            if (line.isEmpty() || line.startsWith("#")) return@forEach

            val match = keyValueRegex.matchEntire(line) ?: return@forEach
            val key = match.groupValues[1].trim()
            val value = match.groupValues[2].trim()

            when (key.lowercase()) {
                "endpoint" -> {
                    val endpointMatch = endpointRegex.matchEntire(value)
                    if (endpointMatch != null) {
                        endpointHost = endpointMatch.groupValues[1]
                        endpointPort = endpointMatch.groupValues[2].toInt()
                    }
                }
                "mtu" -> mtu = value.toIntOrNull()
                "dns" -> dnsServers = value.split(',', ' ', '\t').mapNotNull { it.trim().takeIf(String::isNotEmpty) }
                "privatekey" -> privateKey = value
                "publickey" -> if (serverPublicKey == null) serverPublicKey = value
                "presharedkey" -> if (presharedKey == null) presharedKey = value
                "address" -> clientIp = value.substringBefore('/').trim().ifEmpty { null }
                "allowedips" -> allowedIps = value.split(',', ' ', '\t').mapNotNull { it.trim().takeIf(String::isNotEmpty) }
                "persistentkeepalive" -> keepAlive = value.toIntOrNull()
            }

            when (key) {
                "H1", "H2", "H3", "H4", "Jc", "Jmin", "Jmax", "S1", "S2" -> awgParams[key] = value
            }
        }

        val clientPublicKey = derivePublicKey(privateKey)

        return ParsedAwgConfig(
            endpointHost = endpointHost,
            endpointPort = endpointPort ?: DEFAULT_PORT,
            mtu = mtu ?: DEFAULT_MTU,
            keepAlive = keepAlive ?: DEFAULT_KEEPALIVE,
            dnsServers = dnsServers,
            privateKey = privateKey,
            serverPublicKey = serverPublicKey,
            presharedKey = presharedKey,
            clientIp = clientIp,
            allowedIps = allowedIps,
            awgParams = awgParams,
            clientPublicKey = clientPublicKey
        )
    }

    private fun derivePublicKey(privateKey: String?): String {
        if (privateKey.isNullOrBlank()) return ""

        val privateKeyBytes = try {
            Base64.getDecoder().decode(privateKey)
        } catch (_: IllegalArgumentException) {
            return ""
        }

        if (privateKeyBytes.size != 32) return ""

        val publicKey = ByteArray(32)
        X25519.generatePublicKey(privateKeyBytes, 0, publicKey, 0)
        return Base64.getEncoder().encodeToString(publicKey)
    }
}

private object AwgQrPngWriter {
    fun write(payload: String, outputPath: Path, size: Int, margin: Int) {
        val pngBytes = render(payload, size, margin)
        outputPath.parent?.let(Files::createDirectories)
        Files.newOutputStream(outputPath).use { stream ->
            stream.write(pngBytes)
        }
    }

    fun render(payload: String, size: Int, margin: Int): ByteArray {
        val hints = EnumMap<EncodeHintType, Any>(EncodeHintType::class.java).apply {
            put(EncodeHintType.MARGIN, margin)
            put(EncodeHintType.CHARACTER_SET, "UTF-8")
        }
        val matrix = QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, size, size, hints)
        val output = ByteArrayOutputStream()
        MatrixToImageWriter.writeToStream(matrix, "PNG", output)
        return output.toByteArray()
    }
}
