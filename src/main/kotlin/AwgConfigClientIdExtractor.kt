package org.example

import org.bouncycastle.math.ec.rfc7748.X25519
import java.util.Base64

object AwgConfigClientIdExtractor {
    private val keyValueRegex = Regex("""^\s*([^=]+?)\s*=\s*(.*?)\s*$""")

    fun extractClientId(configText: String): String {
        val privateKey = configText.lineSequence()
            .map(String::trim)
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .mapNotNull { line ->
                val match = keyValueRegex.matchEntire(line) ?: return@mapNotNull null
                val key = match.groupValues[1].trim()
                val value = match.groupValues[2].trim()
                if (key.equals("PrivateKey", ignoreCase = true)) value else null
            }
            .firstOrNull()
            ?: return ""

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
