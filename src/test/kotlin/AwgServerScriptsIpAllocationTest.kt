package org.example

import kotlin.test.Test
import kotlin.test.assertEquals

class AwgServerScriptsIpAllocationTest {

    private val scripts = AwgServerScripts(
        AwgConnection(
            host = "example.com",
            username = "root"
        )
    )

    @Test
    fun `next client ip does not reuse last peer ip from config`() {
        val wgConfig = """
            [Interface]
            Address = 10.8.1.1/24

            [Peer]
            PublicKey = key-1
            AllowedIPs = 10.8.1.2/32

            [Peer]
            PublicKey = key-2
            AllowedIPs = 10.8.1.3/32
        """.trimIndent()

        assertEquals("10.8.1.4", invokeGetNextClientIp("10.8.1.0/24", wgConfig))
    }

    @Test
    fun `parse peer ips includes last peer block at end of file`() {
        val wgConfig = """
            [Peer]
            PublicKey = key-1
            AllowedIPs = 10.8.1.2/32

            [Peer]
            PublicKey = key-2
            AllowedIPs = 10.8.1.3/32
        """.trimIndent()

        assertEquals(
            linkedMapOf(
                "key-1" to "10.8.1.2",
                "key-2" to "10.8.1.3"
            ),
            invokeParsePeerIps(wgConfig)
        )
    }

    @Suppress("UNCHECKED_CAST")
    private fun invokeParsePeerIps(config: String): Map<String, String> {
        val method = scripts.javaClass.getDeclaredMethod("parsePeerIps", String::class.java)
        method.isAccessible = true
        return method.invoke(scripts, config) as Map<String, String>
    }

    private fun invokeGetNextClientIp(subnetCidr: String, config: String): String {
        val method = scripts.javaClass.getDeclaredMethod("getNextClientIp", String::class.java, String::class.java)
        method.isAccessible = true
        return method.invoke(scripts, subnetCidr, config) as String
    }
}
