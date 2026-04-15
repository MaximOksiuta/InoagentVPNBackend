package org.example

import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RepairDuplicateIpsCliTest {

    @Test
    fun `parse accepts repeated server ids and dry run`() {
        val command = RepairDuplicateIpsCli.parse(
            arrayOf("--db", "/tmp/app.db", "--server-id", "1", "--server-id", "2", "--dry-run")
        )

        assertEquals("/tmp/app.db", command.databasePath)
        assertEquals(setOf(1L, 2L), command.serverIds)
        assertTrue(command.dryRun)
    }

    @Test
    fun `planner reassigns only duplicate peers`() {
        val config = """
            [Interface]
            Address = 10.8.1.1/24

            [Peer]
            PublicKey = peer-1
            AllowedIPs = 10.8.1.2/32

            [Peer]
            PublicKey = peer-2
            AllowedIPs = 10.8.1.2/32

            [Peer]
            PublicKey = peer-3
            AllowedIPs = 10.8.1.3/32

            [Peer]
            PublicKey = peer-4
            AllowedIPs = 10.8.1.3/32
        """.trimIndent()

        val reassignments = DuplicateIpRepairPlanner.plan(config).reassignments

        assertEquals(
            linkedMapOf(
                "peer-2" to "10.8.1.4",
                "peer-4" to "10.8.1.5"
            ),
            reassignments
        )
    }

    @Test
    fun `replace client address updates only interface address`() {
        val config = """
            [Interface]
            PrivateKey = key
            Address = 10.8.1.2/32

            [Peer]
            AllowedIPs = 0.0.0.0/0, ::/0
        """.trimIndent()

        val updated = DuplicateIpRepairPlanner.replaceClientAddress(config, "10.8.1.9")

        assertTrue(updated.contains("Address = 10.8.1.9/32"))
        assertTrue(updated.contains("AllowedIPs = 0.0.0.0/0, ::/0"))
        assertFalse(updated.contains("Address = 10.8.1.2/32"))
    }

    @Test
    fun `execute fails when requested server is missing`() {
        val tempDir = createTempDirectory("repair-duplicate-ips")
        val dbPath = tempDir.resolve("app.db").toString()
        val databaseFactory = DatabaseFactory(dbPath)
        databaseFactory.initialize()

        val exception = kotlin.runCatching {
            RepairDuplicateIpsCli.execute(
                RepairDuplicateIpsCommand(
                    databasePath = dbPath,
                    serverIds = setOf(99L),
                    dryRun = true
                )
            )
        }.exceptionOrNull()

        requireNotNull(exception)
        assertTrue(exception.message!!.contains("Server(s) not found: 99"))
    }
}
