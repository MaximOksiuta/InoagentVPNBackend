package org.example

import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class InitAdminCliTest {

    @Test
    fun `execute approves grants admin and unbans user`() {
        val tempDir = createTempDirectory("init-admin-test")
        val databaseFactory = DatabaseFactory(tempDir.resolve("app.db").toString())
        databaseFactory.initialize()
        val userRepository = SqliteUserRepository(databaseFactory)

        val createdUser = userRepository.createUser(
            phone = "+79990001122",
            nickname = "operator",
            telegramId = null,
            passwordHash = "hash"
        ) ?: error("User was not created")

        userRepository.updateBan(createdUser.id, true)

        val result = InitAdminCli.execute(
            InitAdminCommand(
                phone = createdUser.phone,
                databasePath = tempDir.resolve("app.db").toString()
            )
        )

        val updatedUser = userRepository.findByPhone(createdUser.phone) ?: error("User not found after update")

        assertEquals(createdUser.id, result.id)
        assertTrue(result.isApproved)
        assertTrue(result.isAdmin)
        assertFalse(result.isBanned)
        assertTrue(updatedUser.isApproved)
        assertTrue(updatedUser.isAdmin)
        assertFalse(updatedUser.isBanned)
    }

    @Test
    fun `parse accepts positional phone and custom db`() {
        val command = InitAdminCli.parse(arrayOf("+79990001122", "--db", "/tmp/app.db"))

        assertEquals("+79990001122", command.phone)
        assertEquals("/tmp/app.db", command.databasePath)
    }
}
