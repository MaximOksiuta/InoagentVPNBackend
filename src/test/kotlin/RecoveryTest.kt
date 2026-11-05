package org.example

import kotlin.test.*
import java.nio.file.Files
import org.mindrot.jbcrypt.BCrypt

class RecoveryTest {
    @Test fun `formatted phones normalize`() {
        for (phone in listOf("+7 (977) 834-33-79", "8 977 834 33 79", "9778343379", "0079778343379")) assertEquals("+79778343379", normalizePhone(phone))
        assertEquals("+491234567890", normalizePhone("+49 (123) 456-7890"))
        assertFailsWith<IllegalArgumentException> { normalizePhone("abc+79778343379") }
    }
    @Test fun `recovery is bound to telegram single use and expires`() {
        val path = Files.createTempFile("recovery-test", ".db")
        val db = DatabaseFactory(path.toString()); db.initialize()
        val users = SqliteUserRepository(db)
        val user = users.createUser("+79778343379", "Test", 123L, BCrypt.hashpw("old-password", BCrypt.gensalt()))!!
        users.updateApproval(user.id, true)
        val recovery = PasswordRecovery(db)
        assertFailsWith<IllegalArgumentException> { recovery.issue(RecoveryRequest(user.phone, 999)) }
        val ticket = recovery.issue(RecoveryRequest("+7 (977) 834-33-79", 123))
        assertFailsWith<IllegalArgumentException> { recovery.issue(RecoveryRequest(user.phone, 123)) }
        recovery.consume(ResetPasswordRequest(ticket.token, "new-password"))
        assertTrue(BCrypt.checkpw("new-password", users.findById(user.id)!!.passwordHash))
        assertFalse(users.sessionValid(user.id, 0))
        assertFailsWith<IllegalArgumentException> { recovery.consume(ResetPasswordRequest(ticket.token, "other-password")) }
        val expired = recovery.issue(RecoveryRequest(user.phone, 123))
        db.connection().use { c -> c.createStatement().executeUpdate("UPDATE password_resets SET expires_at = 0") }
        assertFailsWith<IllegalArgumentException> { recovery.consume(ResetPasswordRequest(expired.token, "other-password")) }
        assertEquals(1, users.listUsers().size)
        Files.deleteIfExists(path)
    }
}
