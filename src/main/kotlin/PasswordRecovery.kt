package org.example

import kotlinx.serialization.Serializable
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import org.mindrot.jbcrypt.BCrypt

@Serializable data class RecoveryRequest(val phone: String, val telegramId: Long)
@Serializable data class RecoveryTicket(val token: String)
@Serializable data class ResetPasswordRequest(val token: String, val password: String)

class PasswordRecovery(private val db: DatabaseFactory) {
    private fun digest(value: String) = MessageDigest.getInstance("SHA-256").digest(value.toByteArray()).joinToString("") { "%02x".format(it) }

    fun issue(request: RecoveryRequest): RecoveryTicket = db.transaction { connection ->
        val phone = normalizePhone(request.phone)
        val user = connection.prepareStatement("SELECT id, telegram_id, is_banned, is_approved FROM users WHERE phone = ?").use { s ->
            s.setString(1, phone)
            s.executeQuery().use { r ->
                require(r.next()) { "Аккаунт не найден" }
                require(r.getInt("is_banned") == 0 && r.getInt("is_approved") == 1) { "Аккаунт недоступен" }
                val telegram = r.getLong("telegram_id").takeUnless { r.wasNull() }
                require(telegram == null || telegram == request.telegramId) { "Номер привязан к другому Telegram-аккаунту" }
                r.getLong("id")
            }
        }
        val now = System.currentTimeMillis()
        connection.prepareStatement("SELECT created_at FROM password_resets WHERE user_id = ?").use { s ->
            s.setLong(1, user)
            s.executeQuery().use { r -> require(!r.next() || now - r.getLong(1) >= 60_000) { "Повторите запрос через минуту" } }
        }
        connection.prepareStatement("DELETE FROM password_resets WHERE user_id = ? OR expires_at < ?").use { s -> s.setLong(1, user); s.setLong(2, now); s.executeUpdate() }
        val token = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32).also { SecureRandom().nextBytes(it) })
        connection.prepareStatement("INSERT INTO password_resets VALUES (?, ?, ?, ?)").use { s ->
            s.setString(1, digest(token)); s.setLong(2, user); s.setLong(3, now + 600_000); s.setLong(4, now); s.executeUpdate()
        }
        connection.prepareStatement("UPDATE users SET telegram_id = ? WHERE id = ?").use { s -> s.setLong(1, request.telegramId); s.setLong(2, user); s.executeUpdate() }
        RecoveryTicket(token)
    }

    fun consume(request: ResetPasswordRequest) {
        require(request.token.length in 40..100) { "Ссылка недействительна" }
        require(request.password.toByteArray().size in 8..72) { "Пароль должен содержать от 8 до 72 байт" }
        val hash = BCrypt.hashpw(request.password, BCrypt.gensalt())
        db.transaction { c ->
            val user = c.prepareStatement("SELECT user_id FROM password_resets WHERE token_hash = ? AND expires_at > ?").use { s ->
                s.setString(1, digest(request.token)); s.setLong(2, System.currentTimeMillis())
                s.executeQuery().use { r -> require(r.next()) { "Ссылка истекла или уже использована" }; r.getLong(1) }
            }
            c.prepareStatement("UPDATE users SET password_hash = ? WHERE id = ? AND is_banned = 0 AND is_approved = 1").use { s ->
                s.setString(1, hash); s.setLong(2, user); require(s.executeUpdate() == 1) { "Аккаунт недоступен" }
            }
            c.prepareStatement("DELETE FROM password_resets WHERE user_id = ?").use { s -> s.setLong(1, user); s.executeUpdate() }
            c.prepareStatement("INSERT OR REPLACE INTO password_revocations(user_id, changed_at) VALUES (?, ?)").use { s -> s.setLong(1, user); s.setLong(2, System.currentTimeMillis() / 1000); s.executeUpdate() }
        }
    }
}
