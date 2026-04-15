package org.example

import java.sql.SQLException
import java.sql.Statement

data class User(
    val id: Long,
    val phone: String,
    val nickname: String,
    val telegramId: Long?,
    val isAdmin: Boolean,
    val isApproved: Boolean,
    val isBanned: Boolean,
    val passwordHash: String
)

interface UserRepository {
    fun createUser(phone: String, nickname: String, telegramId: Long?, passwordHash: String, isAdmin: Boolean = false): User?
    fun listUsers(): List<User>
    fun findById(userId: Long): User?
    fun findByPhone(phone: String): User?
    fun updateIsAdmin(userId: Long, isAdmin: Boolean): Boolean
    fun updateApproval(userId: Long, isApproved: Boolean): Boolean
    fun updateBan(userId: Long, isBanned: Boolean): Boolean
}

class SqliteUserRepository(
    private val databaseFactory: DatabaseFactory
) : UserRepository {

    override fun createUser(phone: String, nickname: String, telegramId: Long?, passwordHash: String, isAdmin: Boolean): User? {
        val sql = """
            INSERT INTO users(phone, nickname, telegram_id, is_admin, is_approved, is_banned, password_hash)
            VALUES(?, ?, ?, ?, ?, ?, ?)
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS).use { statement ->
                statement.setString(1, phone)
                statement.setString(2, nickname)
                if (telegramId == null) {
                    statement.setObject(3, null)
                } else {
                    statement.setLong(3, telegramId)
                }
                statement.setInt(4, if (isAdmin) 1 else 0)
                statement.setInt(5, 0)
                statement.setInt(6, 0)
                statement.setString(7, passwordHash)

                try {
                    val affectedRows = statement.executeUpdate()
                    if (affectedRows == 0) {
                        null
                    } else {
                        statement.generatedKeys.use { generatedKeys ->
                            if (!generatedKeys.next()) {
                                null
                            } else {
                                User(
                                    id = generatedKeys.getLong(1),
                                    phone = phone,
                                    nickname = nickname,
                                    telegramId = telegramId,
                                    isAdmin = isAdmin,
                                    isApproved = false,
                                    isBanned = false,
                                    passwordHash = passwordHash
                                )
                            }
                        }
                    }
                } catch (exception: SQLException) {
                    if (exception.message?.contains("UNIQUE constraint failed: users.phone") == true) {
                        null
                    } else {
                        throw exception
                    }
                }
            }
        }
    }

    override fun findByPhone(phone: String): User? {
        val sql = """
            SELECT id, phone, nickname, telegram_id, is_admin, is_approved, is_banned, password_hash
            FROM users
            WHERE phone = ?
            LIMIT 1
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                statement.setString(1, phone)
                statement.executeQuery().use { resultSet ->
                    if (!resultSet.next()) {
                        null
                    } else {
                        resultSet.toUser()
                    }
                }
            }
        }
    }

    override fun listUsers(): List<User> {
        val sql = """
            SELECT id, phone, nickname, telegram_id, is_admin, is_approved, is_banned, password_hash
            FROM users
            ORDER BY id ASC
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                statement.executeQuery().use { resultSet ->
                    buildList {
                        while (resultSet.next()) {
                            add(resultSet.toUser())
                        }
                    }
                }
            }
        }
    }

    override fun findById(userId: Long): User? {
        val sql = """
            SELECT id, phone, nickname, telegram_id, is_admin, is_approved, is_banned, password_hash
            FROM users
            WHERE id = ?
            LIMIT 1
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                statement.setLong(1, userId)
                statement.executeQuery().use { resultSet ->
                    if (!resultSet.next()) {
                        null
                    } else {
                        resultSet.toUser()
                    }
                }
            }
        }
    }

    override fun updateIsAdmin(userId: Long, isAdmin: Boolean): Boolean {
        val sql = """
            UPDATE users
            SET is_admin = ?
            WHERE id = ?
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                statement.setInt(1, if (isAdmin) 1 else 0)
                statement.setLong(2, userId)
                statement.executeUpdate() > 0
            }
        }
    }

    override fun updateApproval(userId: Long, isApproved: Boolean): Boolean {
        val sql = """
            UPDATE users
            SET is_approved = ?
            WHERE id = ?
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                statement.setInt(1, if (isApproved) 1 else 0)
                statement.setLong(2, userId)
                statement.executeUpdate() > 0
            }
        }
    }

    override fun updateBan(userId: Long, isBanned: Boolean): Boolean {
        val sql = """
            UPDATE users
            SET is_banned = ?
            WHERE id = ?
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                statement.setInt(1, if (isBanned) 1 else 0)
                statement.setLong(2, userId)
                statement.executeUpdate() > 0
            }
        }
    }

    private fun java.sql.ResultSet.toUser(): User {
        return User(
            id = getLong("id"),
            phone = getString("phone"),
            nickname = getString("nickname"),
            telegramId = getObject("telegram_id")?.let {
                (it as Number).toLong()
            },
            isAdmin = getInt("is_admin") == 1,
            isApproved = getInt("is_approved") == 1,
            isBanned = getInt("is_banned") == 1,
            passwordHash = getString("password_hash")
        )
    }
}
