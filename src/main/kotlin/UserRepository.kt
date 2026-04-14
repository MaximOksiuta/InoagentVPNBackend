package org.example

import java.sql.SQLException
import java.sql.Statement

data class User(
    val id: Long,
    val phone: String,
    val telegramId: Long?,
    val passwordHash: String
)

interface UserRepository {
    fun createUser(phone: String, telegramId: Long?, passwordHash: String): User?
    fun findByPhone(phone: String): User?
}

class SqliteUserRepository(
    private val databaseFactory: DatabaseFactory
) : UserRepository {

    override fun createUser(phone: String, telegramId: Long?, passwordHash: String): User? {
        val sql = """
            INSERT INTO users(phone, telegram_id, password_hash)
            VALUES(?, ?, ?)
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS).use { statement ->
                statement.setString(1, phone)
                if (telegramId == null) {
                    statement.setObject(2, null)
                } else {
                    statement.setLong(2, telegramId)
                }
                statement.setString(3, passwordHash)

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
                                    telegramId = telegramId,
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
            SELECT id, phone, telegram_id, password_hash
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
                        User(
                            id = resultSet.getLong("id"),
                            phone = resultSet.getString("phone"),
                            telegramId = resultSet.getObject("telegram_id")?.let {
                                (it as Number).toLong()
                            },
                            passwordHash = resultSet.getString("password_hash")
                        )
                    }
                }
            }
        }
    }
}
