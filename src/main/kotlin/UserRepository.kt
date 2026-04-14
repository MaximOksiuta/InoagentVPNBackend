package org.example

import java.sql.SQLException
import java.sql.Statement

data class User(
    val id: Long,
    val email: String,
    val passwordHash: String
)

interface UserRepository {
    fun createUser(email: String, passwordHash: String): User?
}

class SqliteUserRepository(
    private val databaseFactory: DatabaseFactory
) : UserRepository {

    override fun createUser(email: String, passwordHash: String): User? {
        val sql = """
            INSERT INTO users(email, password_hash)
            VALUES(?, ?)
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS).use { statement ->
                statement.setString(1, email)
                statement.setString(2, passwordHash)

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
                                    email = email,
                                    passwordHash = passwordHash
                                )
                            }
                        }
                    }
                } catch (exception: SQLException) {
                    if (exception.message?.contains("UNIQUE constraint failed: users.email") == true) {
                        null
                    } else {
                        throw exception
                    }
                }
            }
        }
    }
}
