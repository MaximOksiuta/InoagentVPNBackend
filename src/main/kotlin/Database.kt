package org.example

import java.nio.file.Files
import java.nio.file.Path
import java.sql.Connection
import java.sql.DriverManager

class DatabaseFactory(
    databasePath: String
) {
    private val databasePath: Path = Path.of(databasePath)

    init {
        Class.forName("org.sqlite.JDBC")
    }

    fun initialize() {
        databasePath.parent?.let { Files.createDirectories(it) }
        connection().use { connection ->
            ensureUsersTable(connection)
        }
    }

    fun connection(): Connection {
        return DriverManager.getConnection("jdbc:sqlite:${databasePath.toAbsolutePath()}")
    }

    private fun ensureUsersTable(connection: Connection) {
        val columns = mutableSetOf<String>()
        connection.createStatement().use { statement ->
            statement.executeQuery("PRAGMA table_info(users)").use { resultSet ->
                while (resultSet.next()) {
                    columns += resultSet.getString("name")
                }
            }
        }

        when {
            columns.isEmpty() -> createUsersTable(connection)
            "phone" !in columns -> {
                connection.createStatement().use { statement ->
                    statement.executeUpdate("ALTER TABLE users RENAME TO users_legacy")
                }
                createUsersTable(connection)
            }
            "telegram_id" !in columns -> {
                connection.createStatement().use { statement ->
                    statement.executeUpdate("ALTER TABLE users ADD COLUMN telegram_id INTEGER")
                }
            }
        }
    }

    private fun createUsersTable(connection: Connection) {
        connection.createStatement().use { statement ->
            statement.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    phone TEXT NOT NULL UNIQUE,
                    telegram_id INTEGER,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """.trimIndent()
            )
        }
    }
}
