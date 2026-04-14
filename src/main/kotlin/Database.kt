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
            connection.createStatement().use { statement ->
                statement.executeUpdate(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        email TEXT NOT NULL UNIQUE,
                        password_hash TEXT NOT NULL,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                    """.trimIndent()
                )
            }
        }
    }

    fun connection(): Connection {
        return DriverManager.getConnection("jdbc:sqlite:${databasePath.toAbsolutePath()}")
    }
}
