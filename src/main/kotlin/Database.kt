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
            createServersTable(connection)
        }
    }

    fun connection(): Connection {
        return DriverManager.getConnection("jdbc:sqlite:${databasePath.toAbsolutePath()}").also { connection ->
            connection.createStatement().use { statement ->
                statement.execute("PRAGMA foreign_keys = ON")
                statement.execute("PRAGMA busy_timeout = 5000")
                statement.execute("PRAGMA journal_mode = WAL")
                statement.execute("PRAGMA synchronous = NORMAL")
            }
        }
    }

    fun <T> transaction(block: (Connection) -> T): T {
        return connection().use { connection ->
            val previousAutoCommit = connection.autoCommit
            connection.autoCommit = false
            try {
                val result = block(connection)
                connection.commit()
                result
            } catch (exception: Throwable) {
                runCatching { connection.rollback() }
                throw exception
            } finally {
                connection.autoCommit = previousAutoCommit
            }
        }
    }

    private fun ensureUsersTable(connection: Connection) {
        var columns = userTableColumns(connection)

        when {
            columns.isEmpty() -> {
                createUsersTable(connection)
                columns = userTableColumns(connection)
            }
            "phone" !in columns -> {
                connection.createStatement().use { statement ->
                    statement.executeUpdate("ALTER TABLE users RENAME TO users_legacy")
                }
                createUsersTable(connection)
                columns = userTableColumns(connection)
            }
            "telegram_id" !in columns -> {
                connection.createStatement().use { statement ->
                    statement.executeUpdate("ALTER TABLE users ADD COLUMN telegram_id INTEGER")
                }
                columns = userTableColumns(connection)
            }
        }

        if ("is_admin" !in columns) {
            connection.createStatement().use { statement ->
                statement.executeUpdate("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
            }
            columns = userTableColumns(connection)
        }

        if ("nickname" !in columns) {
            connection.createStatement().use { statement ->
                statement.executeUpdate("ALTER TABLE users ADD COLUMN nickname TEXT NOT NULL DEFAULT ''")
            }
            columns = userTableColumns(connection)
        }

        if ("is_approved" !in columns) {
            connection.createStatement().use { statement ->
                statement.executeUpdate("ALTER TABLE users ADD COLUMN is_approved INTEGER NOT NULL DEFAULT 0")
            }
            columns = userTableColumns(connection)
        }

        if ("is_banned" !in columns) {
            connection.createStatement().use { statement ->
                statement.executeUpdate("ALTER TABLE users ADD COLUMN is_banned INTEGER NOT NULL DEFAULT 0")
            }
        }

        ensureDevicesTable(connection)
        ensureDeviceServersTable(connection)
    }

    private fun userTableColumns(connection: Connection): MutableSet<String> {
        val columns = mutableSetOf<String>()
        connection.createStatement().use { statement ->
            statement.executeQuery("PRAGMA table_info(users)").use { resultSet ->
                while (resultSet.next()) {
                    columns += resultSet.getString("name")
                }
            }
        }
        return columns
    }

    private fun createUsersTable(connection: Connection) {
        connection.createStatement().use { statement ->
            statement.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    phone TEXT NOT NULL UNIQUE,
                    nickname TEXT NOT NULL,
                    telegram_id INTEGER,
                    is_admin INTEGER NOT NULL DEFAULT 0,
                    is_approved INTEGER NOT NULL DEFAULT 0,
                    is_banned INTEGER NOT NULL DEFAULT 0,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """.trimIndent()
            )
        }
    }

    private fun ensureDevicesTable(connection: Connection) {
        val columns = mutableSetOf<String>()
        connection.createStatement().use { statement ->
            statement.executeQuery("PRAGMA table_info(devices)").use { resultSet ->
                while (resultSet.next()) {
                    columns += resultSet.getString("name")
                }
            }
        }

        when {
            columns.isEmpty() -> createDevicesTable(connection)
            "config" in columns -> {
                connection.createStatement().use { statement ->
                    statement.executeUpdate("ALTER TABLE devices RENAME TO devices_legacy")
                }
                createDevicesTable(connection)
                connection.createStatement().use { statement ->
                    statement.executeUpdate(
                        """
                        INSERT INTO devices(id, user_id, name, created_at, updated_at)
                        SELECT id, user_id, name, created_at, updated_at
                        FROM devices_legacy
                        """.trimIndent()
                    )
                    statement.executeUpdate("DROP TABLE devices_legacy")
                }
            }
        }
    }

    private fun createDevicesTable(connection: Connection) {
        connection.createStatement().use { statement ->
            statement.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """.trimIndent()
            )
        }
    }

    private fun ensureDeviceServersTable(connection: Connection) {
        val columns = mutableSetOf<String>()
        connection.createStatement().use { statement ->
            statement.executeQuery("PRAGMA table_info(device_servers)").use { resultSet ->
                while (resultSet.next()) {
                    columns += resultSet.getString("name")
                }
            }
        }
        val foreignKeyTables = mutableSetOf<String>()
        connection.createStatement().use { statement ->
            statement.executeQuery("PRAGMA foreign_key_list(device_servers)").use { resultSet ->
                while (resultSet.next()) {
                    foreignKeyTables += resultSet.getString("table")
                }
            }
        }

        when {
            columns.isEmpty() -> createDeviceServersTable(connection)
            "id" !in columns || "devices" !in foreignKeyTables || "devices_legacy" in foreignKeyTables -> {
                connection.createStatement().use { statement ->
                    statement.executeUpdate("ALTER TABLE device_servers RENAME TO device_servers_legacy")
                }
                createDeviceServersTable(connection)
                connection.createStatement().use { statement ->
                    statement.executeUpdate(
                        """
                        INSERT INTO device_servers(id, device_id, server_id, config, created_at, updated_at)
                        SELECT rowid, device_id, server_id, config, created_at, updated_at
                        FROM device_servers_legacy
                        """.trimIndent()
                    )
                    statement.executeUpdate("DROP TABLE device_servers_legacy")
                }
            }
        }
    }

    private fun createDeviceServersTable(connection: Connection) {
        connection.createStatement().use { statement ->
            statement.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS device_servers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER NOT NULL,
                    server_id INTEGER NOT NULL,
                    config TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (device_id, server_id),
                    FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
                    FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
                )
                """.trimIndent()
            )
        }
    }

    private fun createServersTable(connection: Connection) {
        connection.createStatement().use { statement ->
            statement.executeUpdate(
                """
                CREATE TABLE IF NOT EXISTS servers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    location TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT,
                    ssh_key_path TEXT,
                    container_name TEXT NOT NULL,
                    container_config_dir TEXT NOT NULL,
                    interface_name TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """.trimIndent()
            )
        }
    }
}
