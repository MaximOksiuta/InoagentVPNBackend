package org.example

import java.sql.Statement

data class Server(
    val id: Long,
    val name: String,
    val location: String,
    val connection: AwgConnection
)

interface ServerRepository {
    fun createServer(name: String, location: String, connection: AwgConnection): Server
    fun listServers(): List<Server>
    fun findServer(serverId: Long): Server?
    fun updateServer(serverId: Long, name: String, location: String, connection: AwgConnection): Server?
    fun deleteServer(serverId: Long): Boolean
}

class SqliteServerRepository(
    private val databaseFactory: DatabaseFactory
) : ServerRepository {

    override fun createServer(name: String, location: String, connection: AwgConnection): Server {
        val sql = """
            INSERT INTO servers(
                name,
                location,
                host,
                port,
                username,
                password,
                ssh_key_path,
                container_name,
                container_config_dir,
                interface_name
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """.trimIndent()

        return databaseFactory.connection().use { db ->
            db.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS).use { statement ->
                bindServer(statement, name, location, connection)
                statement.executeUpdate()
                statement.generatedKeys.use { keys ->
                    check(keys.next()) { "Failed to create server" }
                    Server(
                        id = keys.getLong(1),
                        name = name,
                        location = location,
                        connection = connection
                    )
                }
            }
        }
    }

    override fun listServers(): List<Server> {
        val sql = """
            SELECT id, name, location, host, port, username, password, ssh_key_path, container_name, container_config_dir, interface_name
            FROM servers
            ORDER BY id ASC
        """.trimIndent()

        return databaseFactory.connection().use { db ->
            db.prepareStatement(sql).use { statement ->
                statement.executeQuery().use { resultSet ->
                    buildList {
                        while (resultSet.next()) {
                            add(resultSet.toServer())
                        }
                    }
                }
            }
        }
    }

    override fun findServer(serverId: Long): Server? {
        val sql = """
            SELECT id, name, location, host, port, username, password, ssh_key_path, container_name, container_config_dir, interface_name
            FROM servers
            WHERE id = ?
            LIMIT 1
        """.trimIndent()

        return databaseFactory.connection().use { db ->
            db.prepareStatement(sql).use { statement ->
                statement.setLong(1, serverId)
                statement.executeQuery().use { resultSet ->
                    if (resultSet.next()) resultSet.toServer() else null
                }
            }
        }
    }

    override fun updateServer(serverId: Long, name: String, location: String, connection: AwgConnection): Server? {
        val sql = """
            UPDATE servers
            SET
                name = ?,
                location = ?,
                host = ?,
                port = ?,
                username = ?,
                password = ?,
                ssh_key_path = ?,
                container_name = ?,
                container_config_dir = ?,
                interface_name = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """.trimIndent()

        return databaseFactory.connection().use { db ->
            db.prepareStatement(sql).use { statement ->
                bindServer(statement, name, location, connection)
                statement.setLong(11, serverId)
                val updatedRows = statement.executeUpdate()
                if (updatedRows == 0) null else findServer(serverId)
            }
        }
    }

    override fun deleteServer(serverId: Long): Boolean {
        val sql = """
            DELETE FROM servers
            WHERE id = ?
        """.trimIndent()

        return databaseFactory.connection().use { db ->
            db.prepareStatement(sql).use { statement ->
                statement.setLong(1, serverId)
                statement.executeUpdate() > 0
            }
        }
    }

    private fun bindServer(
        statement: java.sql.PreparedStatement,
        name: String,
        location: String,
        connection: AwgConnection
    ) {
        statement.setString(1, name)
        statement.setString(2, location)
        statement.setString(3, connection.host)
        statement.setInt(4, connection.port)
        statement.setString(5, connection.username)
        statement.setString(6, connection.password)
        statement.setString(7, connection.sshKeyPath)
        statement.setString(8, connection.containerName)
        statement.setString(9, connection.containerConfigDir)
        statement.setString(10, connection.interfaceName)
    }

    private fun java.sql.ResultSet.toServer(): Server {
        return Server(
            id = getLong("id"),
            name = getString("name"),
            location = getString("location"),
            connection = AwgConnection(
                host = getString("host"),
                port = getInt("port"),
                username = getString("username"),
                password = getString("password"),
                sshKeyPath = getString("ssh_key_path"),
                containerName = getString("container_name"),
                containerConfigDir = getString("container_config_dir"),
                interfaceName = getString("interface_name")
            )
        )
    }
}
