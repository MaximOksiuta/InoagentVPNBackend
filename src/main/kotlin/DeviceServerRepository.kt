package org.example

import java.sql.SQLException

data class DeviceServerConfig(
    val id: Long,
    val deviceId: Long,
    val serverId: Long,
    val config: String
)

interface DeviceServerRepository {
    fun listAll(): List<DeviceServerConfig>
    fun listByDevice(deviceId: Long): List<DeviceServerConfig>
    fun findByConfigId(configId: Long): DeviceServerConfig?
    fun findById(deviceId: Long, configId: Long): DeviceServerConfig?
    fun findByDeviceAndServer(deviceId: Long, serverId: Long): DeviceServerConfig?
    fun upsert(deviceId: Long, serverId: Long, config: String): DeviceServerConfig
    fun deleteByConfigId(configId: Long): Boolean
    fun delete(deviceId: Long, serverId: Long): Boolean
}

class SqliteDeviceServerRepository(
    private val databaseFactory: DatabaseFactory
) : DeviceServerRepository {

    override fun listAll(): List<DeviceServerConfig> {
        val sql = """
            SELECT id, device_id, server_id, config
            FROM device_servers
            ORDER BY id ASC
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                statement.executeQuery().use { resultSet ->
                    buildList {
                        while (resultSet.next()) {
                            add(resultSet.toDeviceServerConfig())
                        }
                    }
                }
            }
        }
    }

    override fun listByDevice(deviceId: Long): List<DeviceServerConfig> {
        val sql = """
            SELECT id, device_id, server_id, config
            FROM device_servers
            WHERE device_id = ?
            ORDER BY server_id ASC
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                statement.setLong(1, deviceId)
                statement.executeQuery().use { resultSet ->
                    buildList {
                        while (resultSet.next()) {
                            add(resultSet.toDeviceServerConfig())
                        }
                    }
                }
            }
        }
    }

    override fun findByConfigId(configId: Long): DeviceServerConfig? {
        val sql = """
            SELECT id, device_id, server_id, config
            FROM device_servers
            WHERE id = ?
            LIMIT 1
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                statement.setLong(1, configId)
                statement.executeQuery().use { resultSet ->
                    if (resultSet.next()) resultSet.toDeviceServerConfig() else null
                }
            }
        }
    }

    override fun findById(deviceId: Long, configId: Long): DeviceServerConfig? {
        val sql = """
            SELECT id, device_id, server_id, config
            FROM device_servers
            WHERE device_id = ? AND id = ?
            LIMIT 1
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                statement.setLong(1, deviceId)
                statement.setLong(2, configId)
                statement.executeQuery().use { resultSet ->
                    if (resultSet.next()) resultSet.toDeviceServerConfig() else null
                }
            }
        }
    }

    override fun findByDeviceAndServer(deviceId: Long, serverId: Long): DeviceServerConfig? {
        val sql = """
            SELECT id, device_id, server_id, config
            FROM device_servers
            WHERE device_id = ? AND server_id = ?
            LIMIT 1
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                statement.setLong(1, deviceId)
                statement.setLong(2, serverId)
                statement.executeQuery().use { resultSet ->
                    if (resultSet.next()) resultSet.toDeviceServerConfig() else null
                }
            }
        }
    }

    override fun upsert(deviceId: Long, serverId: Long, config: String): DeviceServerConfig {
        val updateSql = """
            UPDATE device_servers
            SET config = ?, updated_at = CURRENT_TIMESTAMP
            WHERE device_id = ? AND server_id = ?
        """.trimIndent()
        val insertSql = """
            INSERT INTO device_servers(device_id, server_id, config)
            VALUES(?, ?, ?)
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            val updated = connection.prepareStatement(updateSql).use { statement ->
                statement.setString(1, config)
                statement.setLong(2, deviceId)
                statement.setLong(3, serverId)
                statement.executeUpdate()
            }
            if (updated > 0) {
                return@use findByDeviceAndServer(deviceId, serverId)
                    ?: error("Failed to load updated device-server config")
            }

            try {
                connection.prepareStatement(insertSql).use { statement ->
                    statement.setLong(1, deviceId)
                    statement.setLong(2, serverId)
                    statement.setString(3, config)
                    statement.executeUpdate()
                }
            } catch (exception: SQLException) {
                if (exception.message?.contains("FOREIGN KEY constraint failed") == true) {
                    error("Device or server was not found")
                }
                throw exception
            }

            findByDeviceAndServer(deviceId, serverId)
                ?: error("Failed to load created device-server config")
        }
    }

    override fun delete(deviceId: Long, serverId: Long): Boolean {
        val sql = """
            DELETE FROM device_servers
            WHERE device_id = ? AND server_id = ?
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                statement.setLong(1, deviceId)
                statement.setLong(2, serverId)
                statement.executeUpdate() > 0
            }
        }
    }

    override fun deleteByConfigId(configId: Long): Boolean {
        val sql = """
            DELETE FROM device_servers
            WHERE id = ?
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                statement.setLong(1, configId)
                statement.executeUpdate() > 0
            }
        }
    }

    private fun java.sql.ResultSet.toDeviceServerConfig(): DeviceServerConfig {
        return DeviceServerConfig(
            id = getLong("id"),
            deviceId = getLong("device_id"),
            serverId = getLong("server_id"),
            config = getString("config")
        )
    }
}
