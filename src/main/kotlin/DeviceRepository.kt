package org.example

import java.sql.Statement

data class Device(
    val id: Long,
    val userId: Long,
    val name: String
)

interface DeviceRepository {
    fun createDevice(userId: Long, name: String): Device
    fun listDevices(userId: Long): List<Device>
    fun findDevice(userId: Long, deviceId: Long): Device?
    fun findById(deviceId: Long): Device?
    fun updateDevice(userId: Long, deviceId: Long, name: String): Device?
    fun deleteDevice(userId: Long, deviceId: Long): Boolean
}

class SqliteDeviceRepository(
    private val databaseFactory: DatabaseFactory
) : DeviceRepository {

    override fun createDevice(userId: Long, name: String): Device {
        val sql = """
            INSERT INTO devices(user_id, name)
            VALUES(?, ?)
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS).use { statement ->
                statement.setLong(1, userId)
                statement.setString(2, name)
                statement.executeUpdate()

                statement.generatedKeys.use { generatedKeys ->
                    check(generatedKeys.next()) { "Failed to create device" }
                    Device(
                        id = generatedKeys.getLong(1),
                        userId = userId,
                        name = name
                    )
                }
            }
        }
    }

    override fun listDevices(userId: Long): List<Device> {
        val sql = """
            SELECT id, user_id, name
            FROM devices
            WHERE user_id = ?
            ORDER BY id ASC
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                statement.setLong(1, userId)
                statement.executeQuery().use { resultSet ->
                    buildList {
                        while (resultSet.next()) {
                            add(resultSet.toDevice())
                        }
                    }
                }
            }
        }
    }

    override fun findDevice(userId: Long, deviceId: Long): Device? {
        val sql = """
            SELECT id, user_id, name
            FROM devices
            WHERE user_id = ? AND id = ?
            LIMIT 1
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                statement.setLong(1, userId)
                statement.setLong(2, deviceId)
                statement.executeQuery().use { resultSet ->
                    if (resultSet.next()) resultSet.toDevice() else null
                }
            }
        }
    }

    override fun findById(deviceId: Long): Device? {
        val sql = """
            SELECT id, user_id, name
            FROM devices
            WHERE id = ?
            LIMIT 1
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                statement.setLong(1, deviceId)
                statement.executeQuery().use { resultSet ->
                    if (resultSet.next()) resultSet.toDevice() else null
                }
            }
        }
    }

    override fun updateDevice(userId: Long, deviceId: Long, name: String): Device? {
        val sql = """
            UPDATE devices
            SET name = ?, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ? AND id = ?
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                statement.setString(1, name)
                statement.setLong(2, userId)
                statement.setLong(3, deviceId)
                val updatedRows = statement.executeUpdate()
                if (updatedRows == 0) null else findDevice(userId, deviceId)
            }
        }
    }

    override fun deleteDevice(userId: Long, deviceId: Long): Boolean {
        val sql = """
            DELETE FROM devices
            WHERE user_id = ? AND id = ?
        """.trimIndent()

        return databaseFactory.connection().use { connection ->
            connection.prepareStatement(sql).use { statement ->
                statement.setLong(1, userId)
                statement.setLong(2, deviceId)
                statement.executeUpdate() > 0
            }
        }
    }

    private fun java.sql.ResultSet.toDevice(): Device {
        return Device(
            id = getLong("id"),
            userId = getLong("user_id"),
            name = getString("name")
        )
    }
}
