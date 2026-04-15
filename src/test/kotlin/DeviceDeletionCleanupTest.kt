package org.example

import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.delete
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.config.MapApplicationConfig
import io.ktor.server.testing.testApplication
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DeviceDeletionCleanupTest {

    @Test
    fun `deleting device cleans remote configs before deleting database rows`() = testApplication {
        environment {
            config = MapApplicationConfig()
        }

        val appConfig = testConfig()
        val databaseFactory = DatabaseFactory(appConfig.databasePath)
        databaseFactory.initialize()
        val userRepository = SqliteUserRepository(databaseFactory)
        val deviceRepository = SqliteDeviceRepository(databaseFactory)
        val deviceServerRepository = SqliteDeviceServerRepository(databaseFactory)
        val serverRepository = SqliteServerRepository(databaseFactory)
        val cleanupService = RecordingDeviceConfigCleanupService()

        application {
            module(
                userRepository = userRepository,
                deviceRepository = deviceRepository,
                deviceServerRepository = deviceServerRepository,
                serverRepository = serverRepository,
                jwtService = JwtService(appConfig.jwt),
                appConfig = appConfig,
                deviceConfigCleanupService = cleanupService
            )
        }

        val client = createClient {
            install(ContentNegotiation) {
                json()
            }
        }

        client.post("/api/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest(phone = "+79995550001", nickname = "admin", password = "strongpass123", telegramId = null))
        }
        val adminUser = userRepository.findByPhone("+79995550001")!!
        userRepository.updateApproval(adminUser.id, true)
        userRepository.updateIsAdmin(adminUser.id, true)

        val loginResponse = client.post("/api/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest(phone = "+79995550001", password = "strongpass123"))
        }
        val token = loginResponse.body<AuthTokenResponse>().accessToken

        val firstServer = serverRepository.createServer(
            name = "Main Server",
            location = "Warsaw",
            connection = AwgConnection(
                host = "10.0.0.1",
                port = 22,
                username = "root",
                password = "secret"
            )
        )
        val secondServer = serverRepository.createServer(
            name = "Backup Server",
            location = "Berlin",
            connection = AwgConnection(
                host = "10.0.0.2",
                port = 22,
                username = "root",
                password = "secret"
            )
        )

        val device = deviceRepository.createDevice(adminUser.id, "MacBook")
        val firstConfig = deviceServerRepository.upsert(device.id, firstServer.id, testAwgConfig())
        val secondConfig = deviceServerRepository.upsert(
            device.id,
            secondServer.id,
            testAwgConfig("LxXnv3lQkJ57D9j75QwF8n90DFyM54KfL8R4K0wVvXs=")
        )

        val deleteResponse = client.delete("/api/devices/${device.id}") {
            header(HttpHeaders.Authorization, "Bearer $token")
        }

        assertEquals(HttpStatusCode.NoContent, deleteResponse.status)
        assertEquals(2, cleanupService.cleanedConfigs.size)
        assertTrue(deviceRepository.findDevice(adminUser.id, device.id) == null)
        assertTrue(deviceServerRepository.listByDevice(device.id).isEmpty())
        assertEquals(setOf(firstServer.id, secondServer.id), cleanupService.cleanedConfigs.map { it.server.id }.toSet())
        assertEquals(setOf(firstConfig.id, secondConfig.id), cleanupService.cleanedConfigs.map { it.config.id }.toSet())
    }

    private fun testConfig(): AppConfig {
        val tempDir = createTempDirectory("device-delete-cleanup-test")
        return AppConfig(
            databasePath = tempDir.resolve("app.db").toString(),
            jwt = JwtConfig(
                secret = "test-jwt-secret",
                issuer = "test-issuer",
                audience = "test-audience",
                realm = "test-realm",
                expiresInMs = 60_000
            ),
            superKey = "test-super-key"
        )
    }

    private fun testAwgConfig(privateKey: String = "SC3OKU18vV4CVWQJfThf7n6vKJQnC0Xel0M5M7hzIUs="): String {
        return """
            [Interface]
            PrivateKey = $privateKey
            Address = 10.8.0.2/32
            DNS = 1.1.1.1

            [Peer]
            PublicKey = server-public-key
            PresharedKey = preshared-key
            Endpoint = 10.0.0.1:51820
            AllowedIPs = 0.0.0.0/0, ::/0
            PersistentKeepalive = 25
        """.trimIndent()
    }

    private class RecordingDeviceConfigCleanupService : DeviceConfigCleanupService {
        val cleanedConfigs = mutableListOf<CleanupCall>()

        override fun cleanup(server: Server, config: DeviceServerConfig) {
            cleanedConfigs += CleanupCall(server, config)
        }
    }

    private data class CleanupCall(
        val server: Server,
        val config: DeviceServerConfig
    )
}
