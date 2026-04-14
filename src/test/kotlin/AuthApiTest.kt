package org.example

import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.testing.testApplication
import io.ktor.server.config.MapApplicationConfig
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class AuthApiTest {

    @Test
    fun `jwt auth flow works`() = testApplication {
        environment {
            config = MapApplicationConfig()
        }
        val appConfig = testConfig()
        application {
            val databaseFactory = DatabaseFactory(appConfig.databasePath)
            databaseFactory.initialize()
            module(
                userRepository = SqliteUserRepository(databaseFactory),
                deviceRepository = SqliteDeviceRepository(databaseFactory),
                deviceServerRepository = SqliteDeviceServerRepository(databaseFactory),
                serverRepository = SqliteServerRepository(databaseFactory),
                jwtService = JwtService(appConfig.jwt),
                appConfig = appConfig
            )
        }

        val client = createClient {
            install(ContentNegotiation) {
                json()
            }
        }

        val registerResponse = client.post("/api/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest(phone = "+79991234567", password = "strongpass123", telegramId = 123L))
        }
        assertEquals(HttpStatusCode.Created, registerResponse.status)

        val loginResponse = client.post("/api/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest(phone = "+79991234567", password = "strongpass123"))
        }
        assertEquals(HttpStatusCode.OK, loginResponse.status)

        val token = loginResponse.body<AuthTokenResponse>().accessToken
        assertNotNull(token)

        val meResponse = client.get("/api/auth/me") {
            header(HttpHeaders.Authorization, "Bearer $token")
        }
        assertEquals(HttpStatusCode.OK, meResponse.status)
        assertEquals(
            CurrentUserResponse(id = 1L, phone = "+79991234567", telegramId = 123L, isAdmin = false),
            meResponse.body()
        )
    }

    @Test
    fun `super key auth flow works`() = testApplication {
        environment {
            config = MapApplicationConfig()
        }
        val appConfig = testConfig()
        application {
            val databaseFactory = DatabaseFactory(appConfig.databasePath)
            databaseFactory.initialize()
            module(
                userRepository = SqliteUserRepository(databaseFactory),
                deviceRepository = SqliteDeviceRepository(databaseFactory),
                deviceServerRepository = SqliteDeviceServerRepository(databaseFactory),
                serverRepository = SqliteServerRepository(databaseFactory),
                jwtService = JwtService(appConfig.jwt),
                appConfig = appConfig
            )
        }

        val client = createClient {
            install(ContentNegotiation) {
                json()
            }
        }

        client.post("/api/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest(phone = "+79991112233", password = "strongpass123", telegramId = null))
        }

        val meResponse = client.get("/api/auth/me") {
            header("X-Super-Key", appConfig.superKey)
            header("X-Phone", "+79991112233")
        }

        assertEquals(HttpStatusCode.OK, meResponse.status)
        assertEquals(
            CurrentUserResponse(id = 1L, phone = "+79991112233", telegramId = null, isAdmin = false),
            meResponse.body()
        )
    }

    @Test
    fun `me returns isAdmin for admin user`() = testApplication {
        environment {
            config = MapApplicationConfig()
        }
        val appConfig = testConfig()
        val databaseFactory = DatabaseFactory(appConfig.databasePath)
        databaseFactory.initialize()
        val userRepository = SqliteUserRepository(databaseFactory)
        application {
            module(
                userRepository = userRepository,
                deviceRepository = SqliteDeviceRepository(databaseFactory),
                deviceServerRepository = SqliteDeviceServerRepository(databaseFactory),
                serverRepository = SqliteServerRepository(databaseFactory),
                jwtService = JwtService(appConfig.jwt),
                appConfig = appConfig
            )
        }

        val client = createClient {
            install(ContentNegotiation) {
                json()
            }
        }

        client.post("/api/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest(phone = "+79991110000", password = "strongpass123", telegramId = null))
        }
        val user = userRepository.findByPhone("+79991110000")!!
        userRepository.updateIsAdmin(user.id, true)

        val loginResponse = client.post("/api/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest(phone = "+79991110000", password = "strongpass123"))
        }
        val token = loginResponse.body<AuthTokenResponse>().accessToken

        val meResponse = client.get("/api/auth/me") {
            header(HttpHeaders.Authorization, "Bearer $token")
        }
        assertEquals(HttpStatusCode.OK, meResponse.status)
        assertEquals(
            CurrentUserResponse(id = 1L, phone = "+79991110000", telegramId = null, isAdmin = true),
            meResponse.body()
        )
    }

    @Test
    fun `invalid auth is rejected`() = testApplication {
        environment {
            config = MapApplicationConfig()
        }
        val appConfig = testConfig()
        application {
            val databaseFactory = DatabaseFactory(appConfig.databasePath)
            databaseFactory.initialize()
            module(
                userRepository = SqliteUserRepository(databaseFactory),
                deviceRepository = SqliteDeviceRepository(databaseFactory),
                deviceServerRepository = SqliteDeviceServerRepository(databaseFactory),
                serverRepository = SqliteServerRepository(databaseFactory),
                jwtService = JwtService(appConfig.jwt),
                appConfig = appConfig
            )
        }

        val client = createClient {
            install(ContentNegotiation) {
                json()
            }
        }

        val response = client.get("/api/auth/me")
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        assertEquals("""{"message":"Invalid credentials"}""", response.bodyAsText())
    }

    @Test
    fun `device crud flow works with server configs for current user only`() = testApplication {
        environment {
            config = MapApplicationConfig()
        }
        val appConfig = testConfig()
        val databaseFactory = DatabaseFactory(appConfig.databasePath)
        databaseFactory.initialize()
        val userRepository = SqliteUserRepository(databaseFactory)
        val deviceServerRepository = SqliteDeviceServerRepository(databaseFactory)
        application {
            module(
                userRepository = userRepository,
                deviceRepository = SqliteDeviceRepository(databaseFactory),
                deviceServerRepository = deviceServerRepository,
                serverRepository = SqliteServerRepository(databaseFactory),
                jwtService = JwtService(appConfig.jwt),
                appConfig = appConfig
            )
        }

        val client = createClient {
            install(ContentNegotiation) {
                json()
            }
        }

        client.post("/api/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest(phone = "+79990000001", password = "strongpass123", telegramId = 11L))
        }
        val firstUser = userRepository.findByPhone("+79990000001")!!
        userRepository.updateIsAdmin(firstUser.id, true)

        val loginResponse = client.post("/api/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest(phone = "+79990000001", password = "strongpass123"))
        }
        val token = loginResponse.body<AuthTokenResponse>().accessToken

        val createServerResponse = client.post("/api/servers") {
            header(HttpHeaders.Authorization, "Bearer $token")
            contentType(ContentType.Application.Json)
            setBody(
                UpsertServerRequest(
                    name = "Main Server",
                    location = "Warsaw",
                    host = "10.0.0.1",
                    port = 22,
                    username = "root",
                    password = null,
                    sshKeyPath = "/keys/main",
                    containerName = "amnezia-awg2",
                    containerConfigDir = "/opt/amnezia/awg",
                    interfaceName = "awg0"
                )
            )
        }
        assertEquals(HttpStatusCode.Created, createServerResponse.status)
        val createdServer = createServerResponse.body<ServerResponse>()

        client.post("/api/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest(phone = "+79990000002", password = "strongpass123", telegramId = 22L))
        }

        val createResponse = client.post("/api/devices") {
            header(HttpHeaders.Authorization, "Bearer $token")
            contentType(ContentType.Application.Json)
            setBody(CreateDeviceRequest(name = "iPhone"))
        }
        assertEquals(HttpStatusCode.Created, createResponse.status)
        val createdDevice = createResponse.body<DeviceResponse>()
        assertEquals("iPhone", createdDevice.name)
        assertEquals(DeviceResponse(id = createdDevice.id, name = "iPhone"), createdDevice)

        val deviceServerConfig = deviceServerRepository.upsert(
            createdDevice.id,
            createdServer.id,
            "[Interface]\nPrivateKey=abc"
        )

        val listResponse = client.get("/api/devices") {
            header(HttpHeaders.Authorization, "Bearer $token")
        }
        assertEquals(HttpStatusCode.OK, listResponse.status)
        assertEquals(
            listOf(
                DeviceResponse(
                    id = createdDevice.id,
                    name = "iPhone"
                )
            ),
            listResponse.body()
        )

        val getResponse = client.get("/api/devices/${createdDevice.id}") {
            header(HttpHeaders.Authorization, "Bearer $token")
        }
        assertEquals(HttpStatusCode.OK, getResponse.status)
        assertEquals(
            DeviceDetailsResponse(
                id = createdDevice.id,
                name = "iPhone",
                configs = listOf(
                    DeviceServerResponse(
                        id = deviceServerConfig.id,
                        serverId = createdServer.id,
                        serverName = "Main Server",
                        serverLocation = "Warsaw",
                        config = "[Interface]\nPrivateKey=abc"
                    )
                )
            ),
            getResponse.body()
        )

        val updateResponse = client.put("/api/devices/${createdDevice.id}") {
            header(HttpHeaders.Authorization, "Bearer $token")
            contentType(ContentType.Application.Json)
            setBody(UpdateDeviceRequest(name = "MacBook"))
        }
        assertEquals(HttpStatusCode.OK, updateResponse.status)
        assertEquals(
            DeviceDetailsResponse(
                id = createdDevice.id,
                name = "MacBook",
                configs = listOf(
                    DeviceServerResponse(
                        id = deviceServerConfig.id,
                        serverId = createdServer.id,
                        serverName = "Main Server",
                        serverLocation = "Warsaw",
                        config = "[Interface]\nPrivateKey=abc"
                    )
                )
            ),
            updateResponse.body()
        )

        val forbiddenByOwnership = client.get("/api/devices/${createdDevice.id}") {
            header("X-Super-Key", appConfig.superKey)
            header("X-Phone", "+79990000002")
        }
        assertEquals(HttpStatusCode.NotFound, forbiddenByOwnership.status)

        val deleteResponse = client.delete("/api/devices/${createdDevice.id}") {
            header(HttpHeaders.Authorization, "Bearer $token")
        }
        assertEquals(HttpStatusCode.NoContent, deleteResponse.status)

        val afterDelete = client.get("/api/devices/${createdDevice.id}") {
            header(HttpHeaders.Authorization, "Bearer $token")
        }
        assertEquals(HttpStatusCode.NotFound, afterDelete.status)
    }

    @Test
    fun `device config can be generated saved and returned`() = testApplication {
        environment {
            config = MapApplicationConfig()
        }
        val appConfig = testConfig()
        val databaseFactory = DatabaseFactory(appConfig.databasePath)
        databaseFactory.initialize()
        val userRepository = SqliteUserRepository(databaseFactory)
        val fakeGenerator = object : DeviceConfigGenerator {
            override fun generate(server: Server, user: User, device: Device): GeneratedDeviceConfig {
                return GeneratedDeviceConfig(
                    clientId = "fake-client-id",
                    config = "[Interface]\nPrivateKey=fake\n# ${server.name} ${user.id} ${device.id}"
                )
            }
        }

        application {
            module(
                userRepository = userRepository,
                deviceRepository = SqliteDeviceRepository(databaseFactory),
                deviceServerRepository = SqliteDeviceServerRepository(databaseFactory),
                serverRepository = SqliteServerRepository(databaseFactory),
                jwtService = JwtService(appConfig.jwt),
                appConfig = appConfig,
                deviceConfigGenerator = fakeGenerator
            )
        }

        val client = createClient {
            install(ContentNegotiation) {
                json()
            }
        }

        client.post("/api/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest(phone = "+79990000055", password = "strongpass123", telegramId = null))
        }
        val user = userRepository.findByPhone("+79990000055")!!
        userRepository.updateIsAdmin(user.id, true)

        val loginResponse = client.post("/api/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest(phone = "+79990000055", password = "strongpass123"))
        }
        val token = loginResponse.body<AuthTokenResponse>().accessToken

        val serverResponse = client.post("/api/servers") {
            header(HttpHeaders.Authorization, "Bearer $token")
            contentType(ContentType.Application.Json)
            setBody(
                UpsertServerRequest(
                    name = "Generator Server",
                    location = "Riga",
                    host = "192.0.2.10",
                    port = 22,
                    username = "root",
                    password = null,
                    sshKeyPath = "/keys/test",
                    containerName = "amnezia-awg2",
                    containerConfigDir = "/opt/amnezia/awg",
                    interfaceName = "awg0"
                )
            )
        }
        val createdServer = serverResponse.body<ServerResponse>()

        val deviceResponse = client.post("/api/devices") {
            header(HttpHeaders.Authorization, "Bearer $token")
            contentType(ContentType.Application.Json)
            setBody(CreateDeviceRequest(name = "Pixel"))
        }
        val createdDevice = deviceResponse.body<DeviceResponse>()

        val generateResponse = client.post("/api/devices/${createdDevice.id}/configs/generate") {
            header(HttpHeaders.Authorization, "Bearer $token")
            contentType(ContentType.Application.Json)
            setBody(GenerateDeviceConfigRequest(serverId = createdServer.id))
        }
        assertEquals(HttpStatusCode.OK, generateResponse.status)
        val generatedConfig = generateResponse.body<DeviceServerResponse>()
        assertEquals(createdServer.id, generatedConfig.serverId)
        assertEquals("Generator Server", generatedConfig.serverName)
        assertEquals("Riga", generatedConfig.serverLocation)
        assertEquals("[Interface]\nPrivateKey=fake\n# Generator Server ${user.id} ${createdDevice.id}", generatedConfig.config)

        val detailsResponse = client.get("/api/devices/${createdDevice.id}") {
            header(HttpHeaders.Authorization, "Bearer $token")
        }
        assertEquals(HttpStatusCode.OK, detailsResponse.status)
        assertEquals(
            DeviceDetailsResponse(
                id = createdDevice.id,
                name = "Pixel",
                configs = listOf(generatedConfig)
            ),
            detailsResponse.body()
        )
    }

    @Test
    fun `cannot generate config twice for same device and server`() = testApplication {
        environment {
            config = MapApplicationConfig()
        }
        val appConfig = testConfig()
        val databaseFactory = DatabaseFactory(appConfig.databasePath)
        databaseFactory.initialize()
        val userRepository = SqliteUserRepository(databaseFactory)
        val fakeGenerator = object : DeviceConfigGenerator {
            override fun generate(server: Server, user: User, device: Device): GeneratedDeviceConfig {
                return GeneratedDeviceConfig(
                    clientId = "duplicate-client-id",
                    config = "generated-config"
                )
            }
        }

        application {
            module(
                userRepository = userRepository,
                deviceRepository = SqliteDeviceRepository(databaseFactory),
                deviceServerRepository = SqliteDeviceServerRepository(databaseFactory),
                serverRepository = SqliteServerRepository(databaseFactory),
                jwtService = JwtService(appConfig.jwt),
                appConfig = appConfig,
                deviceConfigGenerator = fakeGenerator
            )
        }

        val client = createClient {
            install(ContentNegotiation) {
                json()
            }
        }

        client.post("/api/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest(phone = "+79990000066", password = "strongpass123", telegramId = null))
        }
        val user = userRepository.findByPhone("+79990000066")!!
        userRepository.updateIsAdmin(user.id, true)

        val loginResponse = client.post("/api/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest(phone = "+79990000066", password = "strongpass123"))
        }
        val token = loginResponse.body<AuthTokenResponse>().accessToken

        val serverResponse = client.post("/api/servers") {
            header(HttpHeaders.Authorization, "Bearer $token")
            contentType(ContentType.Application.Json)
            setBody(
                UpsertServerRequest(
                    name = "Dup Server",
                    location = "Tallinn",
                    host = "192.0.2.11",
                    port = 22,
                    username = "root",
                    password = null,
                    sshKeyPath = "/keys/test",
                    containerName = "amnezia-awg2",
                    containerConfigDir = "/opt/amnezia/awg",
                    interfaceName = "awg0"
                )
            )
        }
        val createdServer = serverResponse.body<ServerResponse>()

        val deviceResponse = client.post("/api/devices") {
            header(HttpHeaders.Authorization, "Bearer $token")
            contentType(ContentType.Application.Json)
            setBody(CreateDeviceRequest(name = "Galaxy"))
        }
        val createdDevice = deviceResponse.body<DeviceResponse>()

        val firstGenerate = client.post("/api/devices/${createdDevice.id}/configs/generate") {
            header(HttpHeaders.Authorization, "Bearer $token")
            contentType(ContentType.Application.Json)
            setBody(GenerateDeviceConfigRequest(serverId = createdServer.id))
        }
        assertEquals(HttpStatusCode.OK, firstGenerate.status)

        val secondGenerate = client.post("/api/devices/${createdDevice.id}/configs/generate") {
            header(HttpHeaders.Authorization, "Bearer $token")
            contentType(ContentType.Application.Json)
            setBody(GenerateDeviceConfigRequest(serverId = createdServer.id))
        }
        assertEquals(HttpStatusCode.Conflict, secondGenerate.status)
        assertEquals(
            """{"message":"Config for this device and server already exists"}""",
            secondGenerate.bodyAsText()
        )
    }

    @Test
    fun `non admin can view limited servers list but cannot manage servers`() = testApplication {
        environment {
            config = MapApplicationConfig()
        }
        val appConfig = testConfig()
        val databaseFactory = DatabaseFactory(appConfig.databasePath)
        databaseFactory.initialize()
        val userRepository = SqliteUserRepository(databaseFactory)
        application {
            module(
                userRepository = userRepository,
                deviceRepository = SqliteDeviceRepository(databaseFactory),
                deviceServerRepository = SqliteDeviceServerRepository(databaseFactory),
                serverRepository = SqliteServerRepository(databaseFactory),
                jwtService = JwtService(appConfig.jwt),
                appConfig = appConfig
            )
        }

        val client = createClient {
            install(ContentNegotiation) {
                json()
            }
        }

        client.post("/api/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest(phone = "+79990000100", password = "strongpass123", telegramId = null))
        }
        val adminUser = userRepository.findByPhone("+79990000100")!!
        userRepository.updateIsAdmin(adminUser.id, true)

        val adminLoginResponse = client.post("/api/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest(phone = "+79990000100", password = "strongpass123"))
        }
        val adminToken = adminLoginResponse.body<AuthTokenResponse>().accessToken

        val adminCreateServerResponse = client.post("/api/servers") {
            header(HttpHeaders.Authorization, "Bearer $adminToken")
            contentType(ContentType.Application.Json)
            setBody(
                UpsertServerRequest(
                    name = "Public Server",
                    location = "Helsinki",
                    host = "203.0.113.1",
                    port = 22,
                    username = "root",
                    password = null,
                    sshKeyPath = "/keys/pub",
                    containerName = "amnezia-awg2",
                    containerConfigDir = "/opt/amnezia/awg",
                    interfaceName = "awg0"
                )
            )
        }
        assertEquals(HttpStatusCode.Created, adminCreateServerResponse.status)

        client.post("/api/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest(phone = "+79990000101", password = "strongpass123", telegramId = null))
        }

        val loginResponse = client.post("/api/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest(phone = "+79990000101", password = "strongpass123"))
        }
        val token = loginResponse.body<AuthTokenResponse>().accessToken

        val response = client.get("/api/servers") {
            header(HttpHeaders.Authorization, "Bearer $token")
        }
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals(
            listOf(
                ServerListItemResponse(
                    id = 1L,
                    name = "Public Server",
                    location = "Helsinki"
                )
            ),
            response.body()
        )

        val forbiddenCreate = client.post("/api/servers") {
            header(HttpHeaders.Authorization, "Bearer $token")
            contentType(ContentType.Application.Json)
            setBody(
                UpsertServerRequest(
                    name = "Blocked Server",
                    location = "Oslo",
                    host = "203.0.113.2",
                    port = 22,
                    username = "root",
                    password = null,
                    sshKeyPath = "/keys/blocked",
                    containerName = "amnezia-awg2",
                    containerConfigDir = "/opt/amnezia/awg",
                    interfaceName = "awg0"
                )
            )
        }
        assertEquals(HttpStatusCode.Forbidden, forbiddenCreate.status)
        assertEquals("""{"message":"Admin access required"}""", forbiddenCreate.bodyAsText())
    }

    @Test
    fun `admin can manage servers`() = testApplication {
        environment {
            config = MapApplicationConfig()
        }
        val appConfig = testConfig()
        val databaseFactory = DatabaseFactory(appConfig.databasePath)
        databaseFactory.initialize()
        val userRepository = SqliteUserRepository(databaseFactory)

        application {
            module(
                userRepository = userRepository,
                deviceRepository = SqliteDeviceRepository(databaseFactory),
                deviceServerRepository = SqliteDeviceServerRepository(databaseFactory),
                serverRepository = SqliteServerRepository(databaseFactory),
                jwtService = JwtService(appConfig.jwt),
                appConfig = appConfig
            )
        }

        val client = createClient {
            install(ContentNegotiation) {
                json()
            }
        }

        client.post("/api/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest(phone = "+79990000111", password = "strongpass123", telegramId = 1L))
        }
        val adminUser = userRepository.findByPhone("+79990000111")!!
        userRepository.updateIsAdmin(adminUser.id, true)

        val loginResponse = client.post("/api/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest(phone = "+79990000111", password = "strongpass123"))
        }
        val token = loginResponse.body<AuthTokenResponse>().accessToken

        val createResponse = client.post("/api/servers") {
            header(HttpHeaders.Authorization, "Bearer $token")
            contentType(ContentType.Application.Json)
            setBody(
                UpsertServerRequest(
                    name = "Main Server",
                    location = "Frankfurt",
                    host = "1.2.3.4",
                    port = 2222,
                    username = "root",
                    password = "secret",
                    sshKeyPath = "/keys/id_rsa",
                    containerName = "amnezia-awg2",
                    containerConfigDir = "/opt/amnezia/awg",
                    interfaceName = "awg0"
                )
            )
        }
        assertEquals(HttpStatusCode.Created, createResponse.status)
        val createdServer = createResponse.body<ServerResponse>()

        val listResponse = client.get("/api/servers") {
            header(HttpHeaders.Authorization, "Bearer $token")
        }
        assertEquals(HttpStatusCode.OK, listResponse.status)
        assertEquals(
            listOf(
                ServerListItemResponse(
                    id = createdServer.id,
                    name = createdServer.name,
                    location = createdServer.location
                )
            ),
            listResponse.body()
        )

        val getResponse = client.get("/api/servers/${createdServer.id}") {
            header(HttpHeaders.Authorization, "Bearer $token")
        }
        assertEquals(HttpStatusCode.OK, getResponse.status)
        assertEquals(createdServer, getResponse.body())

        val updateResponse = client.put("/api/servers/${createdServer.id}") {
            header(HttpHeaders.Authorization, "Bearer $token")
            contentType(ContentType.Application.Json)
            setBody(
                UpsertServerRequest(
                    name = "Backup Server",
                    location = "Amsterdam",
                    host = "5.6.7.8",
                    port = 22,
                    username = "admin",
                    password = null,
                    sshKeyPath = "/keys/admin_rsa",
                    containerName = "awg-prod",
                    containerConfigDir = "/srv/awg",
                    interfaceName = "awg1"
                )
            )
        }
        assertEquals(HttpStatusCode.OK, updateResponse.status)
        assertEquals(
            ServerResponse(
                id = createdServer.id,
                name = "Backup Server",
                location = "Amsterdam",
                host = "5.6.7.8",
                port = 22,
                username = "admin",
                password = null,
                sshKeyPath = "/keys/admin_rsa",
                containerName = "awg-prod",
                containerConfigDir = "/srv/awg",
                interfaceName = "awg1"
            ),
            updateResponse.body()
        )

        val deleteResponse = client.delete("/api/servers/${createdServer.id}") {
            header(HttpHeaders.Authorization, "Bearer $token")
        }
        assertEquals(HttpStatusCode.NoContent, deleteResponse.status)

        val afterDelete = client.get("/api/servers/${createdServer.id}") {
            header(HttpHeaders.Authorization, "Bearer $token")
        }
        assertEquals(HttpStatusCode.NotFound, afterDelete.status)
    }

    private fun testConfig(): AppConfig {
        val tempDir = createTempDirectory("auth-api-test")
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
}
