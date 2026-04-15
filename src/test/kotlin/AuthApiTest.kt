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
import kotlinx.coroutines.runBlocking
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class AuthApiTest {

    @Test
    fun `jwt auth flow works`() = testApplication {
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

        val registerResponse = client.post("/api/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest(phone = "+79991234567", nickname = "alice", password = "strongpass123", telegramId = 123L))
        }
        assertEquals(HttpStatusCode.Created, registerResponse.status)
        userRepository.approveByPhone("+79991234567")

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
            CurrentUserResponse(id = 1L, phone = "+79991234567", nickname = "alice", telegramId = 123L, isAdmin = false),
            meResponse.body()
        )
    }

    @Test
    fun `super key auth flow works`() = testApplication {
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
            setBody(RegisterRequest(phone = "+79991112233", nickname = "bob", password = "strongpass123", telegramId = null))
        }
        userRepository.approveByPhone("+79991112233")

        val meResponse = client.get("/api/auth/me") {
            header("X-Super-Key", appConfig.superKey)
            header("X-Phone", "+79991112233")
        }

        assertEquals(HttpStatusCode.OK, meResponse.status)
        assertEquals(
            CurrentUserResponse(id = 1L, phone = "+79991112233", nickname = "bob", telegramId = null, isAdmin = false),
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
            setBody(RegisterRequest(phone = "+79991110000", nickname = "admin", password = "strongpass123", telegramId = null))
        }
        val user = userRepository.findByPhone("+79991110000")!!
        userRepository.updateIsAdmin(user.id, true)
        userRepository.updateApproval(user.id, true)

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
            CurrentUserResponse(id = 1L, phone = "+79991110000", nickname = "admin", telegramId = null, isAdmin = true),
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
    fun `unapproved user cannot log in until admin approves`() = testApplication {
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
            setBody(RegisterRequest(phone = "+79992223344", nickname = "pending", password = "strongpass123", telegramId = null))
        }

        val rejectedLogin = client.post("/api/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest(phone = "+79992223344", password = "strongpass123"))
        }
        assertEquals(HttpStatusCode.Forbidden, rejectedLogin.status)
        assertEquals("""{"message":"User is not approved"}""", rejectedLogin.bodyAsText())

        userRepository.approveByPhone("+79992223344")

        val approvedLogin = client.post("/api/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest(phone = "+79992223344", password = "strongpass123"))
        }
        assertEquals(HttpStatusCode.OK, approvedLogin.status)
    }

    @Test
    fun `admin can list approve and ban users`() = testApplication {
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
            setBody(RegisterRequest(phone = "+79992220001", nickname = "chief", password = "strongpass123", telegramId = 1L))
        }
        val adminUser = userRepository.findByPhone("+79992220001")!!
        userRepository.updateIsAdmin(adminUser.id, true)
        userRepository.updateApproval(adminUser.id, true)

        client.post("/api/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest(phone = "+79992220002", nickname = "target", password = "strongpass123", telegramId = 2L))
        }
        val targetUser = userRepository.findByPhone("+79992220002")!!

        val loginResponse = client.post("/api/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest(phone = "+79992220001", password = "strongpass123"))
        }
        val adminToken = loginResponse.body<AuthTokenResponse>().accessToken

        val listBeforeApproval = client.get("/api/users") {
            header(HttpHeaders.Authorization, "Bearer $adminToken")
        }
        assertEquals(HttpStatusCode.OK, listBeforeApproval.status)
        assertEquals(
            listOf(
                AdminUserResponse(
                    id = adminUser.id,
                    phone = adminUser.phone,
                    nickname = adminUser.nickname,
                    telegramId = adminUser.telegramId,
                    isAdmin = true,
                    isApproved = true,
                    isBanned = false
                ),
                AdminUserResponse(
                    id = targetUser.id,
                    phone = targetUser.phone,
                    nickname = targetUser.nickname,
                    telegramId = targetUser.telegramId,
                    isAdmin = false,
                    isApproved = false,
                    isBanned = false
                )
            ),
            listBeforeApproval.body()
        )

        val approveResponse = client.post("/api/users/${targetUser.id}/approve") {
            header(HttpHeaders.Authorization, "Bearer $adminToken")
        }
        assertEquals(HttpStatusCode.OK, approveResponse.status)
        assertEquals(
            AdminUserResponse(
                id = targetUser.id,
                phone = targetUser.phone,
                nickname = targetUser.nickname,
                telegramId = targetUser.telegramId,
                isAdmin = false,
                isApproved = true,
                isBanned = false
            ),
            approveResponse.body()
        )

        val approvedLogin = client.post("/api/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest(phone = "+79992220002", password = "strongpass123"))
        }
        assertEquals(HttpStatusCode.OK, approvedLogin.status)

        val banResponse = client.post("/api/users/${targetUser.id}/ban") {
            header(HttpHeaders.Authorization, "Bearer $adminToken")
        }
        assertEquals(HttpStatusCode.OK, banResponse.status)
        assertEquals(
            AdminUserResponse(
                id = targetUser.id,
                phone = targetUser.phone,
                nickname = targetUser.nickname,
                telegramId = targetUser.telegramId,
                isAdmin = false,
                isApproved = true,
                isBanned = true
            ),
            banResponse.body()
        )

        val bannedLogin = client.post("/api/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest(phone = "+79992220002", password = "strongpass123"))
        }
        assertEquals(HttpStatusCode.Forbidden, bannedLogin.status)
        assertEquals("""{"message":"User is banned"}""", bannedLogin.bodyAsText())
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
        val noopCleanupService = object : DeviceConfigCleanupService {
            override fun cleanup(server: Server, config: DeviceServerConfig) = Unit
        }
        application {
            module(
                userRepository = userRepository,
                deviceRepository = SqliteDeviceRepository(databaseFactory),
                deviceServerRepository = deviceServerRepository,
                serverRepository = SqliteServerRepository(databaseFactory),
                jwtService = JwtService(appConfig.jwt),
                appConfig = appConfig,
                deviceConfigCleanupService = noopCleanupService
            )
        }

        val client = createClient {
            install(ContentNegotiation) {
                json()
            }
        }

        client.post("/api/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(RegisterRequest(phone = "+79990000001", nickname = "first", password = "strongpass123", telegramId = 11L))
        }
        val firstUser = userRepository.findByPhone("+79990000001")!!
        userRepository.updateIsAdmin(firstUser.id, true)
        userRepository.updateApproval(firstUser.id, true)

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
            setBody(RegisterRequest(phone = "+79990000002", nickname = "second", password = "strongpass123", telegramId = 22L))
        }
        userRepository.approveByPhone("+79990000002")

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
            setBody(RegisterRequest(phone = "+79990000055", nickname = "gen", password = "strongpass123", telegramId = null))
        }
        val user = userRepository.findByPhone("+79990000055")!!
        userRepository.updateIsAdmin(user.id, true)
        userRepository.updateApproval(user.id, true)

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
            setBody(RegisterRequest(phone = "+79990000066", nickname = "dup", password = "strongpass123", telegramId = null))
        }
        val user = userRepository.findByPhone("+79990000066")!!
        userRepository.updateIsAdmin(user.id, true)
        userRepository.updateApproval(user.id, true)

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
    fun `concurrent generate for same device and server creates only one config`() = testApplication {
        environment {
            config = MapApplicationConfig()
        }
        val appConfig = testConfig()
        val databaseFactory = DatabaseFactory(appConfig.databasePath)
        databaseFactory.initialize()
        val userRepository = SqliteUserRepository(databaseFactory)
        val generatorCalls = AtomicInteger(0)
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        val fakeGenerator = object : DeviceConfigGenerator {
            override fun generate(server: Server, user: User, device: Device): GeneratedDeviceConfig {
                generatorCalls.incrementAndGet()
                started.countDown()
                check(release.await(5, TimeUnit.SECONDS)) { "Timed out waiting to release generator" }
                return GeneratedDeviceConfig(
                    clientId = "concurrent-client-id",
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
            setBody(RegisterRequest(phone = "+79990000067", nickname = "race", password = "strongpass123", telegramId = null))
        }
        val user = userRepository.findByPhone("+79990000067")!!
        userRepository.updateIsAdmin(user.id, true)
        userRepository.updateApproval(user.id, true)

        val loginResponse = client.post("/api/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest(phone = "+79990000067", password = "strongpass123"))
        }
        val token = loginResponse.body<AuthTokenResponse>().accessToken

        val serverResponse = client.post("/api/servers") {
            header(HttpHeaders.Authorization, "Bearer $token")
            contentType(ContentType.Application.Json)
            setBody(
                UpsertServerRequest(
                    name = "Race Server",
                    location = "Berlin",
                    host = "192.0.2.12",
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
            setBody(CreateDeviceRequest(name = "ThinkPad"))
        }
        val createdDevice = deviceResponse.body<DeviceResponse>()

        val pool = Executors.newFixedThreadPool(2)
        try {
            val first = pool.submit<io.ktor.client.statement.HttpResponse> {
                runBlocking {
                    client.post("/api/devices/${createdDevice.id}/configs/generate") {
                        header(HttpHeaders.Authorization, "Bearer $token")
                        contentType(ContentType.Application.Json)
                        setBody(GenerateDeviceConfigRequest(serverId = createdServer.id))
                    }
                }
            }

            assertTrue(started.await(5, TimeUnit.SECONDS))

            val second = pool.submit<io.ktor.client.statement.HttpResponse> {
                runBlocking {
                    client.post("/api/devices/${createdDevice.id}/configs/generate") {
                        header(HttpHeaders.Authorization, "Bearer $token")
                        contentType(ContentType.Application.Json)
                        setBody(GenerateDeviceConfigRequest(serverId = createdServer.id))
                    }
                }
            }

            release.countDown()

            val firstResponse = first.get(5, TimeUnit.SECONDS)
            val secondResponse = second.get(5, TimeUnit.SECONDS)
            val statuses = listOf(firstResponse.status, secondResponse.status).sortedBy { it.value }

            assertEquals(listOf(HttpStatusCode.OK, HttpStatusCode.Conflict), statuses)
            assertEquals(1, generatorCalls.get())
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun `concurrent delete of same admin config cleans up only once`() = testApplication {
        environment {
            config = MapApplicationConfig()
        }
        val appConfig = testConfig()
        val databaseFactory = DatabaseFactory(appConfig.databasePath)
        databaseFactory.initialize()
        val userRepository = SqliteUserRepository(databaseFactory)
        val cleanupCalls = AtomicInteger(0)
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        val cleanupService = object : DeviceConfigCleanupService {
            override fun cleanup(server: Server, config: DeviceServerConfig) {
                cleanupCalls.incrementAndGet()
                started.countDown()
                check(release.await(5, TimeUnit.SECONDS)) { "Timed out waiting to release cleanup" }
            }
        }
        val deviceRepository = SqliteDeviceRepository(databaseFactory)
        val deviceServerRepository = SqliteDeviceServerRepository(databaseFactory)
        val serverRepository = SqliteServerRepository(databaseFactory)

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
            setBody(RegisterRequest(phone = "+79990000068", nickname = "admin", password = "strongpass123", telegramId = null))
        }
        val admin = userRepository.findByPhone("+79990000068")!!
        userRepository.updateIsAdmin(admin.id, true)
        userRepository.updateApproval(admin.id, true)

        val loginResponse = client.post("/api/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest(phone = "+79990000068", password = "strongpass123"))
        }
        val token = loginResponse.body<AuthTokenResponse>().accessToken

        val server = serverRepository.createServer(
            name = "Delete Server",
            location = "Warsaw",
            connection = AwgConnection(
                host = "192.0.2.13",
                port = 22,
                username = "root",
                password = null,
                sshKeyPath = "/keys/test",
                containerName = "amnezia-awg2",
                containerConfigDir = "/opt/amnezia/awg",
                interfaceName = "awg0"
            )
        )
        val deviceOwner = userRepository.createUser(
            phone = "+79990000069",
            nickname = "owner",
            telegramId = null,
            passwordHash = "hash"
        ) ?: error("User was not created")
        userRepository.updateApproval(deviceOwner.id, true)
        val device = deviceRepository.createDevice(deviceOwner.id, "iPhone")
        val config = deviceServerRepository.upsert(device.id, server.id, "stored-config")

        val pool = Executors.newFixedThreadPool(2)
        try {
            val first = pool.submit<io.ktor.client.statement.HttpResponse> {
                runBlocking {
                    client.delete("/api/configs/${config.id}") {
                        header(HttpHeaders.Authorization, "Bearer $token")
                    }
                }
            }

            assertTrue(started.await(5, TimeUnit.SECONDS))

            val second = pool.submit<io.ktor.client.statement.HttpResponse> {
                runBlocking {
                    client.delete("/api/configs/${config.id}") {
                        header(HttpHeaders.Authorization, "Bearer $token")
                    }
                }
            }

            release.countDown()

            val firstResponse = first.get(5, TimeUnit.SECONDS)
            val secondResponse = second.get(5, TimeUnit.SECONDS)
            val statuses = listOf(firstResponse.status, secondResponse.status).sortedBy { it.value }

            assertEquals(listOf(HttpStatusCode.NoContent, HttpStatusCode.NotFound), statuses)
            assertEquals(1, cleanupCalls.get())
        } finally {
            pool.shutdownNow()
        }
    }

    @Test
    fun `user can download config file and qr for generated config`() = testApplication {
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
                    clientId = "download-client-id",
                    config = """
                        [Interface]
                        PrivateKey = fake
                        Address = 10.0.0.2/32
                        DNS = 1.1.1.1, 1.0.0.1

                        [Peer]
                        PublicKey = server-key
                        AllowedIPs = 0.0.0.0/0, ::/0
                        Endpoint = vpn.example.com:51820
                        PersistentKeepalive = 25
                    """.trimIndent()
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
            setBody(RegisterRequest(phone = "+79990000077", nickname = "qr", password = "strongpass123", telegramId = null))
        }
        val user = userRepository.findByPhone("+79990000077")!!
        userRepository.updateIsAdmin(user.id, true)
        userRepository.updateApproval(user.id, true)

        val loginResponse = client.post("/api/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(LoginRequest(phone = "+79990000077", password = "strongpass123"))
        }
        val token = loginResponse.body<AuthTokenResponse>().accessToken

        val serverResponse = client.post("/api/servers") {
            header(HttpHeaders.Authorization, "Bearer $token")
            contentType(ContentType.Application.Json)
            setBody(
                UpsertServerRequest(
                    name = "QR Server",
                    location = "North Europe",
                    host = "192.0.2.12",
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
            setBody(CreateDeviceRequest(name = "My Phone"))
        }
        val createdDevice = deviceResponse.body<DeviceResponse>()

        val generateResponse = client.post("/api/devices/${createdDevice.id}/configs/generate") {
            header(HttpHeaders.Authorization, "Bearer $token")
            contentType(ContentType.Application.Json)
            setBody(GenerateDeviceConfigRequest(serverId = createdServer.id))
        }
        val createdConfig = generateResponse.body<DeviceServerResponse>()

        val fileResponse = client.get("/api/devices/${createdDevice.id}/configs/${createdConfig.id}/file") {
            header(HttpHeaders.Authorization, "Bearer $token")
        }
        assertEquals(HttpStatusCode.OK, fileResponse.status)
        assertEquals("text/plain", fileResponse.headers[HttpHeaders.ContentType])
        assertTrue(
            fileResponse.headers[HttpHeaders.ContentDisposition]?.contains("filename=North_Europe_My_Phone.conf") == true
        )
        assertEquals(createdConfig.config, fileResponse.bodyAsText())

        val qrResponse = client.get("/api/devices/${createdDevice.id}/configs/${createdConfig.id}/qr") {
            header(HttpHeaders.Authorization, "Bearer $token")
        }
        assertEquals(HttpStatusCode.OK, qrResponse.status)
        assertEquals(ContentType.Image.PNG, qrResponse.contentType())
        val qrBytes = qrResponse.body<ByteArray>()
        assertTrue(qrBytes.size > 8)
        assertTrue(qrBytes[0] == 0x89.toByte())
        assertTrue(qrBytes[1] == 0x50.toByte())
        assertTrue(qrBytes[2] == 0x4E.toByte())
        assertTrue(qrBytes[3] == 0x47.toByte())
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
            setBody(RegisterRequest(phone = "+79990000100", nickname = "root", password = "strongpass123", telegramId = null))
        }
        val adminUser = userRepository.findByPhone("+79990000100")!!
        userRepository.updateIsAdmin(adminUser.id, true)
        userRepository.updateApproval(adminUser.id, true)

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
            setBody(RegisterRequest(phone = "+79990000101", nickname = "user", password = "strongpass123", telegramId = null))
        }
        userRepository.approveByPhone("+79990000101")

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
            setBody(RegisterRequest(phone = "+79990000111", nickname = "boss", password = "strongpass123", telegramId = 1L))
        }
        val adminUser = userRepository.findByPhone("+79990000111")!!
        userRepository.updateIsAdmin(adminUser.id, true)
        userRepository.updateApproval(adminUser.id, true)

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

    private fun UserRepository.approveByPhone(phone: String) {
        val user = findByPhone(phone) ?: error("User with phone $phone not found")
        updateApproval(user.id, true)
    }
}
