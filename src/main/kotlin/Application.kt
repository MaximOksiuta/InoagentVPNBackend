package org.example

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.github.smiley4.ktorswaggerui.SwaggerUI
import io.github.smiley4.ktorswaggerui.data.AuthKeyLocation
import io.github.smiley4.ktorswaggerui.data.AuthScheme
import io.github.smiley4.ktorswaggerui.data.AuthType
import io.github.smiley4.ktorswaggerui.dsl.routing.delete
import io.github.smiley4.ktorswaggerui.dsl.routing.get
import io.github.smiley4.ktorswaggerui.dsl.routing.post
import io.github.smiley4.ktorswaggerui.dsl.routing.put
import io.github.smiley4.ktorswaggerui.dsl.routing.route
import io.github.smiley4.ktorswaggerui.routing.openApiSpec
import io.github.smiley4.ktorswaggerui.routing.swaggerUI
import io.ktor.http.HttpStatusCode
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.ContentDisposition
import io.ktor.http.ContentType
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.auth.Authentication
import io.ktor.server.auth.jwt.JWTPrincipal
import io.ktor.server.auth.jwt.jwt
import io.ktor.server.auth.principal
import io.ktor.server.netty.EngineMain
import io.ktor.server.plugins.callloging.CallLogging
import io.ktor.server.plugins.cors.routing.CORS
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.receive
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respond
import io.ktor.server.response.respondBytes
import io.ktor.server.routing.routing
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.Serializable
import org.mindrot.jbcrypt.BCrypt
import java.util.Date
import java.text.Normalizer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

private const val AUTH_JWT = "auth-jwt"

fun main(args: Array<String>) {
    EngineMain.main(args)
}

@Suppress("unused")
fun Application.module() {
    val appConfig = AppConfig.from(environment.config)
    val databaseFactory = DatabaseFactory(appConfig.databasePath)
    databaseFactory.initialize()
    val userRepository = SqliteUserRepository(databaseFactory)
    val deviceRepository = SqliteDeviceRepository(databaseFactory)
    val deviceServerRepository = SqliteDeviceServerRepository(databaseFactory)
    val serverRepository = SqliteServerRepository(databaseFactory)
    val jwtService = JwtService(appConfig.jwt)
    val deviceConfigGenerator = AwgDeviceConfigGenerator()
    val deviceConfigCleanupService = AwgDeviceConfigCleanupService()
    val configMutationGuard = DeviceConfigMutationGuard()

    module(
        userRepository,
        deviceRepository,
        deviceServerRepository,
        serverRepository,
        jwtService,
        appConfig,
        deviceConfigGenerator,
        deviceConfigCleanupService,
        configMutationGuard
    )
}

fun Application.module(
    userRepository: UserRepository,
    deviceRepository: DeviceRepository,
    deviceServerRepository: DeviceServerRepository,
    serverRepository: ServerRepository,
    jwtService: JwtService,
    appConfig: AppConfig,
    deviceConfigGenerator: DeviceConfigGenerator = AwgDeviceConfigGenerator(),
    deviceConfigCleanupService: DeviceConfigCleanupService = AwgDeviceConfigCleanupService(),
    configMutationGuard: DeviceConfigMutationGuard = DeviceConfigMutationGuard()
) {
    install(CallLogging)
    install(CORS) {
        anyHost()
        allowMethod(HttpMethod.Options)
        allowMethod(HttpMethod.Get)
        allowMethod(HttpMethod.Post)
        allowMethod(HttpMethod.Put)
        allowMethod(HttpMethod.Delete)
        allowHeader(HttpHeaders.Authorization)
        allowHeader(HttpHeaders.ContentType)
        allowHeader("X-Super-Key")
        allowHeader("X-Phone")
        allowNonSimpleContentTypes = true
    }
    install(ContentNegotiation) {
        json()
    }
    install(SwaggerUI) {
        pathFilter = { _, path ->
            path != listOf("api.json") &&
                path != listOf("docs") &&
                path != listOf("swagger") &&
                path != listOf("swagger/")
        }
        info {
            title = "Auth and Devices API"
            version = "1.2.0"
            description = "API for authentication and user device management"
        }
        security {
            securityScheme("bearerAuth") {
                type = AuthType.HTTP
                scheme = AuthScheme.BEARER
                bearerFormat = "JWT"
                description = "JWT access token in Authorization header"
                location = AuthKeyLocation.HEADER
            }
        }
    }
    install(Authentication) {
        jwt(AUTH_JWT) {
            realm = appConfig.jwt.realm
            verifier(jwtService.verifier)
            validate { credential ->
                val phone = credential.payload.getClaim("phone").asString()
                if (phone.isNullOrBlank()) null else JWTPrincipal(credential.payload)
            }
        }
    }
    install(StatusPages) {
        exception<IllegalArgumentException> { call, cause ->
            call.respond(HttpStatusCode.BadRequest, ErrorResponse(cause.message ?: "Invalid request"))
        }
        exception<Throwable> { call, cause ->
            this@module.environment.log.error("Unhandled error", cause)
            call.respond(HttpStatusCode.InternalServerError, ErrorResponse("Internal server error"))
        }
    }

    routing {
        route("/api.json") {
            openApiSpec()
        }

        get("/swagger") {
            call.respondRedirect("/docs")
        }

        get("/swagger/") {
            call.respondRedirect("/docs")
        }

        route("/docs") {
            swaggerUI("/api.json")
        }

        get("/health", {
            description = "Health check endpoint"
            response {
                code(HttpStatusCode.OK) {
                    description = "Service is available"
                    body<HealthResponse> {
                        description = "Health response payload"
                    }
                }
            }
        }) {
            call.respond(HealthResponse(status = "ok"))
        }

        route("/api/auth") {
            post("/register", {
                description = "Register a new user with phone, password and optional telegram id"
                request {
                    body<RegisterRequest> {
                        description = "Registration payload"
                        required = true
                    }
                }
                response {
                    code(HttpStatusCode.Created) {
                        description = "User created successfully"
                        body<RegisterResponse> {
                            description = "Created user payload"
                        }
                    }
                    code(HttpStatusCode.BadRequest) {
                        description = "Validation error"
                        body<ErrorResponse> {
                            description = "Validation error payload"
                        }
                    }
                    code(HttpStatusCode.Conflict) {
                        description = "User with this phone already exists"
                        body<ErrorResponse> {
                            description = "Conflict error payload"
                        }
                    }
                }
            }) {
                val request = call.receive<RegisterRequest>()
                validateRegistrationCredentials(request.phone, request.nickname, request.password)

                val normalizedPhone = normalizePhone(request.phone)
                val createdUser = userRepository.createUser(
                    phone = normalizedPhone,
                    nickname = request.nickname.trim(),
                    telegramId = request.telegramId,
                    passwordHash = BCrypt.hashpw(request.password, BCrypt.gensalt())
                )

                if (createdUser == null) {
                    call.respond(
                        HttpStatusCode.Conflict,
                        ErrorResponse("User with this phone already exists")
                    )
                    return@post
                }

                call.respond(
                    HttpStatusCode.Created,
                    RegisterResponse(
                        id = createdUser.id,
                        phone = createdUser.phone,
                        nickname = createdUser.nickname,
                        telegramId = createdUser.telegramId
                    )
                )
            }

            post("/login", {
                description = "Login with phone and password to get JWT token"
                request {
                    body<LoginRequest> {
                        description = "Login payload"
                        required = true
                    }
                }
                response {
                    code(HttpStatusCode.OK) {
                        description = "Login successful"
                        body<AuthTokenResponse> {
                            description = "JWT access token"
                        }
                    }
                    code(HttpStatusCode.BadRequest) {
                        description = "Validation error"
                        body<ErrorResponse> {
                            description = "Validation error payload"
                        }
                    }
                    code(HttpStatusCode.Unauthorized) {
                        description = "Invalid phone or password"
                        body<ErrorResponse> {
                            description = "Unauthorized error payload"
                        }
                    }
                }
            }) {
                val request = call.receive<LoginRequest>()
                validateLoginCredentials(request.phone, request.password)

                val normalizedPhone = normalizePhone(request.phone)
                val user = userRepository.findByPhone(normalizedPhone)
                if (user == null || !BCrypt.checkpw(request.password, user.passwordHash)) {
                    call.respond(HttpStatusCode.Unauthorized, ErrorResponse("Invalid phone or password"))
                    return@post
                }
                if (!user.isApproved) {
                    call.respond(HttpStatusCode.Forbidden, ErrorResponse("User is not approved"))
                    return@post
                }
                if (user.isBanned) {
                    call.respond(HttpStatusCode.Forbidden, ErrorResponse("User is banned"))
                    return@post
                }

                val token = jwtService.generateToken(user)
                call.respond(
                    HttpStatusCode.OK,
                    AuthTokenResponse(
                        accessToken = token,
                        tokenType = "Bearer",
                        expiresIn = appConfig.jwt.expiresInMs / 1000
                    )
                )
            }

            get("/me", {
                description = "Get current user by JWT token or super key headers"
                securitySchemeNames("bearerAuth")
                response {
                    code(HttpStatusCode.OK) {
                        description = "Current authenticated user"
                        body<CurrentUserResponse> {
                            description = "Authenticated user payload"
                        }
                    }
                    code(HttpStatusCode.Unauthorized) {
                        description = "Missing or invalid credentials"
                        body<ErrorResponse> {
                            description = "Unauthorized error payload"
                        }
                    }
                }
            }) {
                val user = authenticateCurrentUser(call, userRepository, jwtService, appConfig)
                if (user == null) {
                    call.respond(HttpStatusCode.Unauthorized, ErrorResponse("Invalid credentials"))
                    return@get
                }

                call.respond(
                    HttpStatusCode.OK,
                    CurrentUserResponse(
                        id = user.id,
                        phone = user.phone,
                        nickname = user.nickname,
                        telegramId = user.telegramId,
                        isAdmin = user.isAdmin
                    )
                )
            }
        }

        route("/api/devices") {
            get("", {
                description = "List devices of the current user"
                securitySchemeNames("bearerAuth")
                response {
                    code(HttpStatusCode.OK) {
                        description = "User devices"
                        body<List<DeviceResponse>> {
                            description = "List of devices"
                        }
                    }
                    code(HttpStatusCode.Unauthorized) {
                        description = "Missing or invalid credentials"
                        body<ErrorResponse> {
                            description = "Unauthorized error payload"
                        }
                    }
                }
            }) {
                val user = authenticateCurrentUser(call, userRepository, jwtService, appConfig)
                if (user == null) {
                    call.respond(HttpStatusCode.Unauthorized, ErrorResponse("Invalid credentials"))
                    return@get
                }

                call.respond(
                    deviceRepository.listDevices(user.id).map { device -> device.toSummaryResponse() }
                )
            }

            post("", {
                description = "Create a new device for the current user"
                securitySchemeNames("bearerAuth")
                request {
                    body<CreateDeviceRequest> {
                        description = "Device payload"
                        required = true
                    }
                }
                response {
                    code(HttpStatusCode.Created) {
                        description = "Device created"
                        body<DeviceResponse> {
                            description = "Created device"
                        }
                    }
                }
            }) {
                val user = authenticateCurrentUser(call, userRepository, jwtService, appConfig)
                if (user == null) {
                    call.respond(HttpStatusCode.Unauthorized, ErrorResponse("Invalid credentials"))
                    return@post
                }

                val request = call.receive<CreateDeviceRequest>()
                validateDevicePayload(request.name)

                val device = deviceRepository.createDevice(
                    userId = user.id,
                    name = request.name.trim()
                )
                call.respond(HttpStatusCode.Created, device.toSummaryResponse())
            }

            get("/{deviceId}", {
                description = "Get one device of the current user"
                securitySchemeNames("bearerAuth")
                response {
                    code(HttpStatusCode.OK) {
                        description = "Requested device"
                        body<DeviceDetailsResponse> {
                            description = "Device details"
                        }
                    }
                    code(HttpStatusCode.NotFound) {
                        description = "Device not found"
                        body<ErrorResponse> {
                            description = "Not found error payload"
                        }
                    }
                }
            }) {
                val user = authenticateCurrentUser(call, userRepository, jwtService, appConfig)
                if (user == null) {
                    call.respond(HttpStatusCode.Unauthorized, ErrorResponse("Invalid credentials"))
                    return@get
                }

                val deviceId = parseDeviceId(call.parameters["deviceId"])
                val device = deviceRepository.findDevice(user.id, deviceId)
                if (device == null) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("Device not found"))
                    return@get
                }

                call.respond(
                    device.toDetailsResponse(
                        links = deviceServerRepository.listByDevice(device.id),
                        serverRepository = serverRepository
                    )
                )
            }

            put("/{deviceId}", {
                description = "Update one device of the current user"
                securitySchemeNames("bearerAuth")
                request {
                    body<UpdateDeviceRequest> {
                        description = "Updated device payload"
                        required = true
                    }
                }
                response {
                    code(HttpStatusCode.OK) {
                        description = "Updated device"
                        body<DeviceDetailsResponse> {
                            description = "Updated device payload"
                        }
                    }
                    code(HttpStatusCode.NotFound) {
                        description = "Device not found"
                        body<ErrorResponse> {
                            description = "Not found error payload"
                        }
                    }
                }
            }) {
                val user = authenticateCurrentUser(call, userRepository, jwtService, appConfig)
                if (user == null) {
                    call.respond(HttpStatusCode.Unauthorized, ErrorResponse("Invalid credentials"))
                    return@put
                }

                val deviceId = parseDeviceId(call.parameters["deviceId"])
                val request = call.receive<UpdateDeviceRequest>()
                validateDevicePayload(request.name)

                val updated = deviceRepository.updateDevice(
                    userId = user.id,
                    deviceId = deviceId,
                    name = request.name.trim()
                )
                if (updated == null) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("Device not found"))
                    return@put
                }

                call.respond(
                    updated.toDetailsResponse(
                        links = deviceServerRepository.listByDevice(updated.id),
                        serverRepository = serverRepository
                    )
                )
            }

            delete("/{deviceId}", {
                description = "Delete one device of the current user"
                securitySchemeNames("bearerAuth")
                response {
                    code(HttpStatusCode.NoContent) {
                        description = "Device deleted"
                    }
                    code(HttpStatusCode.NotFound) {
                        description = "Device not found"
                        body<ErrorResponse> {
                            description = "Not found error payload"
                        }
                    }
                }
            }) {
                val user = authenticateCurrentUser(call, userRepository, jwtService, appConfig)
                if (user == null) {
                    call.respond(HttpStatusCode.Unauthorized, ErrorResponse("Invalid credentials"))
                    return@delete
                }

                val deviceId = parseDeviceId(call.parameters["deviceId"])
                val device = deviceRepository.findDevice(user.id, deviceId)
                if (device == null) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("Device not found"))
                    return@delete
                }

                val deletionStatus = configMutationGuard.withServerLocks(
                    serverIds = deviceServerRepository.listByDevice(device.id).map(DeviceServerConfig::serverId)
                ) {
                    val linkedConfigs = deviceServerRepository.listByDevice(device.id)
                    linkedConfigs.forEach { config ->
                        val server = serverRepository.findServer(config.serverId)
                            ?: error("Server ${config.serverId} for device config ${config.id} was not found")
                        deviceConfigCleanupService.cleanup(server, config)
                    }

                    val deleted = deviceRepository.deleteDevice(user.id, deviceId)
                    if (!deleted) HttpStatusCode.NotFound else HttpStatusCode.NoContent
                }
                if (deletionStatus == HttpStatusCode.NotFound) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("Device not found"))
                    return@delete
                }

                call.response.status(HttpStatusCode.NoContent)
            }

            post("/{deviceId}/configs/generate", {
                description = "Generate and save config for the current user's device on a selected server"
                securitySchemeNames("bearerAuth")
                request {
                    body<GenerateDeviceConfigRequest> {
                        description = "Server selection for config generation"
                        required = true
                    }
                }
                response {
                    code(HttpStatusCode.OK) {
                        description = "Generated and saved config"
                        body<DeviceServerResponse> {
                            description = "Generated config payload"
                        }
                    }
                    code(HttpStatusCode.NotFound) {
                        description = "Device or server not found"
                        body<ErrorResponse> {
                            description = "Not found error payload"
                        }
                    }
                }
            }) {
                val user = authenticateCurrentUser(call, userRepository, jwtService, appConfig)
                if (user == null) {
                    call.respond(HttpStatusCode.Unauthorized, ErrorResponse("Invalid credentials"))
                    return@post
                }

                val deviceId = parseDeviceId(call.parameters["deviceId"])
                val device = deviceRepository.findDevice(user.id, deviceId)
                if (device == null) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("Device not found"))
                    return@post
                }

                val request = call.receive<GenerateDeviceConfigRequest>()
                require(request.serverId > 0) { "Server id must be a positive number" }

                val server = serverRepository.findServer(request.serverId)
                if (server == null) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("Server not found"))
                    return@post
                }

                val result = configMutationGuard.withServerLock(server.id) {
                    val existingConfig = deviceServerRepository.findByDeviceAndServer(device.id, server.id)
                    if (existingConfig != null) {
                        return@withServerLock GenerateConfigResult.Conflict
                    }

                    val generated = deviceConfigGenerator.generate(server, user, device)
                    val saved = deviceServerRepository.upsert(
                        deviceId = device.id,
                        serverId = server.id,
                        config = generated.config
                    )
                    GenerateConfigResult.Success(saved)
                }

                when (result) {
                    GenerateConfigResult.Conflict -> {
                        call.respond(
                            HttpStatusCode.Conflict,
                            ErrorResponse("Config for this device and server already exists")
                        )
                    }
                    is GenerateConfigResult.Success -> call.respond(result.config.toResponse(server))
                }
            }

            get("/{deviceId}/configs/{configId}/file", {
                description = "Download one saved config file for the current user's device"
                securitySchemeNames("bearerAuth")
                response {
                    code(HttpStatusCode.OK) {
                        description = "Config file content"
                    }
                    code(HttpStatusCode.NotFound) {
                        description = "Device or config not found"
                        body<ErrorResponse> {
                            description = "Not found error payload"
                        }
                    }
                }
            }) {
                val user = authenticateCurrentUser(call, userRepository, jwtService, appConfig)
                if (user == null) {
                    call.respond(HttpStatusCode.Unauthorized, ErrorResponse("Invalid credentials"))
                    return@get
                }

                val deviceId = parseDeviceId(call.parameters["deviceId"])
                val configId = parsePositiveId(call.parameters["configId"], "Config id")
                val device = deviceRepository.findDevice(user.id, deviceId)
                if (device == null) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("Device not found"))
                    return@get
                }

                val deviceConfig = deviceServerRepository.findById(device.id, configId)
                if (deviceConfig == null) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("Config not found"))
                    return@get
                }

                val server = serverRepository.findServer(deviceConfig.serverId)
                if (server == null) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("Server not found"))
                    return@get
                }

                val fileName = buildConfigFileName(server.location, device.name)
                call.response.headers.append(
                    HttpHeaders.ContentDisposition,
                    ContentDisposition.Attachment.withParameter(ContentDisposition.Parameters.FileName, fileName).toString()
                )
                call.respondBytes(
                    bytes = deviceConfig.config.toByteArray(Charsets.UTF_8),
                    contentType = ContentType.Text.Plain,
                    status = HttpStatusCode.OK
                )
            }

            get("/{deviceId}/configs/{configId}/qr", {
                description = "Get QR code PNG for one saved config of the current user's device"
                securitySchemeNames("bearerAuth")
                response {
                    code(HttpStatusCode.OK) {
                        description = "QR code PNG"
                    }
                    code(HttpStatusCode.NotFound) {
                        description = "Device or config not found"
                        body<ErrorResponse> {
                            description = "Not found error payload"
                        }
                    }
                }
            }) {
                val user = authenticateCurrentUser(call, userRepository, jwtService, appConfig)
                if (user == null) {
                    call.respond(HttpStatusCode.Unauthorized, ErrorResponse("Invalid credentials"))
                    return@get
                }

                val deviceId = parseDeviceId(call.parameters["deviceId"])
                val configId = parsePositiveId(call.parameters["configId"], "Config id")
                val device = deviceRepository.findDevice(user.id, deviceId)
                if (device == null) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("Device not found"))
                    return@get
                }

                val deviceConfig = deviceServerRepository.findById(device.id, configId)
                if (deviceConfig == null) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("Config not found"))
                    return@get
                }

                val server = serverRepository.findServer(deviceConfig.serverId)
                if (server == null) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("Server not found"))
                    return@get
                }

                val qrPng = AwgQrCodeService.generatePng(
                    confText = deviceConfig.config,
                    descriptionOverride = server.location
                )
                call.respondBytes(
                    bytes = qrPng,
                    contentType = ContentType.Image.PNG,
                    status = HttpStatusCode.OK
                )
            }
        }

        route("/api/servers") {
            get("", {
                description = "List servers for authenticated users"
                securitySchemeNames("bearerAuth")
                response {
                    code(HttpStatusCode.OK) {
                        description = "Server list"
                        body<List<ServerListItemResponse>> {
                            description = "Server names and locations"
                        }
                    }
                    code(HttpStatusCode.Unauthorized) {
                        description = "Missing or invalid credentials"
                        body<ErrorResponse> {
                            description = "Unauthorized error payload"
                        }
                    }
                }
            }) {
                val user = authenticateCurrentUser(call, userRepository, jwtService, appConfig)
                if (user == null) {
                    call.respond(HttpStatusCode.Unauthorized, ErrorResponse("Invalid credentials"))
                    return@get
                }
                call.respond(serverRepository.listServers().map { it.toListItemResponse() })
            }

            post("", {
                description = "Create a server, available only to administrators"
                securitySchemeNames("bearerAuth")
                request {
                    body<UpsertServerRequest> {
                        description = "Server payload"
                        required = true
                    }
                }
                response {
                    code(HttpStatusCode.Created) {
                        description = "Server created"
                        body<ServerResponse> {
                            description = "Created server"
                        }
                    }
                }
            }) {
                authenticateAdmin(call, userRepository, jwtService, appConfig) ?: return@post
                val request = call.receive<UpsertServerRequest>()
                validateServerPayload(request)

                val server = serverRepository.createServer(
                    name = request.name.trim(),
                    location = request.location.trim(),
                    connection = request.toAwgConnection()
                )
                call.respond(HttpStatusCode.Created, server.toResponse())
            }

            get("/{serverId}", {
                description = "Get one server, available only to administrators"
                securitySchemeNames("bearerAuth")
                response {
                    code(HttpStatusCode.OK) {
                        description = "Requested server"
                        body<ServerResponse> {
                            description = "Server details"
                        }
                    }
                    code(HttpStatusCode.NotFound) {
                        description = "Server not found"
                        body<ErrorResponse> {
                            description = "Not found error payload"
                        }
                    }
                }
            }) {
                authenticateAdmin(call, userRepository, jwtService, appConfig) ?: return@get
                val serverId = parsePositiveId(call.parameters["serverId"], "Server id")
                val server = serverRepository.findServer(serverId)
                if (server == null) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("Server not found"))
                    return@get
                }
                call.respond(server.toResponse())
            }

            put("/{serverId}", {
                description = "Update one server, available only to administrators"
                securitySchemeNames("bearerAuth")
                request {
                    body<UpsertServerRequest> {
                        description = "Updated server payload"
                        required = true
                    }
                }
                response {
                    code(HttpStatusCode.OK) {
                        description = "Updated server"
                        body<ServerResponse> {
                            description = "Updated server payload"
                        }
                    }
                    code(HttpStatusCode.NotFound) {
                        description = "Server not found"
                        body<ErrorResponse> {
                            description = "Not found error payload"
                        }
                    }
                }
            }) {
                authenticateAdmin(call, userRepository, jwtService, appConfig) ?: return@put
                val serverId = parsePositiveId(call.parameters["serverId"], "Server id")
                val request = call.receive<UpsertServerRequest>()
                validateServerPayload(request)

                val updated = serverRepository.updateServer(
                    serverId = serverId,
                    name = request.name.trim(),
                    location = request.location.trim(),
                    connection = request.toAwgConnection()
                )
                if (updated == null) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("Server not found"))
                    return@put
                }
                call.respond(updated.toResponse())
            }

            delete("/{serverId}", {
                description = "Delete one server, available only to administrators"
                securitySchemeNames("bearerAuth")
                response {
                    code(HttpStatusCode.NoContent) {
                        description = "Server deleted"
                    }
                    code(HttpStatusCode.NotFound) {
                        description = "Server not found"
                        body<ErrorResponse> {
                            description = "Not found error payload"
                        }
                    }
                }
            }) {
                authenticateAdmin(call, userRepository, jwtService, appConfig) ?: return@delete
                val serverId = parsePositiveId(call.parameters["serverId"], "Server id")
                val deleted = serverRepository.deleteServer(serverId)
                if (!deleted) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("Server not found"))
                    return@delete
                }
                call.response.status(HttpStatusCode.NoContent)
            }
        }

        route("/api/users") {
            get("", {
                description = "List users, available only to administrators"
                securitySchemeNames("bearerAuth")
                response {
                    code(HttpStatusCode.OK) {
                        description = "Users list"
                        body<List<AdminUserResponse>> {
                            description = "User records with moderation flags"
                        }
                    }
                }
            }) {
                authenticateAdmin(call, userRepository, jwtService, appConfig) ?: return@get
                call.respond(userRepository.listUsers().map { it.toAdminResponse() })
            }

            post("/{userId}/approve", {
                description = "Approve one user, available only to administrators"
                securitySchemeNames("bearerAuth")
                response {
                    code(HttpStatusCode.OK) {
                        description = "Approved user"
                        body<AdminUserResponse> {
                            description = "Updated user"
                        }
                    }
                }
            }) {
                authenticateAdmin(call, userRepository, jwtService, appConfig) ?: return@post
                val userId = parsePositiveId(call.parameters["userId"], "User id")
                val updated = userRepository.updateApproval(userId, true)
                if (!updated) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("User not found"))
                    return@post
                }
                val user = userRepository.findById(userId)
                if (user == null) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("User not found"))
                    return@post
                }
                call.respond(user.toAdminResponse())
            }

            post("/{userId}/ban", {
                description = "Ban one user, available only to administrators"
                securitySchemeNames("bearerAuth")
                response {
                    code(HttpStatusCode.OK) {
                        description = "Banned user"
                        body<AdminUserResponse> {
                            description = "Updated user"
                        }
                    }
                }
            }) {
                authenticateAdmin(call, userRepository, jwtService, appConfig) ?: return@post
                val userId = parsePositiveId(call.parameters["userId"], "User id")
                val updated = userRepository.updateBan(userId, true)
                if (!updated) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("User not found"))
                    return@post
                }
                val user = userRepository.findById(userId)
                if (user == null) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("User not found"))
                    return@post
                }
                call.respond(user.toAdminResponse())
            }
        }

        route("/api/configs") {
            get("", {
                description = "List all saved device configs, available only to administrators"
                securitySchemeNames("bearerAuth")
                response {
                    code(HttpStatusCode.OK) {
                        description = "All saved configs"
                        body<List<AdminDeviceConfigResponse>> {
                            description = "Saved configs with user, device and server context"
                        }
                    }
                }
            }) {
                authenticateAdmin(call, userRepository, jwtService, appConfig) ?: return@get

                val response = deviceServerRepository.listAll().map { config ->
                    config.toAdminResponse(
                        deviceRepository = deviceRepository,
                        userRepository = userRepository,
                        serverRepository = serverRepository
                    )
                }
                call.respond(response)
            }

            delete("/{configId}", {
                description = "Delete one saved config, available only to administrators"
                securitySchemeNames("bearerAuth")
                response {
                    code(HttpStatusCode.NoContent) {
                        description = "Config deleted"
                    }
                    code(HttpStatusCode.NotFound) {
                        description = "Config not found"
                        body<ErrorResponse> {
                            description = "Not found error payload"
                        }
                    }
                }
            }) {
                authenticateAdmin(call, userRepository, jwtService, appConfig) ?: return@delete

                val configId = parsePositiveId(call.parameters["configId"], "Config id")
                val config = deviceServerRepository.findByConfigId(configId)
                if (config == null) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("Config not found"))
                    return@delete
                }

                val deletionStatus = configMutationGuard.withServerLock(config.serverId) {
                    val freshConfig = deviceServerRepository.findByConfigId(configId)
                        ?: return@withServerLock HttpStatusCode.NotFound
                    val server = serverRepository.findServer(freshConfig.serverId)
                        ?: error("Server ${freshConfig.serverId} for config ${freshConfig.id} was not found")
                    deviceConfigCleanupService.cleanup(server, freshConfig)

                    if (deviceServerRepository.deleteByConfigId(configId)) {
                        HttpStatusCode.NoContent
                    } else {
                        HttpStatusCode.NotFound
                    }
                }
                if (deletionStatus == HttpStatusCode.NotFound) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("Config not found"))
                    return@delete
                }

                call.response.status(HttpStatusCode.NoContent)
            }
        }
    }
}

private fun validateRegistrationCredentials(phone: String, nickname: String, password: String) {
    require(phone.isNotBlank()) { "Phone must not be blank" }
    require(nickname.isNotBlank()) { "Nickname must not be blank" }
    require(PHONE_REGEX.matches(normalizePhone(phone))) { "Phone format is invalid" }
    require(password.length >= 8) { "Password must be at least 8 characters long" }
}

private fun validateLoginCredentials(phone: String, password: String) {
    require(phone.isNotBlank()) { "Phone must not be blank" }
    require(PHONE_REGEX.matches(normalizePhone(phone))) { "Phone format is invalid" }
    require(password.isNotBlank()) { "Password must not be blank" }
}

private fun validateDevicePayload(name: String) {
    require(name.isNotBlank()) { "Device name must not be blank" }
    require(name.trim().length <= 255) { "Device name must not exceed 255 characters" }
}

private fun buildConfigFileName(region: String, deviceName: String): String {
    val safeRegion = sanitizeFileNamePart(region)
    val safeDeviceName = sanitizeFileNamePart(deviceName)
    return "${safeRegion}_${safeDeviceName}.conf"
}

private fun sanitizeFileNamePart(value: String): String {
    val normalized = Normalizer.normalize(value.trim(), Normalizer.Form.NFKD)
    val asciiOnly = normalized.replace(Regex("[^\\p{ASCII}]"), "")
    val safe = asciiOnly.replace(Regex("[^A-Za-z0-9._-]+"), "_").trim('_')
    return safe.ifBlank { "item" }
}

private fun parseDeviceId(rawDeviceId: String?): Long {
    return parsePositiveId(rawDeviceId, "Device id")
}

private fun parsePositiveId(rawValue: String?, label: String): Long {
    val parsed = rawValue?.toLongOrNull()
    require(parsed != null && parsed > 0) { "$label must be a positive number" }
    return parsed
}

private fun validateServerPayload(request: UpsertServerRequest) {
    require(request.name.isNotBlank()) { "Server name must not be blank" }
    require(request.location.isNotBlank()) { "Server location must not be blank" }
    require(request.host.isNotBlank()) { "Server host must not be blank" }
    require(request.port in 1..65535) { "Server port must be between 1 and 65535" }
    require(request.username.isNotBlank()) { "Server username must not be blank" }
    require(request.containerName.isNotBlank()) { "Server containerName must not be blank" }
    require(request.containerConfigDir.isNotBlank()) { "Server containerConfigDir must not be blank" }
    require(request.interfaceName.isNotBlank()) { "Server interfaceName must not be blank" }
}

private fun normalizePhone(phone: String): String = phone.trim()

private val PHONE_REGEX = Regex("^\\+[1-9][0-9]{10,14}$")

data class AppConfig(
    val databasePath: String,
    val jwt: JwtConfig,
    val superKey: String
) {
    companion object {
        fun from(config: io.ktor.server.config.ApplicationConfig): AppConfig {
            val jwtSecret = config.propertyOrNull("security.jwt.secret")?.getString()
                ?.takeIf { it.isNotBlank() }
                ?: error("JWT secret is missing. Set JWT_SECRET environment variable.")

            return AppConfig(
                databasePath = config.property("storage.sqlite.path").getString(),
                jwt = JwtConfig(
                    secret = jwtSecret,
                    issuer = config.property("security.jwt.issuer").getString(),
                    audience = config.property("security.jwt.audience").getString(),
                    realm = config.property("security.jwt.realm").getString(),
                    expiresInMs = config.property("security.jwt.expiresInMs").getString().toLong()
                ),
                superKey = config.propertyOrNull("security.super.key")?.getString().orEmpty()
            )
        }
    }
}

data class JwtConfig(
    val secret: String,
    val issuer: String,
    val audience: String,
    val realm: String,
    val expiresInMs: Long
)

class JwtService(
    private val jwtConfig: JwtConfig
) {
    private val algorithm = Algorithm.HMAC256(jwtConfig.secret)
    val verifier = JWT
        .require(algorithm)
        .withIssuer(jwtConfig.issuer)
        .withAudience(jwtConfig.audience)
        .build()

    fun generateToken(user: User): String {
        val now = System.currentTimeMillis()
        return JWT.create()
            .withIssuer(jwtConfig.issuer)
            .withAudience(jwtConfig.audience)
            .withClaim("userId", user.id)
            .withClaim("phone", user.phone)
            .withIssuedAt(Date(now))
            .withExpiresAt(Date(now + jwtConfig.expiresInMs))
            .sign(algorithm)
    }
}

data class GeneratedDeviceConfig(
    val clientId: String,
    val config: String
)

interface DeviceConfigGenerator {
    fun generate(server: Server, user: User, device: Device): GeneratedDeviceConfig
}

interface DeviceConfigCleanupService {
    fun cleanup(server: Server, config: DeviceServerConfig)
}

class DeviceConfigMutationGuard {
    private val serverLocks = ConcurrentHashMap<Long, ReentrantLock>()

    fun <T> withServerLock(serverId: Long, action: () -> T): T {
        val lock = serverLocks.computeIfAbsent(serverId) { ReentrantLock() }
        return lock.withLock(action)
    }

    fun <T> withServerLocks(serverIds: Iterable<Long>, action: () -> T): T {
        val locks = serverIds.toSortedSet().map { serverId ->
            serverLocks.computeIfAbsent(serverId) { ReentrantLock() }
        }

        locks.forEach(ReentrantLock::lock)
        try {
            return action()
        } finally {
            locks.asReversed().forEach(ReentrantLock::unlock)
        }
    }
}

private sealed interface GenerateConfigResult {
    data object Conflict : GenerateConfigResult
    data class Success(val config: DeviceServerConfig) : GenerateConfigResult
}

class AwgDeviceConfigGenerator : DeviceConfigGenerator {
    override fun generate(server: Server, user: User, device: Device): GeneratedDeviceConfig {
        val created = AwgServerScripts(server.connection).addUser(
            name = device.name,
            userId = user.id,
            deviceId = device.id
        )
        return GeneratedDeviceConfig(
            clientId = created.clientId,
            config = created.config
        )
    }
}

class AwgDeviceConfigCleanupService : DeviceConfigCleanupService {
    override fun cleanup(server: Server, config: DeviceServerConfig) {
        val clientId = AwgConfigClientIdExtractor.extractClientId(config.config)
        check(clientId.isNotBlank()) { "Failed to extract clientId from device config ${config.id}" }
        AwgServerScripts(server.connection).deleteUser(clientId)
    }
}

@Serializable
data class RegisterRequest(
    val phone: String,
    val nickname: String,
    val password: String,
    val telegramId: Long? = null
)

@Serializable
data class RegisterResponse(
    val id: Long,
    val phone: String,
    val nickname: String,
    val telegramId: Long?
)

@Serializable
data class LoginRequest(
    val phone: String,
    val password: String
)

@Serializable
data class AuthTokenResponse(
    val accessToken: String,
    val tokenType: String,
    val expiresIn: Long
)

@Serializable
data class CurrentUserResponse(
    val id: Long,
    val phone: String,
    val nickname: String,
    val telegramId: Long?,
    val isAdmin: Boolean
)

@Serializable
data class AdminUserResponse(
    val id: Long,
    val phone: String,
    val nickname: String,
    val telegramId: Long?,
    val isAdmin: Boolean,
    val isApproved: Boolean,
    val isBanned: Boolean
)

@Serializable
data class CreateDeviceRequest(
    val name: String
)

@Serializable
data class UpdateDeviceRequest(
    val name: String
)

@Serializable
data class DeviceResponse(
    val id: Long,
    val name: String
)

@Serializable
data class GenerateDeviceConfigRequest(
    val serverId: Long
)

@Serializable
data class DeviceDetailsResponse(
    val id: Long,
    val name: String,
    val configs: List<DeviceServerResponse>
)

@Serializable
data class DeviceServerResponse(
    val id: Long,
    val serverId: Long,
    val serverName: String,
    val serverLocation: String,
    val config: String
)

@Serializable
data class AdminDeviceConfigResponse(
    val id: Long,
    val userId: Long,
    val userPhone: String,
    val userNickname: String,
    val deviceId: Long,
    val deviceName: String,
    val serverId: Long,
    val serverName: String,
    val serverLocation: String,
    val config: String
)

@Serializable
data class UpsertServerRequest(
    val name: String,
    val location: String,
    val host: String,
    val port: Int = 22,
    val username: String,
    val password: String? = null,
    val sshKeyPath: String? = null,
    val containerName: String = "amnezia-awg2",
    val containerConfigDir: String = "/opt/amnezia/awg",
    val interfaceName: String = "awg0"
)

@Serializable
data class ServerResponse(
    val id: Long,
    val name: String,
    val location: String,
    val host: String,
    val port: Int,
    val username: String,
    val password: String?,
    val sshKeyPath: String?,
    val containerName: String,
    val containerConfigDir: String,
    val interfaceName: String
)

@Serializable
data class ServerListItemResponse(
    val id: Long,
    val name: String,
    val location: String
)

@Serializable
data class ErrorResponse(
    val message: String
)

@Serializable
data class HealthResponse(
    val status: String
)

private suspend fun authenticateCurrentUser(
    call: io.ktor.server.application.ApplicationCall,
    userRepository: UserRepository,
    jwtService: JwtService,
    appConfig: AppConfig
): User? {
    val superKey = call.request.headers["X-Super-Key"]
    val phoneFromHeader = call.request.headers["X-Phone"]?.let(::normalizePhone)

    if (!superKey.isNullOrBlank() || !phoneFromHeader.isNullOrBlank()) {
        if (superKey.isNullOrBlank() || phoneFromHeader.isNullOrBlank()) {
            return null
        }
        if (appConfig.superKey.isBlank() || superKey != appConfig.superKey) {
            return null
        }
        return userRepository.findByPhone(phoneFromHeader)?.takeIf(User::canAccessAccount)
    }

    val principal = call.principal<JWTPrincipal>()
    if (principal != null) {
        val phone = principal.payload.getClaim("phone").asString()?.let(::normalizePhone) ?: return null
        return userRepository.findByPhone(phone)?.takeIf(User::canAccessAccount)
    }

    val bearerToken = call.request.headers["Authorization"]
        ?.removePrefix("Bearer ")
        ?.trim()
        ?.takeIf { it.isNotBlank() }
        ?: return null

    val decoded = runCatching { jwtService.verifier.verify(bearerToken) }.getOrNull() ?: return null
    val phone = decoded.getClaim("phone").asString()?.let(::normalizePhone) ?: return null
    return userRepository.findByPhone(phone)?.takeIf(User::canAccessAccount)
}

private suspend fun authenticateAdmin(
    call: io.ktor.server.application.ApplicationCall,
    userRepository: UserRepository,
    jwtService: JwtService,
    appConfig: AppConfig
): User? {
    val user = authenticateCurrentUser(call, userRepository, jwtService, appConfig)
    if (user == null) {
        call.respond(HttpStatusCode.Unauthorized, ErrorResponse("Invalid credentials"))
        return null
    }
    if (!user.isAdmin) {
        call.respond(HttpStatusCode.Forbidden, ErrorResponse("Admin access required"))
        return null
    }
    return user
}

private fun Device.toSummaryResponse(): DeviceResponse {
    return DeviceResponse(
        id = id,
        name = name
    )
}

private fun User.toAdminResponse(): AdminUserResponse {
    return AdminUserResponse(
        id = id,
        phone = phone,
        nickname = nickname,
        telegramId = telegramId,
        isAdmin = isAdmin,
        isApproved = isApproved,
        isBanned = isBanned
    )
}

private fun User.canAccessAccount(): Boolean = isApproved && !isBanned

private fun Device.toDetailsResponse(
    links: List<DeviceServerConfig>,
    serverRepository: ServerRepository
): DeviceDetailsResponse {
    return DeviceDetailsResponse(
        id = id,
        name = name,
        configs = links.map { it.toResponse(serverRepository) }
    )
}

private fun DeviceServerConfig.toResponse(serverRepository: ServerRepository): DeviceServerResponse {
    val server = serverRepository.findServer(serverId)
        ?: error("Server with id=$serverId was not found for device-server config id=$id")
    return toResponse(server)
}

private fun DeviceServerConfig.toResponse(server: Server): DeviceServerResponse {
    return DeviceServerResponse(
        id = id,
        serverId = serverId,
        serverName = server.name,
        serverLocation = server.location,
        config = config
    )
}

private fun DeviceServerConfig.toAdminResponse(
    deviceRepository: DeviceRepository,
    userRepository: UserRepository,
    serverRepository: ServerRepository
): AdminDeviceConfigResponse {
    val device = deviceRepository.findById(deviceId)
        ?: error("Device with id=$deviceId was not found for config id=$id")
    val user = userRepository.findById(device.userId)
        ?: error("User with id=${device.userId} was not found for config id=$id")
    val server = serverRepository.findServer(serverId)
        ?: error("Server with id=$serverId was not found for config id=$id")

    return AdminDeviceConfigResponse(
        id = id,
        userId = user.id,
        userPhone = user.phone,
        userNickname = user.nickname,
        deviceId = device.id,
        deviceName = device.name,
        serverId = server.id,
        serverName = server.name,
        serverLocation = server.location,
        config = config
    )
}

private fun UpsertServerRequest.toAwgConnection(): AwgConnection {
    return AwgConnection(
        host = host.trim(),
        port = port,
        username = username.trim(),
        password = password,
        sshKeyPath = sshKeyPath,
        containerName = containerName.trim(),
        containerConfigDir = containerConfigDir.trim(),
        interfaceName = interfaceName.trim()
    )
}

private fun Server.toResponse(): ServerResponse {
    return ServerResponse(
        id = id,
        name = name,
        location = location,
        host = connection.host,
        port = connection.port,
        username = connection.username,
        password = connection.password,
        sshKeyPath = connection.sshKeyPath,
        containerName = connection.containerName,
        containerConfigDir = connection.containerConfigDir,
        interfaceName = connection.interfaceName
    )
}

private fun Server.toListItemResponse(): ServerListItemResponse {
    return ServerListItemResponse(
        id = id,
        name = name,
        location = location
    )
}
