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
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.auth.Authentication
import io.ktor.server.auth.jwt.JWTPrincipal
import io.ktor.server.auth.jwt.jwt
import io.ktor.server.auth.principal
import io.ktor.server.netty.EngineMain
import io.ktor.server.plugins.callloging.CallLogging
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.receive
import io.ktor.server.response.respondRedirect
import io.ktor.server.response.respond
import io.ktor.server.routing.routing
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.Serializable
import org.mindrot.jbcrypt.BCrypt
import java.util.Date

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
    val jwtService = JwtService(appConfig.jwt)

    module(userRepository, deviceRepository, jwtService, appConfig)
}

fun Application.module(
    userRepository: UserRepository,
    deviceRepository: DeviceRepository,
    jwtService: JwtService,
    appConfig: AppConfig
) {
    install(CallLogging)
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
                validateRegistrationCredentials(request.phone, request.password)

                val normalizedPhone = normalizePhone(request.phone)
                val createdUser = userRepository.createUser(
                    phone = normalizedPhone,
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
                        telegramId = user.telegramId
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
                    deviceRepository.listDevices(user.id).map { it.toResponse() }
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
                validateDevicePayload(request.name, request.config)

                val device = deviceRepository.createDevice(
                    userId = user.id,
                    name = request.name.trim(),
                    config = request.config
                )
                call.respond(HttpStatusCode.Created, device.toResponse())
            }

            get("/{deviceId}", {
                description = "Get one device of the current user"
                securitySchemeNames("bearerAuth")
                response {
                    code(HttpStatusCode.OK) {
                        description = "Requested device"
                        body<DeviceResponse> {
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

                call.respond(device.toResponse())
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
                        body<DeviceResponse> {
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
                validateDevicePayload(request.name, request.config)

                val updated = deviceRepository.updateDevice(
                    userId = user.id,
                    deviceId = deviceId,
                    name = request.name.trim(),
                    config = request.config
                )
                if (updated == null) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("Device not found"))
                    return@put
                }

                call.respond(updated.toResponse())
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
                val deleted = deviceRepository.deleteDevice(user.id, deviceId)
                if (!deleted) {
                    call.respond(HttpStatusCode.NotFound, ErrorResponse("Device not found"))
                    return@delete
                }

                call.response.status(HttpStatusCode.NoContent)
            }
        }
    }
}

private fun validateRegistrationCredentials(phone: String, password: String) {
    require(phone.isNotBlank()) { "Phone must not be blank" }
    require(PHONE_REGEX.matches(normalizePhone(phone))) { "Phone format is invalid" }
    require(password.length >= 8) { "Password must be at least 8 characters long" }
}

private fun validateLoginCredentials(phone: String, password: String) {
    require(phone.isNotBlank()) { "Phone must not be blank" }
    require(PHONE_REGEX.matches(normalizePhone(phone))) { "Phone format is invalid" }
    require(password.isNotBlank()) { "Password must not be blank" }
}

private fun validateDevicePayload(name: String, config: String) {
    require(name.isNotBlank()) { "Device name must not be blank" }
    require(name.trim().length <= 255) { "Device name must not exceed 255 characters" }
    require(config.isNotBlank()) { "Device config must not be blank" }
}

private fun parseDeviceId(rawDeviceId: String?): Long {
    val deviceId = rawDeviceId?.toLongOrNull()
    require(deviceId != null && deviceId > 0) { "Device id must be a positive number" }
    return deviceId
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

@Serializable
data class RegisterRequest(
    val phone: String,
    val password: String,
    val telegramId: Long? = null
)

@Serializable
data class RegisterResponse(
    val id: Long,
    val phone: String,
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
    val telegramId: Long?
)

@Serializable
data class CreateDeviceRequest(
    val name: String,
    val config: String
)

@Serializable
data class UpdateDeviceRequest(
    val name: String,
    val config: String
)

@Serializable
data class DeviceResponse(
    val id: Long,
    val name: String,
    val config: String
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
        return userRepository.findByPhone(phoneFromHeader)
    }

    val principal = call.principal<JWTPrincipal>()
    if (principal != null) {
        val phone = principal.payload.getClaim("phone").asString()?.let(::normalizePhone) ?: return null
        return userRepository.findByPhone(phone)
    }

    val bearerToken = call.request.headers["Authorization"]
        ?.removePrefix("Bearer ")
        ?.trim()
        ?.takeIf { it.isNotBlank() }
        ?: return null

    val decoded = runCatching { jwtService.verifier.verify(bearerToken) }.getOrNull() ?: return null
    val phone = decoded.getClaim("phone").asString()?.let(::normalizePhone) ?: return null
    return userRepository.findByPhone(phone)
}

private fun Device.toResponse(): DeviceResponse {
    return DeviceResponse(
        id = id,
        name = name,
        config = config
    )
}
