package org.example

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.github.smiley4.ktorswaggerui.SwaggerUI
import io.github.smiley4.ktorswaggerui.data.AuthKeyLocation
import io.github.smiley4.ktorswaggerui.data.AuthScheme
import io.github.smiley4.ktorswaggerui.data.AuthType
import io.github.smiley4.ktorswaggerui.dsl.routing.get
import io.github.smiley4.ktorswaggerui.dsl.routing.post
import io.github.smiley4.ktorswaggerui.dsl.routing.route
import io.github.smiley4.ktorswaggerui.routing.openApiSpec
import io.github.smiley4.ktorswaggerui.routing.swaggerUI
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.auth.Authentication
import io.ktor.server.auth.authenticate
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
    val jwtService = JwtService(appConfig.jwt)

    module(userRepository, jwtService, appConfig)
}

fun Application.module(
    userRepository: UserRepository,
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
            title = "Auth API"
            version = "1.2.0"
            description = "API for registration, login and JWT-based authorization"
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
                val email = credential.payload.getClaim("email").asString()
                if (email.isNullOrBlank()) null else JWTPrincipal(credential.payload)
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
                description = "Register a new user with email and password"
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
                        description = "User with this email already exists"
                        body<ErrorResponse> {
                            description = "Conflict error payload"
                        }
                    }
                }
            }) {
                val request = call.receive<RegisterRequest>()
                validateRegistrationCredentials(request.email, request.password)

                val normalizedEmail = request.email.trim().lowercase()
                val createdUser = userRepository.createUser(
                    email = normalizedEmail,
                    passwordHash = BCrypt.hashpw(request.password, BCrypt.gensalt())
                )

                if (createdUser == null) {
                    call.respond(
                        HttpStatusCode.Conflict,
                        ErrorResponse("User with this email already exists")
                    )
                    return@post
                }

                call.respond(
                    HttpStatusCode.Created,
                    RegisterResponse(
                        id = createdUser.id,
                        email = createdUser.email
                    )
                )
            }

            post("/login", {
                description = "Login with email and password to get JWT token"
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
                        description = "Invalid email or password"
                        body<ErrorResponse> {
                            description = "Unauthorized error payload"
                        }
                    }
                }
            }) {
                val request = call.receive<LoginRequest>()
                validateLoginCredentials(request.email, request.password)

                val normalizedEmail = request.email.trim().lowercase()
                val user = userRepository.findByEmail(normalizedEmail)
                if (user == null || !BCrypt.checkpw(request.password, user.passwordHash)) {
                    call.respond(HttpStatusCode.Unauthorized, ErrorResponse("Invalid email or password"))
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

            authenticate(AUTH_JWT) {
                get("/me", {
                    description = "Get current user by JWT token"
                    securitySchemeNames("bearerAuth")
                    response {
                        code(HttpStatusCode.OK) {
                            description = "Current authenticated user"
                            body<CurrentUserResponse> {
                                description = "Authenticated user payload"
                            }
                        }
                        code(HttpStatusCode.Unauthorized) {
                            description = "Missing or invalid token"
                            body<ErrorResponse> {
                                description = "Unauthorized error payload"
                            }
                        }
                    }
                }) {
                    val principal = call.principal<JWTPrincipal>()
                    val userId = principal?.payload?.getClaim("userId")?.asLong()
                    val email = principal?.payload?.getClaim("email")?.asString()

                    if (userId == null || email.isNullOrBlank()) {
                        call.respond(HttpStatusCode.Unauthorized, ErrorResponse("Invalid token"))
                        return@get
                    }

                    call.respond(
                        HttpStatusCode.OK,
                        CurrentUserResponse(
                            id = userId,
                            email = email
                        )
                    )
                }
            }
        }
    }
}

private fun validateRegistrationCredentials(email: String, password: String) {
    require(email.isNotBlank()) { "Email must not be blank" }
    require(EMAIL_REGEX.matches(email.trim())) { "Email format is invalid" }
    require(password.length >= 8) { "Password must be at least 8 characters long" }
}

private fun validateLoginCredentials(email: String, password: String) {
    require(email.isNotBlank()) { "Email must not be blank" }
    require(EMAIL_REGEX.matches(email.trim())) { "Email format is invalid" }
    require(password.isNotBlank()) { "Password must not be blank" }
}

private val EMAIL_REGEX = Regex("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$")

data class AppConfig(
    val databasePath: String,
    val jwt: JwtConfig
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
                )
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
            .withClaim("email", user.email)
            .withIssuedAt(Date(now))
            .withExpiresAt(Date(now + jwtConfig.expiresInMs))
            .sign(algorithm)
    }
}

@Serializable
data class RegisterRequest(
    val email: String,
    val password: String
)

@Serializable
data class RegisterResponse(
    val id: Long,
    val email: String
)

@Serializable
data class LoginRequest(
    val email: String,
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
    val email: String
)

@Serializable
data class ErrorResponse(
    val message: String
)

@Serializable
data class HealthResponse(
    val status: String
)
