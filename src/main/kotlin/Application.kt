package org.example

import io.github.smiley4.ktorswaggerui.SwaggerUI
import io.github.smiley4.ktorswaggerui.dsl.routing.get
import io.github.smiley4.ktorswaggerui.dsl.routing.post
import io.github.smiley4.ktorswaggerui.dsl.routing.route
import io.github.smiley4.ktorswaggerui.routing.openApiSpec
import io.github.smiley4.ktorswaggerui.routing.swaggerUI
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.callloging.CallLogging
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.routing
import kotlinx.serialization.Serializable
import org.mindrot.jbcrypt.BCrypt

fun main() {
    val databaseFactory = DatabaseFactory()
    databaseFactory.initialize()
    val userRepository = SqliteUserRepository(databaseFactory)

    embeddedServer(Netty, port = 8080, host = "0.0.0.0") {
        module(userRepository)
    }.start(wait = true)
}

fun Application.module(userRepository: UserRepository) {
    install(CallLogging)
    install(ContentNegotiation) {
        json()
    }
    install(SwaggerUI) {
        info {
            title = "Auth API"
            version = "1.0.0"
            description = "API for registering users by email and password"
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

        route("/swagger") {
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
                    code(HttpStatusCode.InternalServerError) {
                        description = "Unexpected server error"
                        body<ErrorResponse> {
                            description = "Internal server error payload"
                        }
                    }
                }
            }) {
                val request = call.receive<RegisterRequest>()
                validateRegisterRequest(request)

                val createdUser = userRepository.createUser(
                    email = request.email.trim().lowercase(),
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
        }
    }
}

private fun validateRegisterRequest(request: RegisterRequest) {
    require(request.email.isNotBlank()) { "Email must not be blank" }
    require(EMAIL_REGEX.matches(request.email.trim())) { "Email format is invalid" }
    require(request.password.length >= 8) { "Password must be at least 8 characters long" }
}

private val EMAIL_REGEX = Regex("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$")

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
data class ErrorResponse(
    val message: String
)

@Serializable
data class HealthResponse(
    val status: String
)
