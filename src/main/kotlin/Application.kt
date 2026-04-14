package org.example

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
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
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
        get("/health") {
            call.respond(HealthResponse(status = "ok"))
        }

        route("/api/auth") {
            post("/register") {
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
