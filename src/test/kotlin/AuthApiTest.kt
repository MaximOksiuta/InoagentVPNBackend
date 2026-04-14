package org.example

import io.ktor.client.call.body
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.testing.testApplication
import io.ktor.server.config.MapApplicationConfig
import kotlinx.serialization.Serializable
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
            CurrentUserResponse(id = 1L, phone = "+79991234567", telegramId = 123L),
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
            CurrentUserResponse(id = 1L, phone = "+79991112233", telegramId = null),
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
