package org.example

import io.ktor.server.testing.testApplication
import io.ktor.server.config.MapApplicationConfig
import io.ktor.client.request.*
import io.ktor.client.statement.bodyAsText
import io.ktor.http.*
import java.nio.file.Files
import kotlinx.serialization.json.Json
import kotlin.test.*
import org.mindrot.jbcrypt.BCrypt

class RecoveryApiTest {
    @Test fun `reset endpoint requires bot proof and revokes old jwt`() = testApplication {
        environment { config = MapApplicationConfig() }
        val config = AppConfig(Files.createTempDirectory("recovery-api").resolve("db.sqlite").toString(), JwtConfig("test-secret", "issuer", "audience", "realm", 60_000), "bot-secret")
        val db = DatabaseFactory(config.databasePath); db.initialize()
        val users = SqliteUserRepository(db)
        val user = users.createUser("+79778343379", "Test", 123, BCrypt.hashpw("old-password", BCrypt.gensalt()))!!
        users.updateApproval(user.id, true)
        val jwt = JwtService(config.jwt)
        val oldToken = jwt.generateToken(user)
        application { module(users, SqliteDeviceRepository(db), SqliteDeviceServerRepository(db), SqliteServerRepository(db), jwt, config) }
        suspend fun issue(key: String) = client.post("/api/auth/recovery/telegram") {
            contentType(ContentType.Application.Json); header("X-Super-Key", key)
            setBody("""{"phone":"+7 (977) 834-33-79","telegramId":123}""")
        }
        assertEquals(HttpStatusCode.Unauthorized, issue("wrong").status)
        val ticketResponse = issue("bot-secret")
        assertEquals(HttpStatusCode.OK, ticketResponse.status)
        val ticket = Json.decodeFromString<RecoveryTicket>(ticketResponse.bodyAsText())
        suspend fun reset() = client.post("/api/auth/recovery/reset") {
            contentType(ContentType.Application.Json)
            setBody("""{"token":"${ticket.token}","password":"new-password"}""")
        }
        assertEquals(HttpStatusCode.OK, reset().status)
        assertEquals(HttpStatusCode.BadRequest, reset().status)
        assertEquals(HttpStatusCode.Unauthorized, client.get("/api/auth/me") { header("Authorization", "Bearer $oldToken") }.status)
        val updated = users.findById(user.id)!!
        val newToken = jwt.generateToken(updated)
        assertEquals(HttpStatusCode.OK, client.get("/api/auth/me") { header("Authorization", "Bearer $newToken") }.status)
        assertEquals(HttpStatusCode.OK, client.post("/api/auth/login") {
            contentType(ContentType.Application.Json); setBody("""{"phone":"8 (977) 834-33-79","password":"new-password"}""")
        }.status)
    }
}
