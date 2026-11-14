package org.example

import io.ktor.server.testing.testApplication
import io.ktor.server.config.MapApplicationConfig
import io.ktor.client.request.*
import io.ktor.client.statement.bodyAsText
import io.ktor.http.*
import java.nio.file.Files
import kotlinx.serialization.json.Json
import kotlinx.serialization.builtins.ListSerializer
import kotlin.test.*

class WorkflowApiTest {
    @Test fun `workflow API protects files jobs and bot outbox`() = testApplication {
        environment { config=MapApplicationConfig() }
        val config=AppConfig(Files.createTempDirectory("workflow-api").resolve("db").toString(),JwtConfig("secret","issuer","audience","realm",60000),"bot-secret")
        val db=DatabaseFactory(config.databasePath);db.initialize()
        val users=SqliteUserRepository(db);val devices=SqliteDeviceRepository(db);val configs=SqliteDeviceServerRepository(db);val servers=SqliteServerRepository(db)
        fun user(phone:String,admin:Boolean=false):User {val u=users.createUser(phone,"Test",123,"hash",admin)!!;users.updateApproval(u.id,true);return users.findById(u.id)!!}
        val admin=user("+79991112233",true);val owner=user("+79991112234");val third=user("+79991112235")
        val a=devices.createDevice(admin.id,"Admin device");val b=devices.createDevice(owner.id,"My device")
        val server=servers.createServer("New server","UK",AwgConnection("127.0.0.1",22,"root","pass"),"Обновите VPN-клиент.")
        val privateConfig=configs.upsert(a.id,server.id,"SECRET_ADMIN_CONFIG")
        val jwt=JwtService(config.jwt);val ownerToken=jwt.generateToken(owner);val adminToken=jwt.generateToken(admin)
        val generator=object:DeviceConfigGenerator { override fun generate(server:Server,user:User,device:Device)=GeneratedDeviceConfig("key","USER_CONFIG_${user.id}") }
        application { module(users,devices,configs,servers,jwt,config,deviceConfigGenerator=generator) }
        suspend fun request(path:String,token:String=ownerToken)=client.get(path){header(HttpHeaders.Authorization,"Bearer $token")}
        assertEquals(HttpStatusCode.Unauthorized,client.get("/api/library").status)
        assertEquals(HttpStatusCode.NotFound,request("/api/library/${privateConfig.id}/file").status)
        assertEquals(HttpStatusCode.OK,request("/api/library/${privateConfig.id}/file",adminToken).status)
        val page=Json.decodeFromString<CatalogPage>(request("/api/library").bodyAsText());assertEquals(0,page.total)
        assertFalse(request("/api/library?all=true").status.isSuccess())
        assertEquals(HttpStatusCode.BadRequest,client.post("/api/library/archive"){header(HttpHeaders.Authorization,"Bearer $ownerToken");contentType(ContentType.Application.Json);setBody("""{"configIds":[${privateConfig.id}]}""")}.status)
        val enqueue=client.post("/api/generation/jobs"){header(HttpHeaders.Authorization,"Bearer $ownerToken");contentType(ContentType.Application.Json);setBody("""{"serverId":${server.id},"requestKey":"request-test-123"}""")}
        assertEquals(HttpStatusCode.Accepted,enqueue.status)
        val job=Json.decodeFromString<GenerationJobView>(enqueue.bodyAsText())
        assertEquals(HttpStatusCode.NotFound,request("/api/generation/jobs/${job.id}",jwt.generateToken(third)).status)
        assertEquals(listOf(b.id),job.items.map { it.deviceId })
        assertEquals(HttpStatusCode.Unauthorized,client.get("/api/bot/notifications").status)
        assertEquals(HttpStatusCode.Unauthorized,request("/api/bot/notifications").status)
        val pending=client.get("/api/bot/notifications"){header("X-Super-Key","bot-secret")}
        val notifications=Json.decodeFromString(ListSerializer(BotNotification.serializer()),pending.bodyAsText());assertEquals(3,notifications.size)
        assertTrue(notifications.all { it.comment == "Обновите VPN-клиент." })
        val item=notifications.first {it.phone==owner.phone}
        val ack=client.post("/api/bot/notifications/${item.id}/delivery"){header("X-Super-Key","bot-secret");contentType(ContentType.Application.Json);setBody("""{"delivered":true}""")}
        assertEquals(HttpStatusCode.NoContent,ack.status)
        val remaining=client.get("/api/bot/notifications"){header("X-Super-Key","bot-secret")}
        assertFalse(Json.decodeFromString(ListSerializer(BotNotification.serializer()),remaining.bodyAsText()).any {it.id==item.id})
        val inbox=Json.decodeFromString(ListSerializer(ServerNotification.serializer()),request("/api/notifications").bodyAsText());assertEquals(1,inbox.size);assertFalse(inbox.single().read)
        assertEquals("Обновите VPN-клиент.", inbox.single().comment)
        assertEquals(HttpStatusCode.NoContent,client.post("/api/notifications/${inbox.single().id}/read"){header(HttpHeaders.Authorization,"Bearer $ownerToken")}.status)
        assertTrue(Json.decodeFromString(ListSerializer(ServerNotification.serializer()),request("/api/notifications").bodyAsText()).single().read)

        val bannedAdmin = user("+79991112236", true)
        users.updateBan(bannedAdmin.id, true)
        users.createUser("+79991112237", "Pending admin", null, "hash", true)
        assertEquals(HttpStatusCode.Unauthorized, request("/api/bot/server-monitoring").status)
        val monitoring = client.get("/api/bot/server-monitoring") { header("X-Super-Key", "bot-secret") }
        assertEquals(HttpStatusCode.OK, monitoring.status)
        val snapshot = Json.decodeFromString<MonitoringSnapshot>(monitoring.bodyAsText())
        assertEquals(listOf(MonitoringAdmin(admin.phone, admin.telegramId)), snapshot.admins)
        assertEquals(server.id, snapshot.servers.single().id)
        assertNull(snapshot.servers.single().probeUrl)
    }
}
