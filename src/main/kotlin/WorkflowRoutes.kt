package org.example

import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.routing.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable

@Serializable data class ServerNotification(val id: Long,val serverId: Long,val serverName: String,val location: String,val createdAt: Long,val read: Boolean)
@Serializable data class BotNotification(val id: Long,val serverId: Long,val serverName: String,val location: String,val phone: String,val telegramId: Long?)
@Serializable data class DeliveryReport(val delivered: Boolean)

fun Route.workflowRoutes(db: DatabaseFactory,queue: GenerationQueue,superKey: String,authenticate: suspend (ApplicationCall)->User?) {
    val catalog=ConfigCatalog(db)
    suspend fun user(call: ApplicationCall): User? = authenticate(call).also { if(it==null) call.respond(HttpStatusCode.Unauthorized,ErrorResponse("Invalid credentials")) }
    suspend fun <T> io(action:()->T): T = withContext(Dispatchers.IO) { action() }
    suspend fun bot(call: ApplicationCall): Boolean {
        val supplied=call.request.headers["X-Super-Key"].orEmpty()
        val valid=superKey.isNotBlank() && java.security.MessageDigest.isEqual(supplied.toByteArray(),superKey.toByteArray())
        if(!valid) call.respond(HttpStatusCode.Unauthorized,ErrorResponse("Invalid credentials"))
        return valid
    }
    get("/api/library") {
        val owner=user(call) ?: return@get
        val q=call.request.queryParameters
        val result=io { catalog.page(owner,q["all"]=="true",q["serverId"]?.toLongOrNull(),q["userId"]?.toLongOrNull(),q["query"].orEmpty(),q["offset"]?.toIntOrNull()?.coerceAtLeast(0) ?: 0,q["limit"]?.toIntOrNull()?.coerceIn(1,100) ?: 50) }
        call.response.headers.append(HttpHeaders.CacheControl,"no-store");call.respond(result)
    }
    get("/api/library/{id}/{format}") {
        val owner=user(call) ?: return@get
        val id=call.parameters["id"]?.toLongOrNull() ?: return@get call.respond(HttpStatusCode.BadRequest)
        val file=io { catalog.file(owner,id) } ?: return@get call.respond(HttpStatusCode.NotFound)
        call.response.headers.append(HttpHeaders.CacheControl,"no-store")
        when(call.parameters["format"]) {
            "file" -> { call.response.headers.append(HttpHeaders.ContentDisposition,ContentDisposition.Attachment.withParameter(ContentDisposition.Parameters.FileName,file.name.substringAfterLast('/')).toString());call.respondBytes(file.content.toByteArray(),ContentType.Text.Plain) }
            "text" -> call.respond(ConfigText(file.content))
            "qr" -> call.respondBytes(io { AwgQrCodeService.generatePng(file.content,file.location) },ContentType.Image.PNG)
            else -> call.respond(HttpStatusCode.NotFound)
        }
    }
    post("/api/library/archive") {
        val owner=user(call) ?: return@post
        val request=call.receive<ArchiveRequest>()
        val bytes=io { catalog.archive(owner,request.configIds) }
        call.response.headers.append(HttpHeaders.CacheControl,"no-store")
        call.response.headers.append(HttpHeaders.ContentDisposition,"attachment; filename=inoagent-configs.zip")
        call.respondBytes(bytes,ContentType.Application.Zip)
    }
    post("/api/generation/jobs") {
        val owner=user(call) ?: return@post
        val request=call.receive<BatchRequest>()
        call.respond(HttpStatusCode.Accepted,io { queue.enqueue(owner,request) })
    }
    get("/api/generation/jobs") { val owner=user(call) ?: return@get;call.respond(io { queue.list(owner) }) }
    get("/api/generation/jobs/{id}") { val owner=user(call) ?: return@get;val job=io { queue.get(owner,call.parameters["id"].orEmpty()) };if(job==null) call.respond(HttpStatusCode.NotFound) else call.respond(job) }
    post("/api/generation/jobs/{id}/retry") { val owner=user(call) ?: return@post;val job=io { queue.retry(owner,call.parameters["id"].orEmpty()) };if(job==null) call.respond(HttpStatusCode.NotFound) else call.respond(HttpStatusCode.Accepted,job) }
    get("/api/notifications") {
        val owner=user(call) ?: return@get
        val rows=io { db.connection().use { c -> c.prepareStatement("SELECT n.*,s.name,s.location FROM server_notifications n JOIN servers s ON s.id=n.server_id WHERE n.user_id=? AND s.archived=0 ORDER BY n.created_at DESC LIMIT 100").use { s ->
            s.setLong(1,owner.id);s.executeQuery().use { r -> buildList { while(r.next()) add(ServerNotification(r.getLong("id"),r.getLong("server_id"),r.getString("name"),r.getString("location"),r.getLong("created_at"),r.getObject("read_at")!=null)) } }
        } } }
        call.respond(rows)
    }
    post("/api/notifications/{id}/read") {
        val owner=user(call) ?: return@post
        val id=call.parameters["id"]?.toLongOrNull() ?: return@post call.respond(HttpStatusCode.BadRequest)
        io { db.connection().use { c -> c.prepareStatement("UPDATE server_notifications SET read_at=? WHERE id=? AND user_id=?").use { s -> s.setLong(1,System.currentTimeMillis());s.setLong(2,id);s.setLong(3,owner.id);s.executeUpdate() } } }
        call.respond(HttpStatusCode.NoContent)
    }
    get("/api/bot/notifications") {
        if(!bot(call)) return@get
        val rows=io { db.connection().use { c -> c.prepareStatement("SELECT n.id,n.server_id,s.name,s.location,u.phone,u.telegram_id FROM server_notifications n JOIN servers s ON s.id=n.server_id JOIN users u ON u.id=n.user_id WHERE n.delivered_at IS NULL AND n.attempts<10 AND n.retry_at<=? AND s.archived=0 AND u.is_approved=1 AND u.is_banned=0 ORDER BY n.created_at LIMIT 50").use { s -> s.setLong(1,System.currentTimeMillis());s.executeQuery().use { r -> buildList { while(r.next()) add(BotNotification(r.getLong("id"),r.getLong("server_id"),r.getString("name"),r.getString("location"),r.getString("phone"),r.getLong("telegram_id").takeUnless { r.wasNull() })) } } } } }
        call.response.headers.append(HttpHeaders.CacheControl,"no-store");call.respond(rows)
    }
    post("/api/bot/notifications/{id}/delivery") {
        if(!bot(call)) return@post
        val id=call.parameters["id"]?.toLongOrNull() ?: return@post call.respond(HttpStatusCode.BadRequest)
        val report=call.receive<DeliveryReport>()
        io { db.connection().use { c -> c.prepareStatement("UPDATE server_notifications SET delivered_at=?,attempts=attempts+1,retry_at=? WHERE id=? AND delivered_at IS NULL").use { s -> s.setObject(1,if(report.delivered) System.currentTimeMillis() else null);s.setLong(2,System.currentTimeMillis()+300_000);s.setLong(3,id);s.executeUpdate() } } }
        call.respond(HttpStatusCode.NoContent)
    }
}
