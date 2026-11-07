package org.example

import java.sql.Connection
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable

fun initializeWorkflowTables(c: Connection) {
    c.createStatement().use { s ->
        s.executeUpdate("CREATE TABLE IF NOT EXISTS generation_jobs (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), server_id INTEGER NOT NULL REFERENCES servers(id), request_key TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(user_id, request_key))")
        s.executeUpdate("CREATE TABLE IF NOT EXISTS generation_items (job_id TEXT NOT NULL REFERENCES generation_jobs(id) ON DELETE CASCADE, device_id INTEGER NOT NULL, server_id INTEGER NOT NULL, device_name TEXT NOT NULL, owner_id INTEGER NOT NULL, owner_name TEXT NOT NULL, state TEXT NOT NULL, config_id INTEGER, error TEXT, PRIMARY KEY(job_id,device_id))")
        s.executeUpdate("CREATE UNIQUE INDEX IF NOT EXISTS generation_active_pair ON generation_items(device_id,server_id) WHERE state IN ('queued','running')")
        s.executeUpdate("CREATE INDEX IF NOT EXISTS generation_queue_state ON generation_items(state,server_id)")
        s.executeUpdate("CREATE TABLE IF NOT EXISTS server_notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id), server_id INTEGER NOT NULL REFERENCES servers(id), created_at INTEGER NOT NULL, read_at INTEGER, delivered_at INTEGER, attempts INTEGER NOT NULL DEFAULT 0, retry_at INTEGER NOT NULL DEFAULT 0, UNIQUE(user_id,server_id))")
    }
}

fun announceNewServer(c: Connection, serverId: Long) {
    c.prepareStatement("INSERT OR IGNORE INTO server_notifications(user_id,server_id,created_at) SELECT id,?,? FROM users WHERE is_approved=1 AND is_banned=0").use { s ->
        s.setLong(1, serverId); s.setLong(2, System.currentTimeMillis()); s.executeUpdate()
    }
}

@Serializable data class BatchRequest(val serverId: Long, val deviceIds: List<Long>? = null, val allUsers: Boolean = false, val requestKey: String, val userId: Long? = null)
@Serializable data class GenerationItemView(val deviceId: Long, val deviceName: String, val userId: Long, val userName: String, val state: String, val configId: Long?, val error: String?)
@Serializable data class GenerationJobView(val id: String, val serverId: Long, val serverName: String, val createdAt: Long, val state: String, val items: List<GenerationItemView>)

/** SQLite owns the queue. Per-server locks cover both queued and legacy synchronous requests. */
class GenerationQueue(
    private val db: DatabaseFactory,
    private val users: UserRepository,
    private val devices: DeviceRepository,
    private val configs: DeviceServerRepository,
    private val servers: ServerRepository,
    private val generator: DeviceConfigGenerator,
    private val guard: DeviceConfigMutationGuard
) : AutoCloseable {
    private val scheduler = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "generation-scheduler").apply { isDaemon = true } }
    private val workers = Executors.newFixedThreadPool(2) { r -> Thread(r, "generation-worker").apply { isDaemon = true } }
    private val runningServers = ConcurrentHashMap.newKeySet<Long>()
    @Volatile private var closed = false

    fun start() {
        db.connection().use { it.createStatement().executeUpdate("UPDATE generation_items SET state='queued' WHERE state='running'") }
        scheduler.scheduleWithFixedDelay({ runCatching { dispatch() } }, 0, 500, TimeUnit.MILLISECONDS)
    }

    @Synchronized fun enqueue(user: User, request: BatchRequest): GenerationJobView {
        require(request.requestKey.matches(Regex("[A-Za-z0-9_-]{8,100}"))) { "Invalid request key" }
        require(!request.allUsers || user.isAdmin) { "Только администратор может выпускать конфиги другим пользователям" }
        require(request.userId == null || user.isAdmin || request.userId == user.id) { "Нет доступа к пользователю" }
        val server = servers.listServers().find { it.id == request.serverId } ?: error("Сервер недоступен для выпуска")
        val owners = (if (request.allUsers) users.listUsers().filter { it.isApproved && !it.isBanned } else listOf(user)).filter { request.userId == null || it.id == request.userId }
        val available = owners.flatMap { owner -> devices.listDevices(owner.id).map { owner to it } }
        val requested = request.deviceIds?.toSet()
        require(requested == null || requested.isNotEmpty()) { "Выберите устройства" }
        require(requested == null || requested.all { id -> available.any { it.second.id == id } }) { "Нет доступа к выбранным устройствам" }
        val targets = available.filter { requested == null || it.second.id in requested }
        require(targets.isNotEmpty() && targets.size <= 1000) { "В задании должно быть от 1 до 1000 устройств" }
        val jobId = db.transaction { c ->
            val existing = c.prepareStatement("SELECT id,server_id FROM generation_jobs WHERE user_id=? AND request_key=?").use { s ->
                s.setLong(1,user.id); s.setString(2,request.requestKey)
                s.executeQuery().use { r -> if(r.next()) { require(r.getLong(2)==server.id) { "Ключ запроса уже использован" }; r.getString(1) } else null }
            }
            if (existing != null) return@transaction existing
            c.prepareStatement("SELECT COUNT(*) FROM generation_items i JOIN generation_jobs j ON j.id=i.job_id WHERE j.user_id=? AND i.state IN ('queued','running')").use { s ->
                s.setLong(1,user.id); s.executeQuery().use { r -> r.next(); require(r.getInt(1) < 1000) { "Дождитесь завершения очереди" } }
            }
            val id = UUID.randomUUID().toString()
            c.prepareStatement("INSERT INTO generation_jobs VALUES (?,?,?,?,?)").use { s -> s.setString(1,id);s.setLong(2,user.id);s.setLong(3,server.id);s.setString(4,request.requestKey);s.setLong(5,System.currentTimeMillis());s.executeUpdate() }
            for ((owner,device) in targets) {
                val configId = c.prepareStatement("SELECT id FROM device_servers WHERE device_id=? AND server_id=?").use { s -> s.setLong(1,device.id);s.setLong(2,server.id);s.executeQuery().use { r -> if(r.next()) r.getLong(1) else null } }
                val pending = c.prepareStatement("SELECT 1 FROM generation_items WHERE device_id=? AND server_id=? AND state IN ('queued','running')").use { s -> s.setLong(1,device.id);s.setLong(2,server.id);s.executeQuery().use { it.next() } }
                c.prepareStatement("INSERT INTO generation_items(job_id,device_id,server_id,device_name,owner_id,owner_name,state,config_id,error) VALUES (?,?,?,?,?,?,?,?,?)").use { s ->
                    s.setString(1,id);s.setLong(2,device.id);s.setLong(3,server.id);s.setString(4,device.name);s.setLong(5,owner.id);s.setString(6,owner.nickname)
                    s.setString(7,if(configId != null || pending) "skipped" else "queued");s.setObject(8,configId);s.setString(9,if(pending && configId == null) "Устройство уже в очереди" else null);s.executeUpdate()
                }
            }
            id
        }
        return get(user,jobId)!!
    }

    fun list(user: User): List<GenerationJobView> = db.connection().use { c ->
        c.prepareStatement("SELECT id FROM generation_jobs WHERE user_id=? ORDER BY created_at DESC LIMIT 30").use { s -> s.setLong(1,user.id);s.executeQuery().use { r -> buildList { while(r.next()) add(r.getString(1)) } } }
    }.mapNotNull { get(user,it) }

    fun get(user: User, id: String): GenerationJobView? = db.connection().use { c ->
        c.prepareStatement("SELECT j.server_id,s.name,j.created_at FROM generation_jobs j JOIN servers s ON s.id=j.server_id WHERE j.id=? AND j.user_id=?").use { s ->
            s.setString(1,id);s.setLong(2,user.id)
            s.executeQuery().use rows@{ r ->
                if(!r.next()) return@rows null
                val serverId=r.getLong(1);val serverName=r.getString(2);val created=r.getLong(3)
                val items=c.prepareStatement("SELECT * FROM generation_items WHERE job_id=? ORDER BY device_id").use { q -> q.setString(1,id);q.executeQuery().use { rows -> buildList {
                    while(rows.next()) add(GenerationItemView(rows.getLong("device_id"),rows.getString("device_name"),rows.getLong("owner_id"),rows.getString("owner_name"),rows.getString("state"),rows.getLong("config_id").takeUnless { rows.wasNull() },rows.getString("error")))
                } } }
                val state = when { items.any { it.state=="running" } -> "running";items.any { it.state=="queued" } -> "queued";items.any { it.state=="failed" } -> "partial";else -> "completed" }
                GenerationJobView(id,serverId,serverName,created,state,items)
            }
        }
    }

    fun retry(user: User, id: String): GenerationJobView? {
        val job=get(user,id) ?: return null
        require(servers.listServers().any { it.id==job.serverId }) { "Сервер выведен из пула" }
        db.transaction { c -> c.prepareStatement("UPDATE generation_items SET state='queued',error=NULL WHERE job_id=? AND state='failed' AND NOT EXISTS (SELECT 1 FROM generation_items other WHERE other.device_id=generation_items.device_id AND other.server_id=generation_items.server_id AND other.state IN ('queued','running'))").use { s -> s.setString(1,id);s.executeUpdate() } }
        return get(user,id)
    }

    private data class Work(val job: String,val deviceId: Long,val ownerId: Long,val requesterId: Long)
    private fun pending(serverId: Long): List<Work> = db.connection().use { c -> c.prepareStatement("SELECT i.job_id,i.device_id,i.owner_id,j.user_id FROM generation_items i JOIN generation_jobs j ON j.id=i.job_id WHERE i.server_id=? AND i.state='queued' ORDER BY j.created_at,i.device_id LIMIT 16").use { s -> s.setLong(1,serverId);s.executeQuery().use { r -> buildList { while(r.next()) add(Work(r.getString(1),r.getLong(2),r.getLong(3),r.getLong(4))) } } } }
    private fun finish(w: Work,state: String,configId: Long?=null,error: String?=null) = db.connection().use { c -> c.prepareStatement("UPDATE generation_items SET state=?,config_id=?,error=? WHERE job_id=? AND device_id=?" + if(state=="failed") " AND state IN ('queued','running')" else "").use { s -> s.setString(1,state);s.setObject(2,configId);s.setString(3,error);s.setString(4,w.job);s.setLong(5,w.deviceId);s.executeUpdate() } }

    private fun dispatch() {
        if(closed) return
        val ids=db.connection().use { c -> c.createStatement().executeQuery("SELECT DISTINCT server_id FROM generation_items WHERE state='queued'").use { r -> buildList { while(r.next()) add(r.getLong(1)) } } }
        for(id in ids) {
            if(runningServers.size>=2) break
            if(runningServers.add(id)) workers.submit { try { process(id) } finally { runningServers.remove(id) } }
        }
    }
    private fun process(serverId: Long) = guard.withServerLock(serverId) {
        val batch=pending(serverId)
        if(batch.isEmpty() || closed) return@withServerLock
        try {
            val server=servers.listServers().find { it.id==serverId } ?: error("Server retired")
            generator.withSession(server) { session ->
                for(w in batch) {
                    if(closed) break
                    try {
                        finish(w,"running")
                        val requester=users.findById(w.requesterId) ?: error("Requester deleted")
                        val owner=users.findById(w.ownerId) ?: error("User deleted")
                        require(requester.isApproved && !requester.isBanned && owner.isApproved && !owner.isBanned)
                        require(requester.id==owner.id || requester.isAdmin)
                        val device=devices.findDevice(owner.id,w.deviceId) ?: error("Device deleted")
                        val existing=configs.findByDeviceAndServer(device.id,serverId)
                        if(existing!=null) { finish(w,"skipped",existing.id);continue }
                        val generated=session.generate(server,owner,device)
                        val saved=configs.upsert(device.id,serverId,generated.config)
                        finish(w,"done",saved.id)
                    } catch (_: Exception) { finish(w,"failed",error="Не удалось выпустить конфигурацию. Можно повторить задание") }
                }
            }
        } catch (_: Exception) {
            for(w in batch) finish(w,"failed",error="Нет доступа к серверу. Проверьте SSH и повторите задание")
        }
    }
    override fun close() { closed=true;scheduler.shutdownNow();workers.shutdown();workers.awaitTermination(35,TimeUnit.SECONDS) }
}
