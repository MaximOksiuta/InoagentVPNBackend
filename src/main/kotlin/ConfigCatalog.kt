package org.example

import kotlinx.serialization.Serializable
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

@Serializable data class CatalogEntry(val id: Long,val deviceId: Long,val deviceName: String,val serverId: Long,val serverName: String,val serverLocation: String,val archived: Boolean,val userId: Long,val userName: String,val userPhone: String?)
@Serializable data class CatalogServer(val id: Long,val name: String,val location: String,val archived: Boolean,val configCount: Int)
@Serializable data class CatalogPage(val entries: List<CatalogEntry>,val total: Int,val servers: List<CatalogServer>)
@Serializable data class ArchiveRequest(val configIds: List<Long>)
@Serializable data class ConfigText(val config: String)

class ConfigCatalog(private val db: DatabaseFactory) {
    private val base = " FROM device_servers c JOIN devices d ON d.id=c.device_id JOIN users u ON u.id=d.user_id JOIN servers s ON s.id=c.server_id "
    fun page(user: User,all: Boolean,serverId: Long?,ownerId: Long?,query: String,offset: Int,limit: Int): CatalogPage {
        require(!all || user.isAdmin) { "Нет доступа к конфигурациям других пользователей" }
        val filters=mutableListOf<String>();val params=mutableListOf<Any>()
        if(!all) { filters+="u.id=?";params+=user.id }
        if(serverId!=null) { filters+="s.id=?";params+=serverId }
        if(ownerId!=null) { filters+="u.id=?";params+=ownerId }
        if(query.isNotBlank()) { filters+="(d.name LIKE ? OR u.nickname LIKE ? OR u.phone LIKE ?)";repeat(3){params+="%${query.take(100)}%"} }
        val where=if(filters.isEmpty()) "" else " WHERE "+filters.joinToString(" AND ")
        return db.connection().use { c ->
            fun count()=c.prepareStatement("SELECT COUNT(*)"+base+where).use { s -> params.forEachIndexed { i,v->s.setObject(i+1,v) };s.executeQuery().use { it.next();it.getInt(1) } }
            val entries=c.prepareStatement("SELECT c.id,d.id AS device_id,d.name AS device_name,s.id AS server_id,s.name AS server_name,s.location,s.archived,u.id AS user_id,u.nickname,u.phone"+base+where+" ORDER BY u.nickname,d.name,c.id LIMIT ? OFFSET ?").use { s ->
                params.forEachIndexed { i,v->s.setObject(i+1,v) };s.setInt(params.size+1,limit);s.setInt(params.size+2,offset)
                s.executeQuery().use { r -> buildList { while(r.next()) add(CatalogEntry(r.getLong("id"),r.getLong("device_id"),r.getString("device_name"),r.getLong("server_id"),r.getString("server_name"),r.getString("location"),r.getInt("archived")==1,r.getLong("user_id"),r.getString("nickname"),if(user.isAdmin && all) r.getString("phone") else null)) } }
            }
            val serverRows=c.prepareStatement("SELECT s.id,s.name,s.location,s.archived,COUNT(c.id) AS total FROM servers s LEFT JOIN device_servers c ON c.server_id=s.id LEFT JOIN devices d ON d.id=c.device_id WHERE s.archived=0 OR c.id IS NOT NULL GROUP BY s.id ORDER BY s.archived,s.id").use { s -> s.executeQuery().use { r -> buildList { while(r.next()) add(CatalogServer(r.getLong("id"),r.getString("name"),r.getString("location"),r.getInt("archived")==1,r.getInt("total"))) } } }
            val ownedCounts=if(!all) c.prepareStatement("SELECT c.server_id,COUNT(*) FROM device_servers c JOIN devices d ON d.id=c.device_id WHERE d.user_id=? GROUP BY c.server_id").use { s -> s.setLong(1,user.id);s.executeQuery().use { r -> buildMap { while(r.next()) put(r.getLong(1),r.getInt(2)) } } } else emptyMap()
            CatalogPage(entries,count(),serverRows.map { if(!all) it.copy(configCount=ownedCounts[it.id] ?: 0) else it }.filter { !it.archived || it.configCount>0 })
        }
    }

    data class File(val name: String,val content: String,val location: String)
    fun file(user: User,id: Long): File? = db.connection().use { c ->
        c.prepareStatement("SELECT c.config,d.name,u.id,u.nickname,s.id,s.name,s.location"+base+" WHERE c.id=? AND (?=1 OR u.id=?)").use { s ->
            s.setLong(1,id);s.setInt(2,if(user.isAdmin) 1 else 0);s.setLong(3,user.id)
            s.executeQuery().use { r -> if(!r.next()) null else File("${safe(r.getString(4))}_user-${r.getLong(3)}/${safe(r.getString(6))}_server-${r.getLong(5)}/${safe(r.getString(2))}_config-$id.conf",r.getString(1),r.getString(7)) }
        }
    }
    fun archive(user: User,ids: List<Long>): ByteArray {
        require(ids.isNotEmpty() && ids.size<=1000) { "Выберите от 1 до 1000 конфигураций" }
        val files=ids.distinct().map { file(user,it) ?: throw IllegalArgumentException("Нет доступа к одной из конфигураций") }
        require(files.sumOf { it.content.toByteArray().size }<=20_000_000) { "Архив слишком большой" }
        val bytes=ByteArrayOutputStream()
        ZipOutputStream(bytes).use { zip -> files.forEach { f -> zip.putNextEntry(ZipEntry(f.name));zip.write(f.content.toByteArray());zip.closeEntry() } }
        return bytes.toByteArray()
    }
    private fun safe(value: String)=value.replace(Regex("[^\\p{L}\\p{N}._ -]"),"_").trim(' ','.').take(64).ifBlank { "config" }
}
