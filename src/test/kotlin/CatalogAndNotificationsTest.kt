package org.example

import java.nio.file.Files
import java.util.zip.ZipInputStream
import kotlin.test.*

class CatalogAndNotificationsTest {
    @Test fun `catalog scopes ownership zip preserves text and new servers create one notification per approved user`() {
        val db=DatabaseFactory(Files.createTempDirectory("catalog-test").resolve("db").toString());db.initialize()
        val users=SqliteUserRepository(db);val devices=SqliteDeviceRepository(db);val servers=SqliteServerRepository(db);val configs=SqliteDeviceServerRepository(db)
        fun user(phone:String,admin:Boolean=false):User {val u=users.createUser(phone,"Owner",123,"hash",admin)!!;users.updateApproval(u.id,true);return users.findById(u.id)!!}
        val admin=user("+79991112233",true);val owner=user("+79991112234");val stranger=user("+79991112235")
        users.updateBan(stranger.id,true)
        val server=servers.createServer("London","UK",AwgConnection("host",22,"root","pass"))
        val first=devices.createDevice(admin.id,"../../unsafe");val second=devices.createDevice(owner.id,"Phone")
        val a=configs.upsert(first.id,server.id,"private-admin\n");val b=configs.upsert(second.id,server.id,"private-owner\n")
        val catalog=ConfigCatalog(db)
        assertEquals(1,catalog.page(owner,false,null,null,"",0,50).total)
        assertNull(catalog.file(owner,a.id));assertNotNull(catalog.file(owner,b.id))
        assertFailsWith<IllegalArgumentException>{catalog.page(owner,true,null,null,"",0,50)}
        assertFailsWith<IllegalArgumentException>{catalog.archive(owner,listOf(a.id,b.id))}
        assertEquals(2,catalog.page(admin,true,server.id,null,"",0,50).total)
        val contents=mutableListOf<String>()
        ZipInputStream(catalog.archive(admin,listOf(a.id,b.id)).inputStream()).use { zip ->
            while(true){val entry=zip.nextEntry ?: break;assertFalse(entry.name.startsWith('/'));assertFalse(entry.name.split('/').contains(".."));contents+=zip.readBytes().toString(Charsets.UTF_8)}
        }
        assertEquals(listOf("private-admin\n","private-owner\n"),contents)
        db.connection().use { c -> c.createStatement().executeQuery("SELECT COUNT(*) FROM server_notifications").use { it.next();assertEquals(2,it.getInt(1)) } }
        servers.updateServer(server.id,"Renamed","UK",server.connection)
        db.connection().use { c -> c.createStatement().executeQuery("SELECT COUNT(*) FROM server_notifications").use { it.next();assertEquals(2,it.getInt(1)) } }
        servers.deleteServer(server.id)
        assertEquals(1,catalog.page(owner,false,null,null,"",0,50).total)
        assertTrue(catalog.page(owner,false,null,null,"",0,50).servers.single().archived)
    }
}
