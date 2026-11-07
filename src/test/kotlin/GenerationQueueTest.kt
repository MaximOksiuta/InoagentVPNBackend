package org.example

import java.nio.file.Files
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

class GenerationQueueTest {
    private class Fixture {
        val db=DatabaseFactory(Files.createTempDirectory("queue-test").resolve("app.db").toString()).also { it.initialize() }
        val users=SqliteUserRepository(db);val devices=SqliteDeviceRepository(db);val configs=SqliteDeviceServerRepository(db);val servers=SqliteServerRepository(db)
        fun user(phone:String,admin:Boolean=false):User { val u=users.createUser(phone,phone,1,"hash",admin)!!;users.updateApproval(u.id,true);return users.findById(u.id)!! }
        fun server()=servers.createServer("Test","Test",AwgConnection("127.0.0.1",22,"root","test"))
    }
    private fun await(queue:GenerationQueue,user:User,id:String):GenerationJobView {
        val deadline=System.currentTimeMillis()+8000
        while(System.currentTimeMillis()<deadline) { val job=queue.get(user,id)!!;if(job.state in listOf("completed","partial")) return job;Thread.sleep(30) }
        error("Queue did not complete")
    }
    @Test fun `batch deduplicates skips existing configs and shares one session`() {
        val f=Fixture();val u=f.user("+79991112233");val server=f.server();val ds=(1..3).map { f.devices.createDevice(u.id,"Device $it") }
        f.configs.upsert(ds[0].id,server.id,"existing-private-config")
        val calls=AtomicInteger();val leases=AtomicInteger()
        val generator=object:DeviceConfigGenerator {
            override fun generate(server:Server,user:User,device:Device):GeneratedDeviceConfig {calls.incrementAndGet();return GeneratedDeviceConfig("key-${device.id}","private-${device.id}")}
            override fun<T> withSession(server:Server,action:(DeviceConfigGenerator)->T):T {leases.incrementAndGet();return action(this)}
        }
        GenerationQueue(f.db,f.users,f.devices,f.configs,f.servers,generator,DeviceConfigMutationGuard()).use { queue ->
            val job=queue.enqueue(u,BatchRequest(server.id,requestKey="request-123"))
            assertEquals(job.id,queue.enqueue(u,BatchRequest(server.id,requestKey="request-123")).id)
            val duplicate=queue.enqueue(u,BatchRequest(server.id,requestKey="request-456"))
            assertTrue(duplicate.items.all { it.state=="skipped" })
            queue.start();val result=await(queue,u,job.id)
            assertEquals("completed",result.state);assertEquals(2,calls.get());assertEquals(1,leases.get());assertEquals(3,f.configs.listAll().size)
            assertEquals("existing-private-config",f.configs.findByDeviceAndServer(ds[0].id,server.id)!!.config)
        }
    }
    @Test fun `ordinary user cannot enqueue foreign devices or inspect foreign jobs`() {
        val f=Fixture();val one=f.user("+79991112233");val two=f.user("+79991112234");val server=f.server();val device=f.devices.createDevice(two.id,"Private")
        val generator=object:DeviceConfigGenerator{override fun generate(server:Server,user:User,device:Device)=GeneratedDeviceConfig("x","x")}
        GenerationQueue(f.db,f.users,f.devices,f.configs,f.servers,generator,DeviceConfigMutationGuard()).use { q ->
            assertFailsWith<IllegalArgumentException>{q.enqueue(one,BatchRequest(server.id,listOf(device.id),requestKey="request-123"))}
            assertFailsWith<IllegalArgumentException>{q.enqueue(one,BatchRequest(server.id,allUsers=true,requestKey="request-123"))}
            val job=q.enqueue(two,BatchRequest(server.id,requestKey="request-123"));assertNull(q.get(one,job.id));assertNull(q.retry(one,job.id))
        }
    }
    @Test fun `failed items retry without regenerating successful items and unfinished work resumes`() {
        val f=Fixture();val admin=f.user("+79991112233",true);val owner=f.user("+79991112234");val server=f.server()
        val first=f.devices.createDevice(admin.id,"First");val second=f.devices.createDevice(owner.id,"Second")
        val calls=mutableMapOf<Long,Int>()
        val generator=object:DeviceConfigGenerator{override fun generate(server:Server,user:User,device:Device):GeneratedDeviceConfig {
            calls[device.id]=(calls[device.id] ?: 0)+1
            if(device.id==second.id && calls[device.id]==1) error("secret must not reach UI")
            return GeneratedDeviceConfig("key","owner-${user.id}")
        }}
        val id=GenerationQueue(f.db,f.users,f.devices,f.configs,f.servers,generator,DeviceConfigMutationGuard()).use { q ->
            val job=q.enqueue(admin,BatchRequest(server.id,allUsers=true,requestKey="request-123"))
            f.db.connection().use { it.createStatement().executeUpdate("UPDATE generation_items SET state='running'") }
            job.id
        }
        GenerationQueue(f.db,f.users,f.devices,f.configs,f.servers,generator,DeviceConfigMutationGuard()).use { q ->
            q.start();val partial=await(q,admin,id);assertEquals("partial",partial.state)
            assertFalse(partial.items.any { it.error?.contains("secret")==true })
            q.retry(admin,id);val done=await(q,admin,id);assertEquals("completed",done.state)
            assertEquals(1,calls[first.id]);assertEquals(2,calls[second.id]);assertEquals("owner-${owner.id}",f.configs.findByDeviceAndServer(second.id,server.id)!!.config)
        }
    }
}
