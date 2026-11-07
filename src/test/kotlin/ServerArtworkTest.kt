package org.example

import io.ktor.server.testing.testApplication
import io.ktor.server.config.MapApplicationConfig
import io.ktor.client.request.*
import io.ktor.client.statement.bodyAsText
import io.ktor.http.*
import java.nio.file.Files
import java.util.concurrent.Executors
import javax.xml.parsers.DocumentBuilderFactory
import kotlin.test.*

class ServerArtworkTest {
    @Test fun `art is stable saved once and distinct for different names`() {
        val dir=Files.createTempDirectory("server-postcards")
        val art=ServerArtwork(dir)
        val london=art.ensure("London")
        assertEquals(london,art.ensure("  LONDON  "))
        val original=Files.readString(london.path)
        val time=Files.getLastModifiedTime(london.path)
        assertEquals(original,Files.readString(ServerArtwork(dir).ensure("London").path))
        assertEquals(time,Files.getLastModifiedTime(london.path))
        assertNotEquals(original,Files.readString(art.ensure("Helsinki").path))
        assertNotEquals(original,Files.readString(art.ensure("London 2").path))
        val threads=Executors.newFixedThreadPool(4)
        try { assertEquals(1,(1..12).map { threads.submit<ServerArtwork.Image> { art.ensure("Vienna") } }.map { it.get().path }.distinct().size) }
        finally { threads.shutdownNow() }
        assertTrue(Files.list(dir).use { files -> files.allMatch { it.fileName.toString().endsWith(".svg") } })
    }

    @Test fun `hostile names cannot become paths or active SVG content`() {
        val dir=Files.createTempDirectory("safe-art")
        val art=ServerArtwork(dir)
        for(name in listOf("../../escape", "<script>alert('x')</script>", "\"><image href=\"https://evil.test/x", "Лондон 🇬🇧", "", "x".repeat(2000))) {
            val image=art.ensure(name)
            assertEquals(dir,image.path.parent)
            assertTrue(image.path.fileName.toString().matches(Regex("v1-[a-f0-9]{64}\\.svg")))
            val svg=Files.readString(image.path)
            assertFalse(svg.contains("script",true));assertFalse(svg.contains("href=",true));assertFalse(svg.contains("<!"))
            val factory=DocumentBuilderFactory.newInstance();factory.isNamespaceAware=true
            val doc=factory.newDocumentBuilder().parse(image.path.toFile())
            assertEquals("svg",doc.documentElement.localName)
            assertTrue(svg.length<8000)
        }
    }

    @Test fun `image endpoint serves saved art with caching and changes after rename`() = testApplication {
        environment { config=MapApplicationConfig() }
        val config=AppConfig(Files.createTempDirectory("art-api").resolve("db").toString(),JwtConfig("secret","issuer","audience","realm",60000),"bot-secret")
        val db=DatabaseFactory(config.databasePath);db.initialize()
        val users=SqliteUserRepository(db);val devices=SqliteDeviceRepository(db);val configs=SqliteDeviceServerRepository(db);val servers=SqliteServerRepository(db)
        val connection=AwgConnection("not-in-svg.example",22,"root","SECRET_PASSWORD")
        val server=servers.createServer("London","UK",connection)
        application { module(users,devices,configs,servers,JwtService(config.jwt),config) }
        val url="/api/server-art/${server.id}"
        val first=client.get(url)
        assertEquals(HttpStatusCode.OK,first.status)
        assertEquals("image/svg+xml",first.headers[HttpHeaders.ContentType]?.substringBefore(';'))
        assertFalse(first.bodyAsText().contains("SECRET_PASSWORD"));assertFalse(first.bodyAsText().contains("not-in-svg"))
        val etag=first.headers[HttpHeaders.ETag]!!
        assertEquals(HttpStatusCode.NotModified,client.get(url){header(HttpHeaders.IfNoneMatch,etag)}.status)
        assertEquals(Files.readString(ServerArtwork.forDatabase(config.databasePath).ensure("London").path),first.bodyAsText())
        servers.updateServer(server.id,"Tokyo","Japan",connection)
        val next=client.get(url){header(HttpHeaders.IfNoneMatch,etag)}
        assertEquals(HttpStatusCode.OK,next.status);assertNotEquals(etag,next.headers[HttpHeaders.ETag]);assertNotEquals(first.bodyAsText(),next.bodyAsText())
        assertEquals(HttpStatusCode.NotFound,client.get("/api/server-art/9999").status)
        assertEquals(HttpStatusCode.NotFound,client.get("/api/server-art/nope").status)
    }
}
