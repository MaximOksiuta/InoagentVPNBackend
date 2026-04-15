import org.gradle.jvm.application.tasks.CreateStartScripts

plugins {
    kotlin("jvm") version "1.9.23"
    kotlin("plugin.serialization") version "1.9.23"
    application
}

group = "org.example"
version = "1.0-SNAPSHOT"

application {
    mainClass.set("org.example.ApplicationKt")
}

repositories {
    mavenCentral()
}

dependencies {
    testImplementation("org.jetbrains.kotlin:kotlin-test")
    testImplementation("io.ktor:ktor-server-test-host-jvm:2.3.12")
    testImplementation("io.ktor:ktor-client-content-negotiation-jvm:2.3.12")
    testImplementation("io.ktor:ktor-client-core-jvm:2.3.12")
    implementation("com.hierynomus:sshj:0.38.0")
    implementation("io.ktor:ktor-server-core-jvm:2.3.12")
    implementation("io.ktor:ktor-server-netty-jvm:2.3.12")
    implementation("io.ktor:ktor-server-call-logging-jvm:2.3.12")
    implementation("io.ktor:ktor-server-cors-jvm:2.3.12")
    implementation("io.ktor:ktor-server-content-negotiation-jvm:2.3.12")
    implementation("io.ktor:ktor-serialization-kotlinx-json-jvm:2.3.12")
    implementation("io.ktor:ktor-server-status-pages-jvm:2.3.12")
    implementation("io.ktor:ktor-server-auth-jvm:2.3.12")
    implementation("io.ktor:ktor-server-auth-jwt-jvm:2.3.12")
    implementation("io.github.smiley4:ktor-swagger-ui:3.6.1")
    implementation("com.auth0:java-jwt:4.4.0")
    implementation("ch.qos.logback:logback-classic:1.5.6")
    implementation("org.xerial:sqlite-jdbc:3.46.0.0")
    implementation("org.mindrot:jbcrypt:0.4")
    implementation("com.google.zxing:core:3.5.3")
    implementation("com.google.zxing:javase:3.5.3")
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
}

tasks.test {
    useJUnitPlatform()
}
kotlin {
    jvmToolchain(17)
}

tasks.register<JavaExec>("awgQrFromConfig") {
    group = "application"
    description = "Generate an Amnezia-compatible AWG QR PNG from a WireGuard/AWG config file"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("org.example.AwgQrCliKt")
}

val initAdminStartScripts by tasks.registering(CreateStartScripts::class) {
    applicationName = "init_admin"
    description = "Create a CLI script that approves a user and grants admin access by phone number"
    mainClass.set("org.example.InitAdminCliKt")
    classpath = files(tasks.named("jar"), configurations.runtimeClasspath)
    outputDir = layout.buildDirectory.dir("init-admin-scripts").get().asFile
}

val repairDuplicateIpsStartScripts by tasks.registering(CreateStartScripts::class) {
    applicationName = "repair_duplicate_ips"
    description = "Create a CLI script that fixes duplicate peer IPs and updates stored device configs"
    mainClass.set("org.example.RepairDuplicateIpsCliKt")
    classpath = files(tasks.named("jar"), configurations.runtimeClasspath)
    outputDir = layout.buildDirectory.dir("repair-duplicate-ips-scripts").get().asFile
}

tasks.named("installDist") {
    dependsOn(initAdminStartScripts)
    dependsOn(repairDuplicateIpsStartScripts)
}
