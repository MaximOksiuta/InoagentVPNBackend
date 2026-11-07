package org.example

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.text.Normalizer
import java.util.Locale

/** Name-seeded, self-contained vector postcards. No user content is inserted into SVG. */
class ServerArtwork(private val directory: Path) {
    data class Image(val path: Path, val etag: String)

    @Synchronized fun ensure(name: String): Image {
        val normalized = Normalizer.normalize(name.trim(), Normalizer.Form.NFKC).lowercase(Locale.ROOT)
        val digest = MessageDigest.getInstance("SHA-256").digest(normalized.toByteArray(Charsets.UTF_8))
        val key = digest.joinToString("") { "%02x".format(it) }
        Files.createDirectories(directory)
        val path = directory.resolve("v1-$key.svg")
        if (!Files.exists(path)) {
            val temp = Files.createTempFile(directory, ".art-", ".tmp")
            try {
                Files.writeString(temp, render(normalized, digest))
                Files.move(temp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } finally { Files.deleteIfExists(temp) }
        }
        return Image(path, "\"art-v1-$key\"")
    }

    private fun render(name: String, hash: ByteArray): String {
        fun n(i: Int) = hash[i].toInt() and 255
        val palettes = listOf(
            listOf("#24374b", "#ddbc99", "#88b4bd", "#425f77", "#182737"),
            listOf("#3a2e49", "#e7b491", "#b4a2cf", "#685275", "#292235"),
            listOf("#273f3b", "#efd1a0", "#94b6a1", "#537c70", "#1b302c"),
            listOf("#4a3435", "#e8bd92", "#dca69e", "#926463", "#352529"),
            listOf("#343b50", "#e6cfb1", "#a4b8d7", "#647491", "#242b3c"),
            listOf("#423d2d", "#e7c8a2", "#c2bd8f", "#857e55", "#2f2c22")
        )
        val (sky, sun, light, middle, dark) = palettes[n(0) % palettes.size]
        val motif = when {
            listOf("london", "лондон").any(name::contains) -> "clock"
            listOf("helsinki", "хельсинки", "петербург", "petersburg").any(name::contains) -> "dome"
            listOf("vienna", "вена", "wien", "osaka", "осака").any(name::contains) -> "wheel"
            listOf("paris", "париж").any(name::contains) -> "tower"
            listOf("tokyo", "токио", "kyoto", "киото", "japan", "япон").any(name::contains) -> "gate"
            listOf("amsterdam", "амстердам", "netherland", "нидерланд").any(name::contains) -> "houses"
            listOf("new york", "new-york", "нью-йорк", "frankfurt", "франкфурт", "singapore", "сингапур", "dubai", "дубай").any(name::contains) -> "skyline"
            else -> listOf("mountain", "islands", "observatory", "arches")[n(1) % 4]
        }
        val stars = (0..5).joinToString("") { i -> "<circle cx=\"${12+n(i+5)%136}\" cy=\"${10+n(i+12)%35}\" r=\".7\" opacity=\".45\"/>" }
        val silhouette = when (motif) {
            "clock" -> """<path d="M29 87V42h3v-7h5V23l4-8 4 8v12h5v7h3v45Z" fill="$light"/><path d="M32 43h18v13H32zM35 63h3v15h-3zM44 63h3v15h-3z" fill="$dark"/><circle cx="41" cy="49.5" r="5" fill="$sun"/><path d="M41 46v4l3 1M69 87V66h9v21M116 87V66h9v21M69 69q28 29 56 0M78 80h38" stroke="$light" stroke-width="3"/>"""
            "dome" -> """<path d="M38 87V64h84v23M49 62V48h62v14M65 47q0-23 15-23t15 23M76 23v-6h8v6M57 65v20M69 65v20M81 65v20M93 65v20M105 65v20" fill="none" stroke="$light" stroke-width="4"/><path d="m33 64 47-14 47 14ZM63 47h34" fill="$sun"/><path d="M28 89h104" stroke="$light" stroke-width="4"/>"""
            "wheel" -> """<circle cx="80" cy="49" r="30" stroke="$light" stroke-width="3"/><path d="m64 89 16-40 16 40M80 19v60M50 49h60M59 28l42 42M59 70l42-42" stroke="$light" stroke-width="1.5"/><g fill="$sun"><circle cx="80" cy="19" r="4"/><circle cx="110" cy="49" r="4"/><circle cx="50" cy="49" r="4"/><circle cx="59" cy="28" r="4"/><circle cx="101" cy="28" r="4"/><circle cx="59" cy="70" r="4"/><circle cx="101" cy="70" r="4"/></g>"""
            "tower" -> """<path d="m58 89 14-39 7-27h2l7 27 14 39H90q-10-20-20 0ZM69 56h23M65 67h30M74 43h12M80 23V13" fill="none" stroke="$light" stroke-width="3"/><path d="M35 89V77h10v12M117 89V71h10v18" stroke="$middle" stroke-width="7"/>"""
            "gate" -> """<path d="m24 74 40-46 40 46" fill="$middle"/><path d="m50 44 14-16 14 16-15-4Z" fill="$light"/><path d="M88 89V43M123 89V43M79 39q27 8 54 0M82 51h48M105 44v8" stroke="$sun" stroke-width="5"/><path d="M86 57h39" stroke="$light" stroke-width="3"/>"""
            "houses" -> """<path d="M22 88V51l13-12 13 12v37M51 88V41l13-14 13 14v47M80 88V50l13-11 13 11v38M109 88V39l13-12 13 12v49" fill="$light"/><path d="M31 58h7m-7 10h7m-7 10h7M60 48h7m-7 10h7m-7 10h7M89 57h7m-7 10h7m-7 10h7M118 46h7m-7 10h7m-7 10h7" stroke="$dark" stroke-width="4"/>"""
            "skyline" -> """<path d="M23 88V61h19v27M47 88V42h17v46M70 88V29h20v59M79 29V16M97 88V52h16v36M119 88V37h18v51" fill="$light" stroke="$light" stroke-width="2"/><path d="M28 68h9m-9 8h9M52 49h7m-7 8h7m-7 8h7M75 36h10m-10 8h10m-10 8h10M124 44h8m-8 8h8" stroke="$dark" stroke-width="3"/>"""
            "mountain" -> """<path d="m11 89 41-57 36 57M61 89l43-71 46 71" fill="$middle"/><path d="m88 44 16-26 17 26-17-7ZM37 53l15-21 14 21-14-7Z" fill="$light"/><path d="m16 89 20-18 25 18 31-28 43 28" fill="$dark"/>"""
            "islands" -> """<path d="M18 78q13-33 34-26t24 26M73 77q19-51 43-38t29 38" fill="$middle"/><path d="M13 84h134M24 91h32m12 0h59" stroke="$light" stroke-width="2"/><path d="M105 67V39m-1 4q-12-17-20-4 12-2 20 4m1-1q5-20 19-13-13 5-19 13" stroke="$sun" stroke-width="2"/>"""
            "observatory" -> """<path d="M42 88V61h76v27M45 60q0-33 35-33t35 33M79 28l15-9" fill="none" stroke="$light" stroke-width="4"/><path d="M80 28v32M36 89h88" stroke="$sun" stroke-width="3"/><circle cx="80" cy="71" r="5" fill="$middle"/>"""
            else -> """<path d="M21 90V50h118v40M27 50q53-49 106 0" stroke="$light" stroke-width="5" fill="none"/><path d="M40 90V70a12 12 0 0 1 24 0v20M96 90V70a12 12 0 0 1 24 0v20" stroke="$middle" stroke-width="9"/><path d="M77 39h6v13h-6Z" fill="$sun"/>"""
        }
        return """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 160 120" fill="none"><defs><clipPath id="frame"><rect width="160" height="120" rx="18"/></clipPath></defs><g clip-path="url(#frame)"><path fill="$sky" d="M0 0h160v120H0z"/><g fill="$light">$stars</g><circle cx="${112+n(2)%20}" cy="${22+n(3)%14}" r="${12+n(4)%7}" fill="$sun"/><path d="M0 80Q40 66 80 79T160 74v46H0Z" fill="$dark" opacity=".5"/>$silhouette<path d="M0 94q42-12 80 0t80-4v30H0Z" fill="$dark"/><path d="M13 106h28q9 0 9-8t9-8h42q9 0 9 8t9 8h28" stroke="$sun" stroke-width="2" stroke-linecap="round"/><circle cx="13" cy="106" r="3" fill="$light"/><circle cx="147" cy="106" r="3" fill="$light"/></g></svg>"""
    }

    companion object {
        fun forDatabase(databasePath: String) = ServerArtwork(Path.of(databasePath).toAbsolutePath().parent.resolve("server-art"))
    }
}
