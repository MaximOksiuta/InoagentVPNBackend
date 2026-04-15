package org.example

private const val DEFAULT_SQLITE_PATH = "data/app.db"
private val PHONE_REGEX = Regex("^\\+[1-9][0-9]{10,14}$")

data class InitAdminCommand(
    val phone: String,
    val databasePath: String
)

data class InitAdminResult(
    val id: Long,
    val phone: String,
    val nickname: String,
    val isAdmin: Boolean,
    val isApproved: Boolean,
    val isBanned: Boolean
)

fun main(args: Array<String>) {
    val command = InitAdminCli.parse(args)
    val result = InitAdminCli.execute(command)

    println(
        "User ${result.phone} (id=${result.id}, nickname=${result.nickname}) " +
            "updated: approved=${result.isApproved}, admin=${result.isAdmin}, banned=${result.isBanned}"
    )
}

object InitAdminCli {
    fun parse(args: Array<String>): InitAdminCommand {
        if (args.isEmpty() || args.any { it == "--help" || it == "-h" }) {
            error(usage())
        }

        var phone: String? = null
        var databasePath = System.getenv("SQLITE_PATH")?.takeIf { it.isNotBlank() } ?: DEFAULT_SQLITE_PATH

        var index = 0
        while (index < args.size) {
            when (val arg = args[index]) {
                "--phone" -> {
                    phone = args.getOrNull(++index)?.takeIf { it.isNotBlank() }
                        ?: error("Missing value for --phone\n${usage()}")
                }

                "--db", "--database", "--sqlite-path" -> {
                    databasePath = args.getOrNull(++index)?.takeIf { it.isNotBlank() }
                        ?: error("Missing value for $arg\n${usage()}")
                }

                else -> {
                    if (arg.startsWith("--")) {
                        error("Unknown argument: $arg\n${usage()}")
                    }

                    if (phone != null) {
                        error("Phone number specified more than once\n${usage()}")
                    }

                    phone = arg
                }
            }
            index++
        }

        val normalizedPhone = phone?.trim()
            ?.takeIf { it.matches(PHONE_REGEX) }
            ?: error("Phone number must be in international format like +79991234567\n${usage()}")

        return InitAdminCommand(
            phone = normalizedPhone,
            databasePath = databasePath
        )
    }

    fun execute(command: InitAdminCommand): InitAdminResult {
        val databaseFactory = DatabaseFactory(command.databasePath)
        databaseFactory.initialize()
        val userRepository = SqliteUserRepository(databaseFactory)
        val user = userRepository.findByPhone(command.phone)
            ?: error("User with phone ${command.phone} not found in ${command.databasePath}")

        userRepository.updateApproval(user.id, true)
        userRepository.updateIsAdmin(user.id, true)
        userRepository.updateBan(user.id, false)

        val updatedUser = userRepository.findByPhone(command.phone)
            ?: error("User with phone ${command.phone} disappeared after update")

        return InitAdminResult(
            id = updatedUser.id,
            phone = updatedUser.phone,
            nickname = updatedUser.nickname,
            isAdmin = updatedUser.isAdmin,
            isApproved = updatedUser.isApproved,
            isBanned = updatedUser.isBanned
        )
    }

    fun usage(): String {
        return """
            Usage:
              init_admin --phone +79991234567 [--db /path/to/app.db]
              init_admin +79991234567

            Options:
              --phone         User phone in international format
              --db            SQLite database path

            Defaults:
              SQLITE_PATH env var or $DEFAULT_SQLITE_PATH is used when --db is omitted
        """.trimIndent()
    }
}
