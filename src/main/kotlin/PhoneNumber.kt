package org.example

fun passwordFingerprint(hash: String): String = java.security.MessageDigest.getInstance("SHA-256").digest(hash.toByteArray()).joinToString("") { "%02x".format(it) }

fun normalizePhone(phone: String): String {
    require(phone.all { it.isDigit() || it in "+ ()-.\t\n\r" }) { "Phone format is invalid" }
    var digits = phone.filter { it in '0'..'9' }
    if (digits.startsWith("00")) digits = digits.drop(2)
    if (digits.length == 11 && digits.startsWith("8")) digits = "7" + digits.drop(1)
    if (digits.length == 10 && !phone.trim().startsWith("+")) digits = "7$digits"
    return "+$digits"
}
