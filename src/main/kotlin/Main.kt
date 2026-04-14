package org.example

fun main() {
    val scripts = AwgServerScripts(AwgConnection(host = "77.110.110.141", username = "root", password = "0iQ5to9sxYZV"))
    print(scripts.addUser("Maxonka"))
}