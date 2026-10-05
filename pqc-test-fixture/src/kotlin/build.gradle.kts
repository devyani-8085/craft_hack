plugins { kotlin("jvm") version "1.9.22" }
dependencies {
    implementation("org.bouncycastle:bcprov-jdk15on:1.60")
    implementation("com.google.crypto.tink:tink:1.7.0")
    implementation("io.jsonwebtoken:jjwt:0.9.1")
    implementation("commons-codec:commons-codec:1.10")
}
