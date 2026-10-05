// Language: Kotlin (JCA/JCE, Android Keystore, Tink)
// Expected artifacts: MD5, SHA-1, SHA-256 | DES, AES/ECB/PKCS5Padding, AES/GCM/NoPadding | RSA-1024 / 2048, EC secp256r1
//   Android Keystore (hardware module) | SSLContext TLSv1 | kotlin.random.Random (weak) vs SecureRandom | Tink AEAD/signature
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.net.ssl.SSLContext
import com.google.crypto.tink.aead.AeadKeyTemplates
import com.google.crypto.tink.signature.SignatureKeyTemplates

const val HARDCODED_SECRET = "kotlin-hardcoded-secret-2024"

fun legacy() {
    MessageDigest.getInstance("MD5")
    MessageDigest.getInstance("SHA-1")
    MessageDigest.getInstance("SHA-256")
    Cipher.getInstance("DES/ECB/PKCS5Padding")
    Cipher.getInstance("AES/ECB/PKCS5Padding")
    Cipher.getInstance("AES/GCM/NoPadding")
    KeyPairGenerator.getInstance("RSA").initialize(1024)
    KeyPairGenerator.getInstance("RSA").initialize(2048)
    KeyPairGenerator.getInstance("EC").initialize(ECGenParameterSpec("secp256r1"))
    KeyStore.getInstance("AndroidKeyStore")
    SSLContext.getInstance("TLSv1")
    kotlin.random.Random.nextInt()
    SecureRandom()
    AeadKeyTemplates.AES256_GCM
    SignatureKeyTemplates.ECDSA_P256
}
