// Language: Scala (JCA + BouncyCastle)
// Expected artifacts: MD5, SHA-1 | DES, AES/ECB | RSA-1024 | HmacSHA1 | SSLContext TLSv1.1 | scala.util.Random (weak)
import java.security.{KeyPairGenerator, MessageDigest}
import javax.crypto.{Cipher, Mac}
import javax.net.ssl.SSLContext

object CryptoLegacy {
  val HardcodedKey = "scala-hardcoded-key-0123456789"
  def run(): Unit = {
    MessageDigest.getInstance("MD5")
    MessageDigest.getInstance("SHA-1")
    Cipher.getInstance("DES/ECB/PKCS5Padding")
    Cipher.getInstance("AES/ECB/PKCS5Padding")
    Mac.getInstance("HmacSHA1")
    KeyPairGenerator.getInstance("RSA").initialize(1024)
    SSLContext.getInstance("TLSv1.1")
    scala.util.Random.nextInt()
  }
}
