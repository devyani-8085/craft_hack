/*
 * Language: Java (JCA/JCE, JSSE, BouncyCastle)
 * Expected artifacts: MD5, SHA-1, SHA-256 | DES/ECB, DESede, AES/ECB, AES/CBC/PKCS5Padding, AES/GCM/NoPadding, RC4 (ARCFOUR)
 *   RSA-1024/2048, DSA, EC secp256r1 (ECDSA/ECDH), DH-1024, SHA1withRSA, SHA256withECDSA
 *   PBKDF2WithHmacSHA1 | SSLContext TLSv1 / TLSv1.3 | java.util.Random (weak) vs SecureRandom | JKS + PKCS11 keystores
 *   Kyber + Dilithium via BouncyCastle PQC provider
 */
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.net.ssl.*;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

public class CryptoLegacy {
    static final String HARDCODED_SECRET = "Sup3rSecretKey!2024";

    void hashes() throws Exception {
        MessageDigest.getInstance("MD5");
        MessageDigest.getInstance("SHA-1");
        MessageDigest.getInstance("SHA-256");
        Mac.getInstance("HmacSHA1");
    }

    void ciphers() throws Exception {
        Cipher.getInstance("DES/ECB/PKCS5Padding");
        Cipher.getInstance("DESede/CBC/PKCS5Padding");
        Cipher.getInstance("AES/ECB/PKCS5Padding");
        Cipher.getInstance("AES/CBC/PKCS5Padding");
        Cipher.getInstance("AES/GCM/NoPadding");
        Cipher.getInstance("ARCFOUR");
        Cipher.getInstance("RSA/ECB/PKCS1Padding");
    }

    void keys() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(1024);                                 // RSA-1024
        rsa.initialize(2048);                                 // RSA-2048
        KeyPairGenerator dsa = KeyPairGenerator.getInstance("DSA");
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new ECGenParameterSpec("secp256r1"));   // P-256
        KeyPairGenerator dh = KeyPairGenerator.getInstance("DH");
        dh.initialize(1024);
        KeyAgreement.getInstance("ECDH");
        Signature.getInstance("SHA1withRSA");
        Signature.getInstance("SHA256withECDSA");
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeyStore.getInstance("JKS");
        KeyStore.getInstance("PKCS11");                       // HSM-backed key store
    }

    void protocols() throws Exception {
        SSLContext.getInstance("TLSv1");                      // TLS 1.0
        SSLContext.getInstance("TLSv1.2");
        SSLContext.getInstance("TLSv1.3");
        new java.util.Random().nextInt();                     // weak RNG
        SecureRandom.getInstanceStrong();
    }

    void pqc() throws Exception {
        Security.addProvider(new BouncyCastlePQCProvider());
        KeyPairGenerator kyber = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        kyber.initialize(KyberParameterSpec.kyber768);        // PQC KEM
        KeyPairGenerator dil = KeyPairGenerator.getInstance("Dilithium", "BCPQC");
        dil.initialize(DilithiumParameterSpec.dilithium3);    // PQC signature
    }
}
