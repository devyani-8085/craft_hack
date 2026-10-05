// Language: C# (.NET System.Security.Cryptography)
// Expected artifacts: MD5, SHA1, SHA256 | DES, TripleDES, RC2, Rijndael/AES CBC/ECB, AesGcm, ChaCha20Poly1305
//   RSA-1024 / 2048, DSA, ECDsa nistP256, ECDiffieHellman nistP384 | Rfc2898DeriveBytes (SHA1) | SslProtocols.Tls / Tls13
//   System.Random (weak) vs RandomNumberGenerator | X509Store (certificate store) | ML-KEM-768 + ML-DSA-65 (.NET PQC)
using System;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;

namespace CryptoFixture
{
    public class CryptoLegacy
    {
        private const string HardcodedKey = "0123456789abcdef0123456789abcdef";

        public void Hashes()
        {
            MD5.Create();
            SHA1.Create();
            SHA256.Create();
            new HMACSHA1();
        }

        public void Ciphers()
        {
            var des = new DESCryptoServiceProvider();
            var tdes = new TripleDESCryptoServiceProvider();
            var rc2 = new RC2CryptoServiceProvider();
            var rij = new RijndaelManaged { Mode = CipherMode.ECB };   // AES-ECB
            var aes = Aes.Create(); aes.Mode = CipherMode.CBC;         // AES-CBC
            var gcm = new AesGcm(new byte[32], 16);                    // AES-256-GCM
            var cc = new ChaCha20Poly1305(new byte[32]);
        }

        public void Keys()
        {
            var rsaWeak = new RSACryptoServiceProvider(1024);          // RSA-1024
            var rsa = RSA.Create(2048);                                // RSA-2048
            var dsa = DSA.Create();
            var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);       // ECDSA P-256
            var dh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP384);
            new Rfc2898DeriveBytes("pw", new byte[8], 1000);           // PBKDF2-SHA1, low iterations
            new PasswordDeriveBytes("pw", new byte[8]);                // PBKDF1
        }

        public void Protocols()
        {
            var opts = new SslClientAuthenticationOptions { EnabledSslProtocols = SslProtocols.Tls | SslProtocols.Tls11 };
            var good = new SslClientAuthenticationOptions { EnabledSslProtocols = SslProtocols.Tls13 };
            new Random().Next();                                       // weak RNG
            RandomNumberGenerator.GetBytes(32);
            var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        }

        public void Pqc()
        {
            var kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);     // ML-KEM-768
            var sig = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65);       // ML-DSA-65
        }
    }
}
