// Language: Swift (CryptoKit, CommonCrypto, Security.framework)
// Expected artifacts: Insecure.MD5, Insecure.SHA1, SHA256 | CCCrypt kCCAlgorithmDES / kCCAlgorithm3DES / AES ECB | AES.GCM, ChaChaPoly
//   P256 signing, Curve25519 key agreement + signing | SecKeyCreateRandomKey RSA 1024 + secure enclave (hardware) | arc4random (ok) vs rand
//   ML-KEM-768 + ML-DSA-65 (CryptoKit iOS 26 PQC)
import CryptoKit
import CommonCrypto
import Security

let hardcodedKey = "0123456789abcdef0123456789abcdef"

func hashes(_ d: Data) {
    _ = Insecure.MD5.hash(data: d)
    _ = Insecure.SHA1.hash(data: d)
    _ = SHA256.hash(data: d)
    _ = SHA512.hash(data: d)
}

func ciphers(_ key: SymmetricKey) throws {
    _ = try AES.GCM.seal(Data(), using: key)                  // AES-GCM
    _ = try ChaChaPoly.seal(Data(), using: key)
    var out = [UInt8](repeating: 0, count: 64); var n = 0
    CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmDES), CCOptions(kCCOptionECBMode), hardcodedKey, 8, nil, [UInt8](), 0, &out, 64, &n)
    CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithm3DES), 0, hardcodedKey, 24, nil, [UInt8](), 0, &out, 64, &n)
    CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode), hardcodedKey, 16, nil, [UInt8](), 0, &out, 64, &n)
}

func asymmetric() {
    _ = P256.Signing.PrivateKey()                             // ECDSA P-256
    _ = P256.KeyAgreement.PrivateKey()
    _ = Curve25519.KeyAgreement.PrivateKey()                  // X25519
    _ = Curve25519.Signing.PrivateKey()                       // Ed25519
    let rsa: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits as String: 1024]
    SecKeyCreateRandomKey(rsa as CFDictionary, nil)           // RSA-1024
    let se: [String: Any] = [kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave]
    SecKeyCreateRandomKey(se as CFDictionary, nil)            // Secure Enclave (hardware module)
}

func pqc() throws {
    _ = try MLKEM768.PrivateKey()                             // ML-KEM-768
    _ = try MLDSA65.PrivateKey()                              // ML-DSA-65
}
