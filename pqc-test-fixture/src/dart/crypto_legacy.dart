// Language: Dart / Flutter (package:crypto, pointycastle, encrypt)
// Expected artifacts: md5, sha1, sha256 | AES-ECB, AES-CBC (encrypt pkg) | RSA-1024 (pointycastle) | SecurityContext TLS | Random() (weak) vs Random.secure()
import 'dart:io';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';
import 'package:pointycastle/export.dart';

const hardcodedKey = '0123456789abcdef0123456789abcdef';

void legacy() {
  md5.convert([1]);
  sha1.convert([1]);
  sha256.convert([1]);
  AES(Key.fromUtf8(hardcodedKey), mode: AESMode.ecb);
  AES(Key.fromUtf8(hardcodedKey), mode: AESMode.cbc);
  RSAKeyGenerator()..init(ParametersWithRandom(RSAKeyGeneratorParameters(BigInt.from(65537), 1024, 12), SecureRandom('Fortuna')));
  SecurityContext.defaultContext.setTrustedCertificates('ca.pem');
  Random();
  Random.secure();
}
