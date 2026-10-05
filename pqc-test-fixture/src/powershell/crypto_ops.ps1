# Language: PowerShell (.NET crypto, certificate store, ConvertTo-SecureString)
# Expected artifacts: MD5 + SHA1 CryptoServiceProviders | DES / TripleDES / AES-ECB | RSA-1024 | New-SelfSignedCertificate RSA SHA1
#   [Net.SecurityProtocolType]::Tls / Ssl3 | Cert:\LocalMachine\My (certificate store) | Get-Random (weak)
$HardcodedKey = "0123456789abcdef0123456789abcdef"
[System.Security.Cryptography.MD5]::Create()
[System.Security.Cryptography.SHA1]::Create()
[System.Security.Cryptography.DES]::Create()
[System.Security.Cryptography.TripleDES]::Create()
$aes = [System.Security.Cryptography.Aes]::Create(); $aes.Mode = "ECB"
New-Object System.Security.Cryptography.RSACryptoServiceProvider(1024)
New-SelfSignedCertificate -DnsName "legacy.local" -KeyAlgorithm RSA -KeyLength 1024 -HashAlgorithm SHA1 -CertStoreLocation Cert:\LocalMachine\My
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Ssl3
Get-Random
