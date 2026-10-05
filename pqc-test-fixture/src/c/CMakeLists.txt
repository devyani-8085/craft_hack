# Expected artifact type: library (SCA / build manifest) — OpenSSL, liboqs, wolfSSL linked
cmake_minimum_required(VERSION 3.20)
project(c_crypto_fixture C CXX)
find_package(OpenSSL 1.0.2 REQUIRED)
find_package(liboqs REQUIRED)
find_package(wolfssl REQUIRED)
find_package(cryptopp REQUIRED)
find_package(Botan REQUIRED)
target_link_libraries(app OpenSSL::SSL OpenSSL::Crypto OQS::oqs wolfssl cryptopp Botan::Botan)
