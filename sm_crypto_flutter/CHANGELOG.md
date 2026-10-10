## 0.1.2

* Fix code formatting so the package passes the pub.dev static analysis check
* Require Dart 3.7 or newer
* Write the package description and this changelog in English, as pub.dev requires
* Check formatting in CI

## 0.1.1

* Add a runnable example (`example/example.dart`) covering SM3, SM4 and SM2
* Publish releases from GitHub Actions on tag push (pub.dev automated publishing + OIDC)

## 0.1.0

* Initial release: SM2, SM3 and SM4, API-aligned with sm-crypto-js and interoperable with it
* SM2: elliptic curve public key cryptography
  * Key pair generation (custom random supported)
  * Public key compression / comparison / verification
  * Encryption and decryption (C1C2C3 and C1C3C2, string or byte array in/out)
  * Signature and verification (SM3 hash or raw, strict DER encoding, userId, point pool)
* SM3: 256-bit hash and HMAC-SM3
* SM4: block cipher (ECB / CBC, pkcs#5 / pkcs#7 / none padding)
