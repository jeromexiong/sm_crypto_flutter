# sm_crypto_flutter

[![pub package](https://img.shields.io/pub/v/sm_crypto_flutter.svg)](https://pub.dev/packages/sm_crypto_flutter)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> 仓库：https://github.com/jeromexiong/sm_crypto_flutter ｜ pub.dev：[`sm_crypto_flutter`](https://pub.dev/packages/sm_crypto_flutter)

国密算法 SM2、SM3、SM4 的纯 Dart 实现。API 与 [sm-crypto](https://github.com/juneandgreen/sm-crypto)（js）对齐，输出与 js 版**可互操作**（密文、签名、杂凑互通，双向实测通过）。

- 纯 Dart，零运行时依赖，可用于 Flutter / Dart VM
- SM2：密钥对生成、公钥压缩/比较/验证、加解密（C1C2C3 / C1C3C2）、签名验签（SM3 杂凑 / 纯签名、DER、userId）
- SM3：杂凑 + HMAC-SM3
- SM4：ECB / CBC、pkcs#5 / pkcs#7 / none 填充

## 安装

```yaml
dependencies:
  sm_crypto_flutter: ^0.1.0
```

## sm2

### 获取密钥对

```dart
import 'package:sm_crypto_flutter/sm_crypto_flutter.dart';

final keypair = SM2.generateKeyPairHex();
final publicKey = keypair.publicKey;   // 公钥（130 位，04 + x + y）
final privateKey = keypair.privateKey; // 私钥（64 位）

// 默认生成公钥 130 位太长，可以压缩公钥到 66 位
final compressedPublicKey = SM2.compressPublicKeyHex(publicKey); // 与 publicKey 等价
SM2.comparePublicKeyHex(publicKey, compressedPublicKey); // 判断公钥是否等价

// 自定义随机数（十进制字符串或 BigInt）
// 注意：开发者使用自定义随机数，需要自行确保传入的随机数符合密码学安全
final keypair2 = SM2.generateKeyPairHex('123123123123123');

final verifyResult = SM2.verifyPublicKey(publicKey); // 验证公钥
```

### 加密解密

```dart
const cipherMode = 1; // 1 - C1C3C2，0 - C1C2C3，默认为 1

final encryptData = SM2.doEncrypt('hello', publicKey, cipherMode);
final decryptData = SM2.doDecrypt(encryptData, privateKey, cipherMode); // 解密结果

// 输入数组
final encryptData2 = SM2.doEncrypt([0x61, 0x62], publicKey, cipherMode);
final decryptData2 = SM2.doDecrypt(encryptData2, privateKey, cipherMode, 'array'); // 输出数组
```

> ps：解密失败（密文非法或校验不过）返回 `''` / `[]`，与 js 版行为一致。
> ps：密文会在解密时自动补充 `04`，如遇到其他工具补充的 `04` 需手动去除再传入。

### 签名验签

```dart
// 纯签名（不做 sm3 杂凑）
final sig1 = SM2.doSignature(msg, privateKey, hash: false);
SM2.doVerifySignature(msg, sig1, publicKey, hash: false); // 验签结果

// 纯签名 + 生成椭圆曲线点 + der 编解码
final sig2 = SM2.doSignature(msg, privateKey, der: true);
SM2.doVerifySignature(msg, sig2, publicKey, der: true);

// sm3 杂凑（默认行为）
final sig3 = SM2.doSignature(msg, privateKey);
SM2.doVerifySignature(msg, sig3, publicKey);

// sm3 杂凑（不做公钥推导，速度更快）
final sig4 = SM2.doSignature(msg, privateKey, publicKey: publicKey);

// sm3 杂凑 + userId（长度小于 8192，默认 '1234567812345678'）
final sig5 = SM2.doSignature(msg, privateKey, publicKey: publicKey, userId: 'testUserId');
SM2.doVerifySignature(msg, sig5, publicKey, userId: 'testUserId');

// 传入事先已生成好的椭圆曲线点，可加快签名速度
final sig6 = SM2.doSignature(msg, privateKey,
    pointPool: [SM2.getPoint(), SM2.getPoint(), SM2.getPoint()]);
```

> ps：理论上来说，只做纯签名是最快的。
> ps：`hash` 参数默认为 `true`，即默认会做 sm3 杂凑。如需纯签名（不做杂凑），请显式传入 `hash: false`。

### 其他工具

```dart
SM2.getPoint(); // 获取一个椭圆曲线点，可在签名时传入
SM2.getPublicKeyFromPrivateKey(privateKey); // 根据私钥获取公钥
```

## sm3

```dart
final hashData = SM3.hash('abc'); // 杂凑，返回 hex 串

// hmac（key 为 hex 串或字节数组）
final hmacData = SM3.hash('abc', key: 'daac25c1512fe50f...');
```

## sm4

### 加密

```dart
const msg = 'hello world! 我是 juneandgreen.'; // 可以为 utf8 串或字节数组
const key = '0123456789abcdeffedcba9876543210'; // hex 串或字节数组，要求 128 比特

SM4.encrypt(msg, key); // 默认输出 hex 串，默认 pkcs#7 填充（传 pkcs#5 也走 pkcs#7）
SM4.encrypt(msg, key, padding: 'none'); // 不使用 padding
SM4.encrypt(msg, key, padding: 'none', output: 'array'); // 输出字节数组
SM4.encrypt(msg, key, mode: 'cbc', iv: 'fedcba98765432100123456789abcdef'); // cbc 模式
```

### 解密

```dart
const encryptData = '0e395deb10f6e8a17e17823e1fd9bd98...'; // hex 串或字节数组

SM4.decrypt(encryptData, key); // 默认输出 utf8 串
SM4.decrypt(encryptData, key, padding: 'none', output: 'array');
SM4.decrypt(encryptData, key, mode: 'cbc', iv: 'fedcba98765432100123456789abcdef');
```

## 与 sm-crypto-js 的 API 对照

| sm-crypto-js | sm_crypto_flutter (Dart) |
|---|---|
| `sm2.generateKeyPairHex(a?)` | `SM2.generateKeyPairHex([random])` |
| `sm2.compressPublicKeyHex(pk)` | `SM2.compressPublicKeyHex(pk)` |
| `sm2.comparePublicKeyHex(a, b)` | `SM2.comparePublicKeyHex(a, b)` |
| `sm2.verifyPublicKey(pk)` | `SM2.verifyPublicKey(pk)` |
| `sm2.doEncrypt(msg, pk, mode)` | `SM2.doEncrypt(msg, pk, [mode])` |
| `sm2.doDecrypt(ct, sk, mode, {output})` | `SM2.doDecrypt(ct, sk, [mode], [output])` |
| `sm2.doSignature(msg, sk, opts)` | `SM2.doSignature(msg, sk, {hash, der, publicKey, userId, pointPool})` |
| `sm2.doVerifySignature(msg, sig, pk, opts)` | `SM2.doVerifySignature(msg, sig, pk, {hash, der, userId})` |
| `sm2.getPublicKeyFromPrivateKey(sk)` | `SM2.getPublicKeyFromPrivateKey(sk)` |
| `sm2.getPoint()` | `SM2.getPoint()` |
| `sm3(msg, {key})` | `SM3.hash(msg, {key})` |
| `sm4.encrypt(msg, key, opts)` | `SM4.encrypt(msg, key, {padding, mode, iv, output})` |
| `sm4.decrypt(ct, key, opts)` | `SM4.decrypt(ct, key, {padding, mode, iv, output})` |

已知偏差（详见 `docs/plans/2026-10-10-sm-crypto-dart-design.md`）：

- `generateKeyPairHex(256, SecureRandom)` 不支持，随机源固定为 `Random.secure()`；自定义随机数收敛为十进制字符串 / `BigInt`。
- `doDecrypt` 的 `output` 为位置参数（js 为具名 options）；其余 options 均为 Dart 命名参数。
- 异常类型为 `ArgumentError` / `FormatException`（js 抛 `Error`），消息文本一致。
- 非法 utf8 解码抛 `FormatException`（js 抛 `Error('Malformed UTF-8 data')`）。

## 开发与验证

```bash
dart pub get
dart analyze
dart test                              # 75 项测试（含 js 向量互操作）
dart pub publish --dry-run             # 发布前自检（文件清单 / pubspec / LICENSE）
```

双向互操作验证需要额外 clone 参考实现（不入库），放在本包同级目录：

```bash
git clone https://github.com/juneandgreen/sm-crypto sm-crypto-js   # 在仓库根目录执行
cd sm-crypto-js && npm install && cd ../sm_crypto_flutter

node tool/gen_vectors.cjs              # 用 sm-crypto-js 重新生成互操作向量
dart run tool/gen_dart_vectors.dart \
  && node tool/check_interop.cjs       # dart -> js 方向互操作验证
```

互操作测试向量由 `sm-crypto-js` 0.5.7 生成（`tool/interop_vectors.json`），
js 测试用例（`sm-crypto-js/test/*.test.js`）已全部移植为 Dart 测试。

发布流程（首版手动 + tag 触发自动发布）见仓库的 [`docs/publishing.md`](../docs/publishing.md)。

## 协议

MIT
