/// sm_crypto_flutter 用法示例：SM3 杂凑、SM4 对称加解密、SM2 公钥加解密与签名验签。
///
/// 运行：`dart run example/example.dart`
library;

import 'package:sm_crypto_flutter/sm_crypto_flutter.dart';

const _msg = 'hello world! 我是 juneandgreen.';
const _sm4Key = '0123456789abcdeffedcba9876543210';
const _sm4Iv = 'fedcba98765432100123456789abcdef';
const _hmacKey = 'daac25c1512fe50f79b0e4526b93f5c0';

void main() {
  sm3Demo();
  sm4Demo();
  sm2Demo();
}

/// SM3：杂凑 + HMAC-SM3（HMAC 的 key 为 hex 串或字节数组）。
void sm3Demo() {
  print('== SM3 ==');
  print('SM3.hash(msg)          = ${SM3.hash(_msg)}');
  print('SM3.hash(msg, key: ..) = ${SM3.hash(_msg, key: _hmacKey)}');
}

/// SM4：ECB / CBC（pkcs#7 填充），默认输出 hex 串。
void sm4Demo() {
  print('== SM4 ==');

  // 默认 ECB + pkcs#7；返回值在 output: 'string'（默认）下是 hex 串
  final ecbCipher = SM4.encrypt(_msg, _sm4Key) as String;
  final ecbPlain = SM4.decrypt(ecbCipher, _sm4Key) as String;
  print('ECB 密文               = $ecbCipher');
  print('ECB 往返一致           = ${ecbPlain == _msg}');

  final cbcCipher =
      SM4.encrypt(_msg, _sm4Key, mode: 'cbc', iv: _sm4Iv) as String;
  final cbcPlain =
      SM4.decrypt(cbcCipher, _sm4Key, mode: 'cbc', iv: _sm4Iv) as String;
  print('CBC 密文               = $cbcCipher');
  print('CBC 往返一致           = ${cbcPlain == _msg}');

  // output: 'array' 时返回字节数组
  final bytes = SM4.decrypt(ecbCipher, _sm4Key, output: 'array') as List<int>;
  print('output: array 字节数   = ${bytes.length}');
}

/// SM2：密钥对、公钥压缩/等价判断、加解密（C1C3C2 / C1C2C3）、签名验签（DER / r‖s）。
void sm2Demo() {
  print('== SM2 ==');

  final keypair = SM2.generateKeyPairHex();
  final publicKey = keypair.publicKey; // 130 位：04 + x(64) + y(64)
  final privateKey = keypair.privateKey; // 64 位

  final compressed = SM2.compressPublicKeyHex(publicKey);
  print('公钥压缩为 66 位       = $compressed');
  print(
    '压缩前后等价           = '
    '${SM2.comparePublicKeyHex(publicKey, compressed)}',
  );
  print(
    '公钥可由私钥推导一致   = '
    '${SM2.getPublicKeyFromPrivateKey(privateKey) == publicKey}',
  );

  // 加密：默认 C1C3C2（mode 0 = C1C2C3）；C1 占前 128 位 hex
  final cipher = SM2.doEncrypt(_msg, publicKey);
  final plain = SM2.doDecrypt(cipher, privateKey) as String;
  print('密文长度（hex 位）     = ${cipher.length}');
  print('解密往返一致           = ${plain == _msg}');

  // 签名：默认 SM3 杂凑 + r‖s（128 位 hex）；der: true 输出 ASN.1 DER
  final signature = SM2.doSignature(_msg, privateKey);
  final derSignature = SM2.doSignature(_msg, privateKey, der: true);
  print('签名（r‖s）长度        = ${signature.length}');
  print(
    '验签 r‖s               = '
    '${SM2.doVerifySignature(_msg, signature, publicKey)}',
  );
  print(
    '验签 DER               = '
    '${SM2.doVerifySignature(_msg, derSignature, publicKey, der: true)}',
  );
  print(
    '篡改消息后验签         = '
    '${SM2.doVerifySignature('$_msg!', signature, publicKey)}',
  );
}
