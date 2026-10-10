// 生成 Dart 侧的签名/密文，供 tool/check_interop.cjs 用 sm-crypto-js 反向验证。
//
// 用法：dart run tool/gen_dart_vectors.dart
import 'dart:convert';
import 'dart:io';

import 'package:sm_crypto/sm_crypto.dart';

void main() {
  final jsVectors = jsonDecode(
    File('tool/interop_vectors.json').readAsStringSync(),
  ) as Map<String, dynamic>;
  final keypair = jsVectors['keypair'] as Map;
  final privateKey = keypair['privateKey'] as String;
  final publicKey = keypair['publicKey'] as String;
  const msg = 'absasdagfadgadsfdfdsf';

  final out = {
    'msg': msg,
    'publicKey': publicKey,
    'privateKey': privateKey,
    'cipherC1C3C2': SM2.doEncrypt(msg, publicKey, 1),
    'cipherC1C2C3': SM2.doEncrypt(msg, publicKey, 0),
    'signatures': [
      {'hash': true, 'der': false, 'sig': SM2.doSignature(msg, privateKey)},
      {
        'hash': false,
        'der': false,
        'sig': SM2.doSignature(msg, privateKey, hash: false),
      },
      {
        'hash': true,
        'der': true,
        'sig': SM2.doSignature(msg, privateKey, der: true),
      },
      {
        'hash': true,
        'der': false,
        'userId': 'testUserId',
        'sig': SM2.doSignature(msg, privateKey,
            publicKey: publicKey, userId: 'testUserId'),
      },
    ],
  };

  File('tool/dart_vectors.json').writeAsStringSync(jsonEncode(out));
  stdout.writeln('written: tool/dart_vectors.json');
}
