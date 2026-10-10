import 'dart:convert';
import 'dart:io';

import 'package:sm_crypto_flutter/sm_crypto_flutter.dart';
import 'package:test/test.dart';

/// 与 sm-crypto-js（参考实现）的互操作向量。
///
/// 向量由 `node tool/gen_vectors.cjs` 生成（sm-crypto-js 0.5.7），
/// 断言 Dart 实现能解密 js 密文、验证 js 签名、复现 js 的杂凑输出。
void main() {
  final vectors = jsonDecode(
    File('tool/interop_vectors.json').readAsStringSync(),
  ) as Map<String, dynamic>;

  final privateKey = (vectors['keypair'] as Map)['privateKey'] as String;
  final publicKey = (vectors['keypair'] as Map)['publicKey'] as String;
  final compressed = (vectors['keypair'] as Map)['compressed'] as String;
  final msg = vectors['msg'] as String;
  final bytesMsg = (vectors['bytesMsg'] as List).cast<int>();

  group('sm2 keypair', () {
    test('deterministic keypair from custom random matches js', () {
      final kp = SM2.generateKeyPairHex('123123123123123');
      expect(kp.privateKey, privateKey);
      expect(kp.publicKey, publicKey);
      expect(SM2.compressPublicKeyHex(kp.publicKey), compressed);
      expect(SM2.getPublicKeyFromPrivateKey(privateKey), publicKey);
    });
  });

  group('js encrypt -> dart decrypt', () {
    test('C1C3C2 / C1C2C3', () {
      expect(
          SM2.doDecrypt(vectors['cipherC1C3C2'] as String, privateKey, 1), msg);
      expect(
          SM2.doDecrypt(vectors['cipherC1C2C3'] as String, privateKey, 0), msg);
    });

    test('compressed public key cipher', () {
      expect(
          SM2.doDecrypt(
              vectors['cipherCompressedKey'] as String, privateKey, 1),
          msg);
    });

    test('byte array cipher', () {
      expect(
          SM2.doDecrypt(
              vectors['cipherBytes'] as String, privateKey, 1, 'array'),
          bytesMsg);
    });

    test('dart encrypt -> dart decrypt round trip', () {
      final ct = SM2.doEncrypt(msg, publicKey, 1);
      expect(SM2.doDecrypt(ct, privateKey, 1), msg);
      final ct0 = SM2.doEncrypt(msg, compressed, 0);
      expect(SM2.doDecrypt(ct0, privateKey, 0), msg);
    });
  });

  group('js sign -> dart verify', () {
    final signatures =
        (vectors['signatures'] as List).cast<Map<String, dynamic>>();
    for (var i = 0; i < signatures.length; i++) {
      final entry = signatures[i];
      final opts = entry['opts'] as Map<String, dynamic>;
      final sig = entry['sig'] as String;
      final hash = (opts['hash'] as bool?) ?? true;
      final der = (opts['der'] as bool?) ?? false;
      final userId = opts['userId'] as String?;

      test('signature #$i (hash:$hash der:$der userId:$userId)', () {
        expect(
            SM2.doVerifySignature(msg, sig, publicKey,
                hash: hash, der: der, userId: userId),
            true);
        // 篡改消息必须验签失败
        expect(
            SM2.doVerifySignature('$msg!', sig, publicKey,
                hash: hash, der: der, userId: userId),
            false);
      });
    }
  });

  group('sm3 vectors from js', () {
    final sm3Vectors = (vectors['sm3Vectors'] as List).cast<Map<String, dynamic>>();
    for (var i = 0; i < sm3Vectors.length; i++) {
      final v = sm3Vectors[i];
      test('sm3 vector #$i', () {
        final input = v.containsKey('bytes')
            ? (v['bytes'] as List).cast<int>()
            : v['input'] as String;
        expect(SM3.hash(input), v['hash']);
      });
    }

    final hmacVectors =
        (vectors['hmacVectors'] as List).cast<Map<String, dynamic>>();
    for (var i = 0; i < hmacVectors.length; i++) {
      final v = hmacVectors[i];
      test('hmac vector #$i', () {
        final input = v.containsKey('bytes')
            ? (v['bytes'] as List).cast<int>()
            : v['input'] as String;
        expect(SM3.hash(input, key: v['key']), v['hash']);
      });
    }
  });

  group('sm4 vectors from js', () {
    final sm4Vectors =
        (vectors['sm4Vectors'] as List).cast<Map<String, dynamic>>();
    for (var i = 0; i < sm4Vectors.length; i++) {
      final v = sm4Vectors[i];
      test('sm4 vector #$i', () {
        final msgOrBytes =
            v.containsKey('bytes') ? (v['bytes'] as List).cast<int>() : v['msg'];
        final ct = v['ct'] as String;

        // dart 加密结果必须与 js 一致（确定性输入）
        expect(
            SM4.encrypt(msgOrBytes, v['key'],
                mode: v['mode'] as String?, iv: v['iv']),
            ct);

        // js 密文必须能被 dart 解密（字节输入按 array 输出对比）
        final decrypted = msgOrBytes is List
            ? SM4.decrypt(ct, v['key'],
                mode: v['mode'] as String?, iv: v['iv'], output: 'array')
            : SM4.decrypt(ct, v['key'],
                mode: v['mode'] as String?, iv: v['iv']);
        expect(decrypted, msgOrBytes);
      });
    }
  });
}
