import 'dart:typed_data';

import 'package:sm_crypto_flutter/sm_crypto_flutter.dart';
import 'package:test/test.dart';

/// 移植自 sm-crypto-js/test/sm2.test.js 的行为用例。
void main() {
  const cipherMode = 1; // 1 - C1C3C2，0 - C1C2C3
  const msgString = 'absasdagfadgadsfdfdsf';

  late KeyPair keypair;
  late String unCompressedPublicKey;
  late String compressedPublicKey;
  late String privateKey;

  setUpAll(() {
    keypair = SM2.generateKeyPairHex();
    unCompressedPublicKey = keypair.publicKey;
    privateKey = keypair.privateKey;
    compressedPublicKey = SM2.compressPublicKeyHex(unCompressedPublicKey);
  });

  group('sm2: generate keypair', () {
    test('shapes and validity', () {
      expect(unCompressedPublicKey.length, 130);
      expect(privateKey.length, 64);
      expect(compressedPublicKey.length, 66);
      expect(SM2.verifyPublicKey(unCompressedPublicKey), true);
      expect(SM2.verifyPublicKey(compressedPublicKey), true);
      expect(
          SM2.comparePublicKeyHex(unCompressedPublicKey, compressedPublicKey),
          true);
      expect(SM2.comparePublicKeyHex(unCompressedPublicKey, unCompressedPublicKey),
          true);
      expect(SM2.comparePublicKeyHex(compressedPublicKey, compressedPublicKey),
          true);
    });

    test('custom random number', () {
      final keypair2 = SM2.generateKeyPairHex('123123123123123');
      expect(keypair2.publicKey.length, 130);
      expect(keypair2.privateKey.length, 64);
      final compressed2 = SM2.compressPublicKeyHex(keypair2.publicKey);
      expect(compressed2.length, 66);
      expect(SM2.verifyPublicKey(keypair2.publicKey), true);
      expect(SM2.verifyPublicKey(compressed2), true);
      expect(SM2.comparePublicKeyHex(keypair2.publicKey, compressed2), true);
    });
  });

  group('sm2: encrypt and decrypt data', () {
    for (final pk in ['uncompressed', 'compressed']) {
      test('with $pk public key', () {
        final publicKey =
            pk == 'uncompressed' ? unCompressedPublicKey : compressedPublicKey;

        var encryptData = SM2.doEncrypt(msgString, publicKey, cipherMode);
        var decryptData = SM2.doDecrypt(encryptData, privateKey, cipherMode);
        expect(decryptData, msgString);

        for (var i = 0; i < 25; i++) {
          encryptData = SM2.doEncrypt(msgString, publicKey, cipherMode);
          decryptData = SM2.doDecrypt(encryptData, privateKey, cipherMode);
          expect(decryptData, msgString);
        }
      });
    }

    test('both cipher modes', () {
      for (final mode in [0, 1]) {
        final encryptData = SM2.doEncrypt(msgString, unCompressedPublicKey, mode);
        expect(SM2.doDecrypt(encryptData, privateKey, mode), msgString);
      }
    });

    test('byte array input', () {
      final encryptData = SM2.doEncrypt(
          [0x61, 0x62, 0x73, 0x61, 0x73, 0x64, 0x61, 0x67, 0x66, 0x61, 0x64,
            0x67, 0x61, 0x64, 0x73, 0x66, 0x64, 0x66, 0x64, 0x73, 0x66],
          unCompressedPublicKey,
          cipherMode);
      expect(SM2.doDecrypt(encryptData, privateKey, cipherMode), msgString);
    });

    test('Uint8List input equals List<int> input', () {
      final bytes = [0x61, 0x62, 0x73, 0x61, 0x73, 0x64, 0x61, 0x67, 0x66,
        0x61, 0x64, 0x67, 0x61, 0x64, 0x73, 0x66, 0x64, 0x66, 0x64, 0x73, 0x66];
      final encryptData = SM2.doEncrypt(
          Uint8List.fromList(bytes), unCompressedPublicKey, cipherMode);
      expect(SM2.doDecrypt(encryptData, privateKey, cipherMode, 'array'), bytes);
    });
  });

  group('sm2: sign and verify', () {
    test('hash default + explicit hash:true', () {
      for (var i = 0; i < 25; i++) {
        final sig = SM2.doSignature(msgString, privateKey);
        expect(SM2.doVerifySignature(msgString, sig, unCompressedPublicKey), true);
      }
      final sig = SM2.doSignature(msgString, privateKey);
      expect(
          SM2.doVerifySignature(msgString, sig, unCompressedPublicKey, hash: true),
          true);
    });

    test('pure signature (hash:false)', () {
      final sig = SM2.doSignature(msgString, privateKey, hash: false);
      expect(
          SM2.doVerifySignature(msgString, sig, unCompressedPublicKey,
              hash: false),
          true);
      expect(SM2.doVerifySignature(msgString, sig, unCompressedPublicKey), false);
    });

    test('der encoding', () {
      for (final hash in [true, false]) {
        final sig =
            SM2.doSignature(msgString, privateKey, der: true, hash: hash);
        expect(
            SM2.doVerifySignature(msgString, sig, unCompressedPublicKey,
                der: true, hash: hash),
            true);
      }
    });

    test('skip public key derivation', () {
      final sig = SM2.doSignature(msgString, privateKey,
          publicKey: unCompressedPublicKey);
      expect(SM2.doVerifySignature(msgString, sig, unCompressedPublicKey), true);
    });

    test('userId semantics', () {
      final sig = SM2.doSignature(msgString, privateKey,
          publicKey: unCompressedPublicKey, userId: 'testUserId');
      expect(
          SM2.doVerifySignature(msgString, sig, unCompressedPublicKey,
              userId: 'testUserId'),
          true);
      expect(
          SM2.doVerifySignature(msgString, sig, unCompressedPublicKey,
              userId: 'wrongTestUserId'),
          false);

      // 空 userId
      final sigEmpty = SM2.doSignature(msgString, privateKey,
          publicKey: unCompressedPublicKey, userId: '');
      expect(
          SM2.doVerifySignature(msgString, sigEmpty, unCompressedPublicKey,
              userId: ''),
          true);
      expect(SM2.doVerifySignature(msgString, sigEmpty, unCompressedPublicKey),
          false);

      // 默认 userId 与显式 1234567812345678 等价
      final sigDefault = SM2.doSignature(msgString, privateKey,
          publicKey: unCompressedPublicKey);
      expect(SM2.doVerifySignature(msgString, sigDefault, unCompressedPublicKey),
          true);
      expect(
          SM2.doVerifySignature(msgString, sigDefault, unCompressedPublicKey,
              userId: ''),
          false);
      expect(
          SM2.doVerifySignature(msgString, sigDefault, unCompressedPublicKey,
              userId: '1234567812345678'),
          true);
    });

    test('verify with compressed public key', () {
      final sig = SM2.doSignature(msgString, privateKey);
      expect(SM2.doVerifySignature(msgString, sig, compressedPublicKey), true);
    });

    test('invalid public key verify returns false', () {
      final sig = SM2.doSignature('msg', SM2.generateKeyPairHex().privateKey);
      expect(SM2.doVerifySignature('msg', sig, ''), false);
    });

    test('pointPool accelerates and stays compatible', () {
      final pool = [SM2.getPoint(), SM2.getPoint(), SM2.getPoint()];
      final sig = SM2.doSignature(msgString, privateKey, pointPool: pool);
      expect(pool.length, 2); // 从尾部消费一个点
      expect(SM2.doVerifySignature(msgString, sig, unCompressedPublicKey), true);
    });
  });

  test('sm2: getPublicKeyFromPrivateKey', () {
    for (var i = 0; i < 10; i++) {
      final kp = SM2.generateKeyPairHex();
      expect(SM2.getPublicKeyFromPrivateKey(kp.privateKey), kp.publicKey);
    }
  });

  test('sm2: decrypt with invalid c1 point', () {
    final encryptData =
        SM2.doEncrypt(msgString, unCompressedPublicKey, cipherMode);
    final invalidC1 = '00' * 64;
    final invalidEncryptData = invalidC1 + encryptData.substring(128);
    expect(SM2.doDecrypt(invalidEncryptData, privateKey, cipherMode), '');
  });

  group('sm2: verify signature with invalid r or s', () {
    test('zero r / zero s rejected', () {
      final invalidSigHexZeroR = '00' * 32 + 'a' * 64;
      expect(
          SM2.doVerifySignature(
              msgString, invalidSigHexZeroR, unCompressedPublicKey),
          false);
      final invalidSigHexZeroS = 'a' * 64 + '00' * 32;
      expect(
          SM2.doVerifySignature(
              msgString, invalidSigHexZeroS, unCompressedPublicKey),
          false);
      final sig = SM2.doSignature(msgString, privateKey);
      expect(SM2.doVerifySignature(msgString, sig, unCompressedPublicKey), true);
    });
  });

  group('sm2: verify signature with invalid public key', () {
    test('invalid public keys rejected, valid accepted', () {
      final sig = SM2.doSignature(msgString, privateKey);
      final invalidPublicKey = '04' + '00' * 64;
      expect(
          SM2.doVerifySignature(msgString, sig, invalidPublicKey), false);
      final invalidPublicKey2 = '04' + 'a' * 10;
      expect(
          SM2.doVerifySignature(msgString, sig, invalidPublicKey2), false);
      expect(SM2.doVerifySignature(msgString, sig, unCompressedPublicKey), true);
      expect(SM2.doVerifySignature(msgString, sig, compressedPublicKey), true);
    });
  });

  // DER 编码必须为规范编码：拒绝可延展的非规范但数值等价编码
  group('sm2: der verify must reject non-canonical encodings', () {
    test('malleability suite', () {
      final sig = SM2.doSignature(msgString, privateKey,
          der: true, hash: false);
      expect(
          SM2.doVerifySignature(msgString, sig, unCompressedPublicKey,
              der: true, hash: false),
          true);

      // 解析原始 DER：30 <seqLen> 02 <rLen> <rVal> 02 <sLen> <sVal>
      final seqLen = int.parse(sig.substring(2, 4), radix: 16);
      expect(2 + 2 + seqLen * 2, sig.length);
      expect(sig.substring(4, 6), '02');
      final rLen = int.parse(sig.substring(6, 8), radix: 16);
      const rValStart = 8;
      final rVal = sig.substring(rValStart, rValStart + rLen * 2);
      final sTagStart = rValStart + rLen * 2;
      expect(sig.substring(sTagStart, sTagStart + 2), '02');
      final sLen = int.parse(sig.substring(sTagStart + 2, sTagStart + 4),
          radix: 16);
      final sVal = sig.substring(sTagStart + 4, sTagStart + 4 + sLen * 2);

      String seqLenHexFor(int newSeqLen) => newSeqLen < 0x80
          ? newSeqLen.toRadixString(16).padLeft(2, '0')
          : '81' + newSeqLen.toRadixString(16).padLeft(2, '0');

      // R 前导多余 00（padding 1~4 字节）
      for (var pad = 1; pad <= 4; pad++) {
        final paddedR = '00' * pad + rVal;
        final paddedRLen = paddedR.length ~/ 2;
        final newSeqLen = 2 + paddedRLen + 2 + sLen;
        final malleated = '30' +
            seqLenHexFor(newSeqLen) +
            '02' +
            paddedRLen.toRadixString(16).padLeft(2, '0') +
            paddedR +
            '02' +
            sLen.toRadixString(16).padLeft(2, '0') +
            sVal;
        expect(malleated, isNot(sig));
        expect(
            SM2.doVerifySignature(msgString, malleated, unCompressedPublicKey,
                der: true, hash: false),
            false);
      }

      // S 前导多余 00
      for (var pad = 1; pad <= 4; pad++) {
        final paddedS = '00' * pad + sVal;
        final paddedSLen = paddedS.length ~/ 2;
        final newSeqLen = 2 + rLen + 2 + paddedSLen;
        final finalSig = '30' +
            seqLenHexFor(newSeqLen) +
            '02' +
            rLen.toRadixString(16).padLeft(2, '0') +
            rVal +
            '02' +
            paddedSLen.toRadixString(16).padLeft(2, '0') +
            paddedS;
        expect(finalSig, isNot(sig));
        expect(
            SM2.doVerifySignature(msgString, finalSig, unCompressedPublicKey,
                der: true, hash: false),
            false);
      }

      // 尾部追加多余字节
      expect(
          SM2.doVerifySignature(msgString, sig + 'deadbeef',
              unCompressedPublicKey, der: true, hash: false),
          false);

      // 错误的外层 tag
      expect(
          SM2.doVerifySignature(msgString, '31' + sig.substring(2),
              unCompressedPublicKey, der: true, hash: false),
          false);

      // 错误的 R tag
      expect(
          SM2.doVerifySignature(msgString,
              sig.substring(0, 4) + '03' + sig.substring(6), unCompressedPublicKey,
              der: true, hash: false),
          false);

      // 完全非法的输入
      for (final bad in ['', 'zz', '30']) {
        expect(
            SM2.doVerifySignature(msgString, bad, unCompressedPublicKey,
                der: true, hash: false),
            false);
      }
    });
  });

  // 无穷远点 sentinel 绕过（GHSA-xj7m-r97m-9h7w 回归）：00 前缀 / 未知前缀公钥
  group('sm2: reject infinity-sentinel public keys', () {
    test('regression for 00-prefix bypass', () {
      final sig = SM2.doSignature(msgString, privateKey);

      final evilPublicKeys = [
        '0', // 单字符
        '00', // 纯 sentinel
        '00' + '11' * 64,
        '00' + 'a' * 128,
        '00' + '22' * 32,
        '01' + '11' * 64,
        '05' + '22' * 32,
        'ff' + '22' * 32,
        '', // 空串
      ];

      for (final pk in evilPublicKeys) {
        // 验签必须返回 false 而不抛异常
        expect(SM2.doVerifySignature(msgString, sig, pk), false,
            reason: 'evil public key: $pk');
        // verifyPublicKey 也必须返回 false 而不抛异常
        expect(SM2.verifyPublicKey(pk), false);
        // comparePublicKeyHex 与合法公钥比较必须返回 false
        expect(SM2.comparePublicKeyHex(pk, unCompressedPublicKey), false);
        expect(SM2.comparePublicKeyHex(unCompressedPublicKey, pk), false);
        // doEncrypt 面对畸形公钥应抛出可捕获的 ArgumentError
        expect(() => SM2.doEncrypt(msgString, pk, cipherMode),
            throwsA(isA<ArgumentError>().having(
                (e) => e.message, 'message', contains('Invalid public key'))));
      }

      // hash: false 路径同样必须安全
      expect(SM2.doVerifySignature(msgString, sig, '00', hash: false), false);
    });
  });

  // Uint8List 与 List<int> 等价字节必须产生可互相验证的签名
  test('sm2: Uint8List and List<int> produce mutually verifiable signatures',
      () {
    final typed = Uint8List.fromList([0x80, 0x01, 0x69, 0x24, 0xff, 0x00, 0x7f]);
    final array = List<int>.from(typed);

    const combos = [
      [true, false],
      [false, false],
      [true, true],
      [false, true],
    ];

    for (final combo in combos) {
      final hash = combo[0];
      final der = combo[1];

      final sigFromTyped = SM2.doSignature(typed, privateKey,
          hash: hash, der: der,
          publicKey: unCompressedPublicKey, userId: '1234567812345678');
      expect(
          SM2.doVerifySignature(typed, sigFromTyped, unCompressedPublicKey,
              hash: hash, der: der, userId: '1234567812345678'),
          true);
      expect(
          SM2.doVerifySignature(array, sigFromTyped, unCompressedPublicKey,
              hash: hash, der: der, userId: '1234567812345678'),
          true);

      final sigFromArray = SM2.doSignature(array, privateKey,
          hash: hash, der: der,
          publicKey: unCompressedPublicKey, userId: '1234567812345678');
      expect(
          SM2.doVerifySignature(typed, sigFromArray, unCompressedPublicKey,
              hash: hash, der: der, userId: '1234567812345678'),
          true);
      expect(
          SM2.doVerifySignature(array, sigFromArray, unCompressedPublicKey,
              hash: hash, der: der, userId: '1234567812345678'),
          true);
    }
  });
}
