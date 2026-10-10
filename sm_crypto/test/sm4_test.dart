import 'package:sm_crypto/sm_crypto.dart';
import 'package:test/test.dart';

/// 移植自 sm-crypto-js/test/sm4.test.js 的固定向量。
void main() {
  const msg = 'hello world! 我是 juneandgreen.';
  const input = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, //
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
  ];
  const output1 = [
    0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f,
    0x53, 0x6e, 0x42, 0x46, 0x00, 0x2a, 0x8a, 0x4e, 0xfa, 0x86, 0x3c, 0xca,
    0xd0, 0x24, 0xac, 0x03, 0x00, 0xbb, 0x40, 0xd2,
  ];
  const output2Block = [
    0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f,
    0x53, 0x6e, 0x42, 0x46,
  ];
  const output3 = [
    0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f,
    0x53, 0x6e, 0x42, 0x46, 0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
    0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46, 0x00, 0x2a, 0x8a, 0x4e,
    0xfa, 0x86, 0x3c, 0xca, 0xd0, 0x24, 0xac, 0x03, 0x00, 0xbb, 0x40, 0xd2,
  ];
  const outputHexStr1 =
      '681edf34d206965e86b3e94f536e4246002a8a4efa863ccad024ac0300bb40d2';
  const outputHexStr2 = '681edf34d206965e86b3e94f536e4246';
  const outputHexStr3 =
      '681edf34d206965e86b3e94f536e4246681edf34d206965e86b3e94f536e4246002a8a4efa863ccad024ac0300bb40d2';
  const input2 = [
    0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21,
    0x20, 0xe6, 0x88, 0x91, 0xe6, 0x98, 0xaf, 0x20, 0x6a, 0x75, 0x6e, 0x65,
    0x61, 0x6e, 0x64, 0x67, 0x72, 0x65, 0x65, 0x6e, 0x2e,
  ];
  const output2HexStr =
      '0e395deb10f6e8a17e17823e1fd9bd98a1bff1df508b5b8a1efb79ec633d1bb129432ac1b74972dbe97bab04f024e89c';
  const output3HexStr =
      '0d6cfa73c823b2ac0d6a92c564171892000fbea90be7a4d440bc58a9044fcb5f3d1615d91a6dbfb4dfb0c6915071527b';
  const output2 = [
    0x0e, 0x39, 0x5d, 0xeb, 0x10, 0xf6, 0xe8, 0xa1, 0x7e, 0x17, 0x82, 0x3e,
    0x1f, 0xd9, 0xbd, 0x98, 0xa1, 0xbf, 0xf1, 0xdf, 0x50, 0x8b, 0x5b, 0x8a,
    0x1e, 0xfb, 0x79, 0xec, 0x63, 0x3d, 0x1b, 0xb1, 0x29, 0x43, 0x2a, 0xc1,
    0xb7, 0x49, 0x72, 0xdb, 0xe9, 0x7b, 0xab, 0x04, 0xf0, 0x24, 0xe8, 0x9c,
  ];
  const iv = [
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, //
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
  ];
  const ivHexStr = 'fedcba98765432100123456789abcdef';
  const key = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, //
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
  ];
  const keyHexStr = '0123456789abcdeffedcba9876543210';

  group('sm4: encrypt a group', () {
    test('padding default / pkcs#5 / none', () {
      expect(SM4.encrypt(input, key), outputHexStr1);
      expect(SM4.encrypt(input, key, output: 'array'), output1);
      expect(SM4.encrypt(input, key, padding: 'pkcs#5'), outputHexStr1);
      expect(SM4.encrypt(input, key, padding: 'pkcs#5', output: 'array'),
          output1);
      expect(SM4.encrypt(input, key, padding: 'none'), outputHexStr2);
      expect(SM4.encrypt(input, key, padding: 'none', output: 'array'),
          output2Block);
    });

    test('utf8 string / byte array input, hex key', () {
      expect(SM4.encrypt(msg, keyHexStr), output2HexStr);
      expect(SM4.encrypt(msg, keyHexStr, output: 'array'), output2);
      expect(SM4.encrypt(input2, keyHexStr), output2HexStr);
      expect(SM4.encrypt(input2, keyHexStr, output: 'array'), output2);
    });

    test('cbc mode with iv as array and hex string', () {
      expect(SM4.encrypt(msg, keyHexStr, mode: 'cbc', iv: iv), output3HexStr);
      expect(SM4.encrypt(msg, keyHexStr, mode: 'cbc', iv: ivHexStr),
          output3HexStr);
    });
  });

  group('sm4: decrypt a group', () {
    test('round trip forms', () {
      expect(SM4.decrypt(outputHexStr1, key, output: 'array'), input);
      expect(SM4.decrypt(output1, key, output: 'array'), input);
      expect(
          SM4.decrypt(outputHexStr2, key,
              padding: 'none', output: 'array'),
          input);
      expect(SM4.decrypt(output2Block, key, padding: 'none', output: 'array'),
          input);
      expect(SM4.decrypt(output2HexStr, keyHexStr), msg);
      expect(SM4.decrypt(output2, keyHexStr), msg);
      expect(SM4.decrypt(output2HexStr, keyHexStr, output: 'array'), input2);
      expect(SM4.decrypt(output2, keyHexStr, output: 'array'), input2);
    });

    test('cbc mode', () {
      expect(SM4.decrypt(output3HexStr, keyHexStr, mode: 'cbc', iv: iv), msg);
      expect(SM4.decrypt(output3HexStr, keyHexStr, mode: 'cbc', iv: ivHexStr),
          msg);
    });
  });

  group('sm4: several groups', () {
    test('encrypt', () {
      expect(SM4.encrypt([...input, ...input], key), outputHexStr3);
      expect(SM4.encrypt([...input, ...input], key, output: 'array'), output3);
      expect(SM4.encrypt([...input, ...input], key, padding: 'none'),
          outputHexStr2 + outputHexStr2);
      expect(
          SM4.encrypt([...input, ...input], key,
              padding: 'none', output: 'array'),
          [...output2Block, ...output2Block]);
    });

    test('decrypt', () {
      expect(SM4.decrypt(outputHexStr3, key, output: 'array'),
          [...input, ...input]);
      expect(SM4.decrypt(output3, key, output: 'array'), [...input, ...input]);
      expect(
          SM4.decrypt(outputHexStr2 + outputHexStr2, key,
              padding: 'none', output: 'array'),
          [...input, ...input]);
      expect(
          SM4.decrypt([...output2Block, ...output2Block], key,
              padding: 'none', output: 'array'),
          [...input, ...input]);
    });
  });

  test('sm4: encrypt unicode string', () {
    expect(SM4.encrypt('🇨🇳𠮷😀😃😄😁😆😅', keyHexStr),
        'a0b1aac2e6db928ddfc8a081a6661d0452b44e5720db106714ffc8cbee29bcf7d96b4d64bffd07553e6a2ee096523b7f');
    expect(
        SM4.decrypt(
            'a0b1aac2e6db928ddfc8a081a6661d0452b44e5720db106714ffc8cbee29bcf7d96b4d64bffd07553e6a2ee096523b7f',
            keyHexStr),
        '🇨🇳𠮷😀😃😄😁😆😅');
    expect(SM4.decrypt(SM4.encrypt('🇨🇳𠮷😀😃😄😁😆😅', keyHexStr), keyHexStr),
        '🇨🇳𠮷😀😃😄😁😆😅');
  });

  test('sm4: encrypt a group 1000000 times', () {
    var temp = List<int>.from(input);
    for (var i = 0; i < 1000000; i++) {
      temp = SM4.encrypt(temp, key, padding: 'none', output: 'array') as List<int>;
    }
    expect(temp, [
      0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f, //
      0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66,
    ]);
  }, timeout: const Timeout(Duration(minutes: 3)));

  group('sm4: invalid padding', () {
    test('corrupted ciphertext throws', () {
      expect(
          () => SM4.decrypt(
              'a0b1aac2e6db928ddfc8a081a6661d0452b44e5720db106714ffc8cbee29bcf7d96b4d64bffd07553e6a2ee096523b7a',
              keyHexStr),
          throwsA(isA<ArgumentError>().having(
              (e) => e.message, 'message', contains('padding is invalid'))));
      expect(
          () => SM4.decrypt(
              'a0b1aac2e6db928ddfc8a081a6661d0452b44e5720db106714ffc8cbee29bcf7d96b4d64bffd07553e6a2ee096523b7f',
              ivHexStr),
          throwsA(isA<ArgumentError>().having(
              (e) => e.message, 'message', contains('padding is invalid'))));
    });

    test('invalid key / iv throws', () {
      expect(() => SM4.encrypt('abc', '0123'), throwsArgumentError);
      expect(() => SM4.encrypt('abc', keyHexStr, mode: 'cbc', iv: '0102'),
          throwsArgumentError);
    });
  });

  test('sm4: string output is hex for encrypt, utf8 for decrypt', () {
    final ct = SM4.encrypt(msg, keyHexStr) as String;
    expect(ct, matches(RegExp(r'^[0-9a-f]+$')));
    expect(SM4.decrypt(ct, keyHexStr), msg);
    expect(SM4.decrypt(ct, keyHexStr, output: 'array'), input2);
  });
}
