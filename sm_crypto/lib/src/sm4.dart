/// SM4 分组密码算法（GM/T 0002）。
///
/// 移植自 sm-crypto-js/src/sm4/index.js，支持 ECB/CBC 模式、
/// pkcs#5/pkcs#7/none 填充、hex/utf8/字节数组输入输出。
library;

import 'utils.dart';

class SM4 {
  SM4._();

  static const int _decrypt = 0;
  static const int _round = 32;
  static const int _block = 16;

  static const List<int> _sbox = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2,
    0x28, 0xfb, 0x2c, 0x05, 0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
    0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9c, 0x42, 0x50, 0xf4,
    0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa,
    0x75, 0x8f, 0x3f, 0xa6, 0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
    0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8, 0x68, 0x6b, 0x81, 0xb2,
    0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b,
    0x01, 0x21, 0x78, 0x87, 0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
    0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e, 0xea, 0xbf, 0x8a, 0xd2,
    0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30,
    0xf5, 0x8c, 0xb1, 0xe3, 0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
    0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37, 0x45,
    0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41,
    0x1f, 0x10, 0x5a, 0xd8, 0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
    0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0, 0x89, 0x69, 0x97, 0x4a,
    0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e,
    0xd7, 0xcb, 0x39, 0x48,
  ];

  static const List<int> _ck = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
  ];

  /// 加密（js `sm4.encrypt`）。
  ///
  /// - [msg]：utf8 串或字节数组。
  /// - [key]：hex 串或字节数组，必须 128 比特，否则抛 [ArgumentError]。
  /// - [padding]：`'pkcs#7'`（默认，`'pkcs#5'` 等价）或 `'none'`。
  /// - [mode]：`'cbc'` 走 CBC（需 [iv]），其余走 ECB。
  /// - [iv]：hex 串或字节数组，CBC 下必须 128 比特。
  /// - [output]：`'string'` 输出 hex 串（默认），`'array'` 输出字节数组。
  static dynamic encrypt(
    dynamic msg,
    dynamic key, {
    String padding = 'pkcs#7',
    String? mode,
    dynamic iv,
    String output = 'string',
  }) {
    return _sm4(msg, key, 1, padding: padding, mode: mode, iv: iv, output: output);
  }

  /// 解密（js `sm4.decrypt`）。
  ///
  /// - [data]：hex 串或字节数组。
  /// - 输出：`'string'` 输出 utf8 串（默认），`'array'` 输出字节数组。
  ///
  /// 其余参数同 [encrypt]。
  static dynamic decrypt(
    dynamic data,
    dynamic key, {
    String padding = 'pkcs#7',
    String? mode,
    dynamic iv,
    String output = 'string',
  }) {
    return _sm4(data, key, 0, padding: padding, mode: mode, iv: iv, output: output);
  }

  static dynamic _sm4(
    dynamic inArray,
    dynamic key,
    int cryptFlag, {
    String padding = 'pkcs#7',
    String? mode,
    dynamic iv,
    String output = 'string',
  }) {
    final isCbc = mode == 'cbc';
    List<int>? ivBytes;
    if (isCbc) {
      ivBytes = iv is String ? hexToBytes(iv) : List<int>.from(iv as List);
      if (ivBytes.length != _block) {
        throw ArgumentError.value(iv, 'iv', 'iv is invalid');
      }
    }

    // 检查 key：hex 串或字节数组，必须 128 比特
    final keyBytes = key is String ? hexToBytes(key) : List<int>.from(key as List);
    if (keyBytes.length != _block) {
      throw ArgumentError.value(key, 'key', 'key is invalid');
    }

    // 检查输入：加密时字符串按 utf8，解密时字符串按 hex（统一为可增长列表）
    final List<int> input;
    if (inArray is String) {
      input = List<int>.from(
          cryptFlag != _decrypt ? utf8ToBytes(inArray) : hexToBytes(inArray));
    } else {
      input = List<int>.from(inArray as List);
    }

    // 新增填充（sm4 是 16 字节一组，pkcs#5 走 pkcs#7）
    if ((padding == 'pkcs#5' || padding == 'pkcs#7') && cryptFlag != _decrypt) {
      final paddingCount = _block - input.length % _block;
      input.addAll(List<int>.filled(paddingCount, paddingCount));
    }

    // 生成轮密钥
    final roundKey = _keyExt(keyBytes, cryptFlag);

    final out = <int>[];
    var lastVector = ivBytes ?? const <int>[];
    var point = 0;
    while (input.length - point >= _block) {
      final block = input.sublist(point, point + _block);
      if (isCbc && cryptFlag != _decrypt) {
        // 加密过程在组加密前进行异或
        for (var i = 0; i < _block; i++) {
          block[i] = (block[i] ^ lastVector[i]) & 0xff;
        }
      }

      final blockOut = _cryptBlock(block, roundKey);

      if (isCbc && cryptFlag == _decrypt) {
        // 解密过程在组解密后进行异或
        for (var i = 0; i < _block; i++) {
          blockOut[i] = (blockOut[i] ^ lastVector[i]) & 0xff;
        }
      }

      out.addAll(blockOut);
      lastVector = isCbc
          ? (cryptFlag != _decrypt ? blockOut : block)
          : lastVector;
      point += _block;
    }

    // 去除填充（与 js 一致：填充字节为 0 时不移除也不报错；
    // 填充字节与实际字节不符或越界则抛 'padding is invalid'）
    if ((padding == 'pkcs#5' || padding == 'pkcs#7') && cryptFlag == _decrypt) {
      final paddingCount = out.isEmpty ? 0 : out[out.length - 1];
      for (var i = 1; i <= paddingCount; i++) {
        if (i > out.length || out[out.length - i] != paddingCount) {
          throw ArgumentError('padding is invalid');
        }
      }
      if (paddingCount > 0) {
        out.removeRange(out.length - paddingCount, out.length);
      }
    }

    // 调整输出
    if (output == 'array') return out;
    return cryptFlag != _decrypt ? bytesToHex(out) : bytesToUtf8(out);
  }

  /// 以一组 128 比特进行加密/解密操作（js `sms4Crypt`）。
  static List<int> _cryptBlock(List<int> input, List<int> roundKey) {
    final x = List<int>.filled(4, 0);
    for (var i = 0; i < 4; i++) {
      x[i] = ((input[4 * i] & 0xff) << 24) |
          ((input[4 * i + 1] & 0xff) << 16) |
          ((input[4 * i + 2] & 0xff) << 8) |
          (input[4 * i + 3] & 0xff);
    }

    for (var r = 0; r < _round; r += 4) {
      var mid = (x[1] ^ x[2] ^ x[3] ^ roundKey[r + 0]) & 0xffffffff;
      x[0] = (x[0] ^ _l1(_byteSub(mid))) & 0xffffffff;

      mid = (x[2] ^ x[3] ^ x[0] ^ roundKey[r + 1]) & 0xffffffff;
      x[1] = (x[1] ^ _l1(_byteSub(mid))) & 0xffffffff;

      mid = (x[3] ^ x[0] ^ x[1] ^ roundKey[r + 2]) & 0xffffffff;
      x[2] = (x[2] ^ _l1(_byteSub(mid))) & 0xffffffff;

      mid = (x[0] ^ x[1] ^ x[2] ^ roundKey[r + 3]) & 0xffffffff;
      x[3] = (x[3] ^ _l1(_byteSub(mid))) & 0xffffffff;
    }

    // 反序变换
    final output = List<int>.filled(_block, 0);
    for (var j = 0; j < 16; j += 4) {
      output[j] = (x[3 - j ~/ 4] >>> 24) & 0xff;
      output[j + 1] = (x[3 - j ~/ 4] >>> 16) & 0xff;
      output[j + 2] = (x[3 - j ~/ 4] >>> 8) & 0xff;
      output[j + 3] = x[3 - j ~/ 4] & 0xff;
    }
    return output;
  }

  /// 密钥扩展算法（js `sms4KeyExt`），解密时返回反序轮密钥。
  static List<int> _keyExt(List<int> key, int cryptFlag) {
    final roundKey = List<int>.filled(_round, 0);
    final x = List<int>.filled(4, 0);
    for (var i = 0; i < 4; i++) {
      x[i] = ((key[4 * i] & 0xff) << 24) |
          ((key[4 * i + 1] & 0xff) << 16) |
          ((key[4 * i + 2] & 0xff) << 8) |
          (key[4 * i + 3] & 0xff);
    }

    // 与系统参数做异或
    x[0] ^= 0xa3b1bac6;
    x[1] ^= 0x56aa3350;
    x[2] ^= 0x677d9197;
    x[3] ^= 0xb27022dc;

    for (var r = 0; r < _round; r += 4) {
      var mid = (x[1] ^ x[2] ^ x[3] ^ _ck[r + 0]) & 0xffffffff;
      x[0] = (x[0] ^ _l2(_byteSub(mid))) & 0xffffffff;
      roundKey[r + 0] = x[0];

      mid = (x[2] ^ x[3] ^ x[0] ^ _ck[r + 1]) & 0xffffffff;
      x[1] = (x[1] ^ _l2(_byteSub(mid))) & 0xffffffff;
      roundKey[r + 1] = x[1];

      mid = (x[3] ^ x[0] ^ x[1] ^ _ck[r + 2]) & 0xffffffff;
      x[2] = (x[2] ^ _l2(_byteSub(mid))) & 0xffffffff;
      roundKey[r + 2] = x[2];

      mid = (x[0] ^ x[1] ^ x[2] ^ _ck[r + 3]) & 0xffffffff;
      x[3] = (x[3] ^ _l2(_byteSub(mid))) & 0xffffffff;
      roundKey[r + 3] = x[3];
    }

    // 解密时使用反序的轮密钥
    if (cryptFlag == _decrypt) {
      for (var r = 0; r < 16; r++) {
        final tmp = roundKey[r];
        roundKey[r] = roundKey[31 - r];
        roundKey[31 - r] = tmp;
      }
    }
    return roundKey;
  }

  static int _rotl(int x, int n) {
    final s = n & 31;
    return ((x << s) | (x >>> (32 - s))) & 0xffffffff;
  }

  /// 非线性变换。
  static int _byteSub(int a) {
    return ((_sbox[(a >>> 24) & 0xff] & 0xff) << 24) |
        ((_sbox[(a >>> 16) & 0xff] & 0xff) << 16) |
        ((_sbox[(a >>> 8) & 0xff] & 0xff) << 8) |
        (_sbox[a & 0xff] & 0xff);
  }

  /// 线性变换，加密/解密用。
  static int _l1(int b) => (b ^ _rotl(b, 2) ^ _rotl(b, 10) ^ _rotl(b, 18) ^ _rotl(b, 24)) & 0xffffffff;

  /// 线性变换，生成轮密钥用。
  static int _l2(int b) => (b ^ _rotl(b, 13) ^ _rotl(b, 23)) & 0xffffffff;
}
