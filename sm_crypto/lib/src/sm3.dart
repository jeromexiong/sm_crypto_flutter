/// SM3 密码杂凑算法（GM/T 0004），含 HMAC-SM3。
///
/// 移植自 sm-crypto-js/src/sm2/sm3.js，API 与 js 的 `sm3(msg, {key})` 对齐。
library;

import 'utils.dart';

class SM3 {
  SM3._();

  /// 杂凑入口，返回 hex 串（js 默认导出函数）。
  ///
  /// - [input] 为 [String]（按 utf8 编码）或 [List<int>]（字节直通）。
  /// - 提供 [key] 时计算 HMAC-SM3；[key] 为 hex 串或 [List<int>]。
  ///   空字符串 key 抛 [ArgumentError]（js `'invalid key'`）。
  static String hash(dynamic input, {dynamic key}) {
    final bytes = toBytes(input);
    if (key == null) return bytesToHex(digest(bytes));

    final List<int> keyBytes;
    if (key is String) {
      if (key.isEmpty) {
        throw ArgumentError.value(key, 'key', 'invalid key');
      }
      keyBytes = hexToBytes(key);
    } else if (key is List<int>) {
      keyBytes = List<int>.from(key);
    } else {
      throw ArgumentError.value(key, 'key', 'must be hex String or List<int>');
    }
    return bytesToHex(hmac(bytes, keyBytes));
  }

  /// SM3 杂凑，返回 32 字节摘要（js `sm3` 本体）。
  static List<int> digest(List<int> input) {
    final lenBits = input.length * 8;

    // k 是满足 len + 1 + k ≡ 448 (mod 512) 的最小非负整数
    var k = lenBits % 512;
    k = k >= 448 ? 512 - (k % 448) - 1 : 448 - k - 1;

    final padBytes = (k - 7) ~/ 8;
    final m = <int>[
      ...input,
      0x80,
      ...List<int>.filled(padBytes, 0),
      // 64 比特大端消息长度
      for (var i = 7; i >= 0; i--) (lenBits >> (8 * i)) & 0xff,
    ];

    final w = List<int>.filled(68, 0);
    final w1 = List<int>.filled(64, 0);
    final v = <int>[
      0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, //
      0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e,
    ];

    for (var block = 0; block < m.length ~/ 64; block++) {
      final start = 64 * block;
      for (var j = 0; j < 16; j++) {
        final o = start + j * 4;
        w[j] = ((m[o] & 0xff) << 24) |
            ((m[o + 1] & 0xff) << 16) |
            ((m[o + 2] & 0xff) << 8) |
            (m[o + 3] & 0xff);
      }

      // W16 ～ W67
      for (var j = 16; j < 68; j++) {
        w[j] = (_p1((w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15)) & 0xffffffff) ^
                _rotl(w[j - 13], 7) ^
                w[j - 6]) &
            0xffffffff;
      }

      // W′0 ～ W′63
      for (var j = 0; j < 64; j++) {
        w1[j] = (w[j] ^ w[j + 4]) & 0xffffffff;
      }

      var a = v[0];
      var b = v[1];
      var c = v[2];
      var d = v[3];
      var e = v[4];
      var f = v[5];
      var g = v[6];
      var h = v[7];

      for (var j = 0; j < 64; j++) {
        final t = j <= 15 ? 0x79cc4519 : 0x7a879d8a;
        final ss1 = _rotl((_rotl(a, 12) + e + _rotl(t, j)) & 0xffffffff, 7);
        final ss2 = (ss1 ^ _rotl(a, 12)) & 0xffffffff;

        final tt1 = ((j <= 15
                    ? (a ^ b ^ c)
                    : ((a & b) | (a & c) | (b & c))) &
                0xffffffff) +
            d +
            ss2 +
            w1[j];
        final tt2 = ((j <= 15
                    ? (e ^ f ^ g)
                    : ((e & f) | (~e & g))) &
                0xffffffff) +
            h +
            ss1 +
            w[j];

        d = c;
        c = _rotl(b, 9);
        b = a;
        a = tt1 & 0xffffffff;
        h = g;
        g = _rotl(f, 19);
        f = e;
        e = _p0(tt2 & 0xffffffff);
      }

      v[0] ^= a;
      v[1] ^= b;
      v[2] ^= c;
      v[3] ^= d;
      v[4] ^= e;
      v[5] ^= f;
      v[6] ^= g;
      v[7] ^= h;
    }

    final result = <int>[];
    for (final word in v) {
      result.add((word >> 24) & 0xff);
      result.add((word >> 16) & 0xff);
      result.add((word >> 8) & 0xff);
      result.add(word & 0xff);
    }
    return result;
  }

  /// HMAC-SM3（js `hmac`），返回 32 字节摘要。
  static List<int> hmac(List<int> input, List<int> key) {
    const blockLen = 64;
    var k = key;
    if (k.length > blockLen) k = digest(k);
    k = [...k, ...List<int>.filled(blockLen - k.length, 0)];

    final ipadKey = [for (final b in k) (b ^ 0x36) & 0xff];
    final opadKey = [for (final b in k) (b ^ 0x5c) & 0xff];

    final inner = digest([...ipadKey, ...input]);
    return digest([...opadKey, ...inner]);
  }

  static int _rotl(int x, int n) {
    final s = n & 31;
    return ((x << s) | (x >>> (32 - s))) & 0xffffffff;
  }

  static int _p0(int x) => (x ^ _rotl(x, 9) ^ _rotl(x, 17)) & 0xffffffff;

  static int _p1(int x) => (x ^ _rotl(x, 15) ^ _rotl(x, 23)) & 0xffffffff;
}
