/// SM2 椭圆曲线公钥密码算法（GM/T 0003）。
///
/// API 与语义对齐 sm-crypto-js/src/sm2/index.js，输出与 js 版可互操作。
library;

import 'dart:math';

import 'asn1.dart';
import 'ec.dart';
import 'sm3.dart';
import 'utils.dart';

/// 密钥对（js `generateKeyPairHex` 返回的 `{privateKey, publicKey}`）。
class KeyPair {
  const KeyPair({required this.privateKey, required this.publicKey});

  /// 私钥，64 位 hex 串。
  final String privateKey;

  /// 未压缩公钥，`04` + x + y，130 位 hex 串。
  final String publicKey;
}

/// 预生成的椭圆曲线点（js `getPoint` 返回的 keypair + `k` + `x1`），
/// 可放入 [SM2.doSignature] 的 pointPool 加快签名。
class SM2Point {
  const SM2Point({
    required this.privateKey,
    required this.publicKey,
    required this.k,
    required this.x1,
  });

  /// 随机数 k 的 hex 串（同时是临时私钥）。
  final String privateKey;

  /// 点 k·G 的未压缩 hex 串。
  final String publicKey;

  /// 随机数 k。
  final BigInt k;

  /// 点 k·G 的仿射 x 坐标。
  final BigInt x1;
}

class SM2 {
  SM2._();

  /// 密文格式：C1C2C3。
  static const int c1c2c3 = 0;

  /// 密文格式：C1C3C2（默认）。
  static const int c1c3c2 = 1;

  static const String defaultUserId = '1234567812345678';

  // sm2p256v1 曲线参数（js `generateEcparam`）
  static final BigInt _p = BigInt.parse(
    'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
    radix: 16,
  );
  static final BigInt _a = BigInt.parse(
    'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
    radix: 16,
  );
  static final BigInt _b = BigInt.parse(
    '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
    radix: 16,
  );
  static final BigInt _n = BigInt.parse(
    'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
    radix: 16,
  );
  static final ECCurveFp _curve = ECCurveFp(_p, _a, _b);
  static final ECPointFp _g =
      _curve.decodePointHex(
        '04'
        '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7'
        'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0',
      )!;
  static final Random _rng = Random.secure();

  /// 生成密钥对：publicKey = privateKey · G（js `generateKeyPairHex`）。
  ///
  /// 可选 [random] 为自定义随机数（十进制字符串或 [BigInt]），语义对应 js
  /// 「参数直接透传 jsbn BigInteger 构造器」的单参用法。开发者使用自定义
  /// 随机数需自行确保其符合密码学安全。
  static KeyPair generateKeyPairHex([dynamic random]) {
    final BigInt d;
    if (random == null) {
      d = _randomScalar();
    } else {
      final BigInt r;
      if (random is BigInt) {
        r = random;
      } else {
        r = BigInt.parse(random.toString(), radix: 10);
      }
      // jsbn 的 mod 返回非负值；Dart BigInt % 对正模数同为非负
      d = r % (_n - BigInt.one) + BigInt.one;
    }

    final privateKey = leftPad(d.toRadixString(16), 64);
    final p = _g.multiply(d);
    final publicKey =
        '04' +
        leftPad(p.getX().toBigInteger().toRadixString(16), 64) +
        leftPad(p.getY().toBigInteger().toRadixString(16), 64);
    return KeyPair(privateKey: privateKey, publicKey: publicKey);
  }

  /// 压缩公钥：130 位 → 66 位（js `compressPublicKeyHex`）。
  static String compressPublicKeyHex(String s) {
    if (s.length != 130) {
      throw ArgumentError.value(s, 's', 'Invalid public key to compress');
    }
    final len = (s.length - 2) ~/ 2;
    final xHex = s.substring(2, 2 + len);
    final y = BigInt.parse(s.substring(2 + len, 2 + 2 * len), radix: 16);
    final prefix = y.isEven ? '02' : '03';
    return prefix + xHex;
  }

  /// 验证公钥是否为椭圆曲线上的点（js `verifyPublicKey`）。
  static bool verifyPublicKey(String publicKey) {
    if (publicKey.isEmpty) return false;
    ECPointFp? point;
    try {
      point = _curve.decodePointHex(publicKey);
    } catch (_) {
      return false;
    }
    // 无穷远点（00 前缀返回 infinity）不是合法公钥
    if (point == null || point.isInfinity()) return false;

    final x = point.getX();
    final y = point.getY();
    // 验证 y² 是否等于 x³ + ax + b
    return y.square().equals(
      x.multiply(x.square()).add(x.multiply(_curve.a)).add(_curve.b),
    );
  }

  /// 验证两个公钥是否等价（支持压缩/未压缩混用，js `comparePublicKeyHex`）。
  static bool comparePublicKeyHex(String publicKey1, String publicKey2) {
    if (!verifyPublicKey(publicKey1) || !verifyPublicKey(publicKey2)) {
      return false;
    }
    final point1 = _curve.decodePointHex(publicKey1)!;
    final point2 = _curve.decodePointHex(publicKey2)!;
    return point1.equals(point2);
  }

  /// 加密（js `doEncrypt`）。
  ///
  /// [msg] 为 utf8 串或字节数组；[cipherMode] 1 = C1C3C2（默认），0 = C1C2C3。
  /// 返回 hex 串。公钥非法抛 [ArgumentError]。
  static String doEncrypt(
    dynamic msg,
    String publicKey, [
    int cipherMode = c1c3c2,
  ]) {
    if (!verifyPublicKey(publicKey)) {
      throw ArgumentError.value(publicKey, 'publicKey', 'Invalid public key');
    }
    final msgBytes = toBytes(msg);
    final pubPoint = _curve.decodePointHex(publicKey)!;

    final keypair = generateKeyPairHex();
    final k = BigInt.parse(keypair.privateKey, radix: 16);

    // c1 = k · G
    var c1 = keypair.publicKey;
    if (c1.length > 128) c1 = c1.substring(c1.length - 128);

    // (x2, y2) = k · publicKey
    final p = pubPoint.multiply(k);
    final x2 = hexToBytes(
      leftPad(p.getX().toBigInteger().toRadixString(16), 64),
    );
    final y2 = hexToBytes(
      leftPad(p.getY().toBigInteger().toRadixString(16), 64),
    );

    // c3 = hash(x2 ‖ msg ‖ y2)
    final c3 = bytesToHex(SM3.digest([...x2, ...msgBytes, ...y2]));

    // c2 = msg ⊕ KDF(x2 ‖ y2)
    final t = _kdf([...x2, ...y2], msgBytes.length);
    final c2 = [for (var i = 0; i < msgBytes.length; i++) msgBytes[i] ^ t[i]];

    return cipherMode == c1c2c3
        ? c1 + bytesToHex(c2) + c3
        : c1 + c3 + bytesToHex(c2);
  }

  /// 解密（js `doDecrypt`）。
  ///
  /// [cipherMode] 1 = C1C3C2（默认），0 = C1C2C3；[output] `'string'` 返回
  /// utf8 串（默认），`'array'` 返回字节数组。解密失败（密文非法或校验不过）
  /// 静默返回 `''` 或 `[]`，与 js 行为一致。
  static dynamic doDecrypt(
    String encryptData,
    String privateKey, [
    int cipherMode = c1c3c2,
    String output = 'string',
  ]) {
    dynamic fail() => output == 'array' ? <int>[] : '';

    final String c3;
    final String c2;
    if (cipherMode == c1c2c3) {
      c3 = _slice(encryptData, encryptData.length - 64);
      c2 = _slice(encryptData, 128, encryptData.length - 64);
    } else {
      c3 = _slice(encryptData, 128, 192);
      c2 = _slice(encryptData, 192);
    }

    List<int> msg;
    try {
      msg = hexToBytes(c2);
    } catch (_) {
      return fail();
    }

    final c1Hex = _slice(encryptData, 0, 128);
    ECPointFp? c1;
    BigInt d;
    try {
      c1 = _curve.decodePointHex('04' + c1Hex);
      d = BigInt.parse(privateKey, radix: 16);
    } catch (_) {
      return fail();
    }
    if (c1 == null || !verifyPublicKey('04' + c1Hex)) return fail();

    final p = c1.multiply(d);
    final x2 = hexToBytes(
      leftPad(p.getX().toBigInteger().toRadixString(16), 64),
    );
    final y2 = hexToBytes(
      leftPad(p.getY().toBigInteger().toRadixString(16), 64),
    );

    final t = _kdf([...x2, ...y2], msg.length);
    for (var i = 0; i < msg.length; i++) {
      msg[i] ^= t[i];
    }

    // c3 = hash(x2 ‖ msg ‖ y2)
    final checkC3 = bytesToHex(SM3.digest([...x2, ...msg, ...y2]));
    if (checkC3 != c3.toLowerCase()) return fail();

    return output == 'array' ? msg : bytesToUtf8(msg);
  }

  /// 签名（js `doSignature`）。
  ///
  /// - [hash] 默认 true，即做 SM3 杂凑；false 为纯签名。
  /// - [der] true 输出 ASN.1 DER 编码，false 输出 r ‖ s 的 128 位 hex。
  /// - [publicKey] 传入公钥可跳过由私钥推导公钥的过程，速度更快。
  /// - [userId] 默认 `1234567812345678`。
  /// - [pointPool] 传入事先生成好的 [SM2Point] 可加快签名速度（从尾部消费）。
  static String doSignature(
    dynamic msg,
    String privateKey, {
    List<SM2Point>? pointPool,
    bool der = false,
    bool hash = true,
    String? publicKey,
    String? userId,
  }) {
    var hashHex = bytesToHex(toBytes(msg));
    if (hash) {
      publicKey ??= getPublicKeyFromPrivateKey(privateKey);
      hashHex = _getHash(hashHex, publicKey, userId ?? defaultUserId);
    }

    final dA = BigInt.parse(privateKey, radix: 16);
    final e = hashHex.isEmpty ? BigInt.zero : BigInt.parse(hashHex, radix: 16);

    late BigInt k;
    late BigInt r;
    late BigInt s;
    do {
      do {
        final SM2Point point;
        if (pointPool != null && pointPool.isNotEmpty) {
          point = pointPool.removeLast();
        } else {
          point = getPoint();
        }
        k = point.k;

        // r = (e + x1) mod n
        r = (e + point.x1) % _n;
      } while (r == BigInt.zero || r + k == _n);

      // s = ((1 + dA)^-1 · (k - r · dA)) mod n
      s = (dA + BigInt.one).modInverse(_n) * ((k - r * dA) % _n) % _n;
    } while (s == BigInt.zero);

    if (der) return encodeDer(r, s);
    return leftPad(r.toRadixString(16), 64) + leftPad(s.toRadixString(16), 64);
  }

  /// 验签（js `doVerifySignature`）。
  ///
  /// 任何非法输入（公钥非法、DER 非规范、r/s 越界等）返回 false，不抛异常。
  static bool doVerifySignature(
    dynamic msg,
    String signHex,
    String publicKey, {
    bool der = false,
    bool hash = true,
    String? userId,
  }) {
    if (!verifyPublicKey(publicKey)) return false;

    var hashHex = bytesToHex(toBytes(msg));
    if (hash) {
      hashHex = _getHash(hashHex, publicKey, userId ?? defaultUserId);
    }

    final BigInt r;
    final BigInt s;
    if (der) {
      try {
        final rs = decodeDer(signHex);
        r = rs.r;
        s = rs.s;
      } catch (_) {
        // 非规范 DER 编码（前导 00 填充、tag 错误、长度不一致等）
        return false;
      }
    } else {
      try {
        r = _parseHexOrZero(_slice(signHex, 0, 64));
        s = _parseHexOrZero(_slice(signHex, 64));
      } catch (_) {
        return false;
      }
    }

    final nSubOne = _n - BigInt.one;
    if (r < BigInt.one || r > nSubOne) return false;
    if (s < BigInt.one || s > nSubOne) return false;

    final pa = _curve.decodePointHex(publicKey);
    if (pa == null || pa.isInfinity()) return false;
    final e = hashHex.isEmpty ? BigInt.zero : BigInt.parse(hashHex, radix: 16);

    // t = (r + s) mod n
    final t = (r + s) % _n;
    if (t == BigInt.zero) return false;

    // x1y1 = s · G + t · PA
    final x1y1 = _g.multiply(s).add(pa.multiply(t));

    // R = (e + x1) mod n
    final rr = (e + x1y1.getX().toBigInteger()) % _n;
    return r == rr;
  }

  /// 根据私钥推导公钥（js `getPublicKeyFromPrivateKey`）。
  static String getPublicKeyFromPrivateKey(String privateKey) {
    final d = BigInt.parse(privateKey, radix: 16);
    final pa = _g.multiply(d);
    return '04' +
        leftPad(pa.getX().toBigInteger().toRadixString(16), 64) +
        leftPad(pa.getY().toBigInteger().toRadixString(16), 64);
  }

  /// 获取一个椭圆曲线点，可在签名时传入 [SM2.doSignature] 的 pointPool
  /// （js `getPoint`）。
  static SM2Point getPoint() {
    final keypair = generateKeyPairHex();
    final pa = _curve.decodePointHex(keypair.publicKey)!;
    return SM2Point(
      privateKey: keypair.privateKey,
      publicKey: keypair.publicKey,
      k: BigInt.parse(keypair.privateKey, radix: 16),
      x1: pa.getX().toBigInteger(),
    );
  }

  /// SM3 杂凑：z = hash(ENTL ‖ userId ‖ a ‖ b ‖ Gx ‖ Gy ‖ Px ‖ Py)，
  /// e = hash(z ‖ msg)（js `getHash`）。
  static String _getHash(String hashHex, String publicKey, String userId) {
    final uidHex = bytesToHex(utf8ToBytes(userId));
    final a = leftPad(_a.toRadixString(16), 64);
    final b = leftPad(_b.toRadixString(16), 64);
    final gx = leftPad(_g.getX().toBigInteger().toRadixString(16), 64);
    final gy = leftPad(_g.getY().toBigInteger().toRadixString(16), 64);

    final String px;
    final String py;
    if (publicKey.length == 128) {
      px = publicKey.substring(0, 64);
      py = publicKey.substring(64, 128);
    } else {
      final ECPointFp? point;
      try {
        point = _curve.decodePointHex(publicKey);
      } catch (_) {
        throw ArgumentError.value(publicKey, 'publicKey', 'Invalid public key');
      }
      if (point == null || point.isInfinity()) {
        throw ArgumentError.value(publicKey, 'publicKey', 'Invalid public key');
      }
      px = leftPad(point.getX().toBigInteger().toRadixString(16), 64);
      py = leftPad(point.getY().toBigInteger().toRadixString(16), 64);
    }

    final data = hexToBytes(uidHex + a + b + gx + gy + px + py);

    // entl 为 userId 的比特长度
    final entl = uidHex.length * 4;
    final z = SM3.digest([(entl >> 8) & 0xff, entl & 0xff, ...data]);

    // e = hash(z ‖ msg)
    return bytesToHex(SM3.digest([...z, ...hexToBytes(hashHex)]));
  }

  /// KDF：以 SM3 为杂凑函数的密钥流（计数器从 1 起、大端 4 字节）。
  static List<int> _kdf(List<int> z, int len) {
    final out = <int>[];
    var ct = 1;
    while (out.length < len) {
      out.addAll(
        SM3.digest([
          ...z,
          (ct >> 24) & 0xff,
          (ct >> 16) & 0xff,
          (ct >> 8) & 0xff,
          ct & 0xff,
        ]),
      );
      ct++;
    }
    return out.sublist(0, len);
  }

  static BigInt _randomScalar() {
    final bytes = List<int>.generate(32, (_) => _rng.nextInt(256));
    final r = BigInt.parse(bytesToHex(bytes), radix: 16);
    return r % (_n - BigInt.one) + BigInt.one;
  }

  /// js `substr(start, len)` 语义的越界安全切片。
  static String _slice(String s, int start, [int? end]) {
    var from = start;
    if (from < 0) from = 0;
    if (from > s.length) from = s.length;
    var to = end ?? s.length;
    if (to < from) to = from;
    if (to > s.length) to = s.length;
    return s.substring(from, to);
  }

  static BigInt _parseHexOrZero(String hex) {
    if (hex.isEmpty) return BigInt.zero;
    return BigInt.parse(hex, radix: 16);
  }
}
