/// 有限域 GFp 上的椭圆曲线运算（jsbn 系投影坐标实现）。
///
/// 移植自 sm-crypto-js/src/sm2/ec.js（与 gm_crypto/lib/sm/utils/ec.dart 同源）。
library;

/// 素域元素。
class ECFieldElementFp {
  ECFieldElementFp(this.q, this.x);

  /// 模数 q。
  final BigInt q;

  /// 元素值。
  final BigInt x;

  /// 返回具体数值（js `toBigInteger`）。
  BigInt toBigInteger() => x;

  /// 相等判断。
  bool equals(ECFieldElementFp other) => q == other.q && x == other.x;

  /// 取反。
  ECFieldElementFp negate() => ECFieldElementFp(q, (-x) % q);

  /// 相加。
  ECFieldElementFp add(ECFieldElementFp b) =>
      ECFieldElementFp(q, (x + b.toBigInteger()) % q);

  /// 相减。
  ECFieldElementFp subtract(ECFieldElementFp b) =>
      ECFieldElementFp(q, (x - b.toBigInteger()) % q);

  /// 相乘。
  ECFieldElementFp multiply(ECFieldElementFp b) =>
      ECFieldElementFp(q, (x * b.toBigInteger()) % q);

  /// 平方。
  ECFieldElementFp square() => ECFieldElementFp(q, (x * x) % q);
}

/// 曲线上的点（投影坐标，z 分量）。
class ECPointFp {
  ECPointFp(this.curve, this.x, this.y, [BigInt? z]) : z = z ?? BigInt.one;

  /// 所属曲线。
  final ECCurveFp curve;

  /// 仿射 x（无穷远点为 null）。
  final ECFieldElementFp? x;

  /// 仿射 y（无穷远点为 null）。
  final ECFieldElementFp? y;

  /// 投影坐标 z 分量。
  final BigInt z;

  BigInt? _zinv;

  /// 仿射 x 坐标。
  ECFieldElementFp getX() {
    _zinv ??= z.modInverse(curve.q);
    return curve.fromBigInteger(x!.toBigInteger() * _zinv! % curve.q);
  }

  /// 仿射 y 坐标。
  ECFieldElementFp getY() {
    _zinv ??= z.modInverse(curve.q);
    return curve.fromBigInteger(y!.toBigInteger() * _zinv! % curve.q);
  }

  /// 点相等判断。
  bool equals(ECPointFp other) {
    if (other == this) return true;
    if (isInfinity()) return other.isInfinity();
    if (other.isInfinity()) return isInfinity();

    final u = (other.y!.toBigInteger() * z - y!.toBigInteger() * other.z) % curve.q;
    if (u != BigInt.zero) return false;

    final v = (other.x!.toBigInteger() * z - x!.toBigInteger() * other.z) % curve.q;
    return v == BigInt.zero;
  }

  /// 是否为无穷远点。
  bool isInfinity() {
    if (x == null && y == null) return true;
    return z == BigInt.zero && y!.toBigInteger() != BigInt.zero;
  }

  /// 取反。
  ECPointFp negate() => ECPointFp(curve, x, y!.negate(), z);

  /// 点加。
  ECPointFp add(ECPointFp b) {
    if (isInfinity()) return b;
    if (b.isInfinity()) return this;
    final x1 = x!.toBigInteger();
    final y1 = y!.toBigInteger();
    final z1 = z;
    final x2 = b.x!.toBigInteger();
    final y2 = b.y!.toBigInteger();
    final z2 = b.z;
    final q = curve.q;
    final w1 = (x1 * z2) % q;
    final w2 = (x2 * z1) % q;
    final w3 = (w1 - w2) % q;
    final w4 = (y1 * z2) % q;
    final w5 = (y2 * z1) % q;
    final w6 = (w4 - w5) % q;

    if (w3 == BigInt.zero) {
      if (w6 == BigInt.zero) return twice();
      return curve.infinity;
    }

    final w7 = (w1 + w2) % q;
    final w8 = (z1 * z2) % q;
    final w9 = (w3 * w3) % q;
    final w10 = (w3 * w9) % q;
    final w11 = (w8 * (w6 * w6) % q - w7 * w9) % q;

    final x3 = (w3 * w11) % q;
    final y3 = (w6 * (w9 * w1 % q - w11) - w4 * w10) % q;
    final z3 = (w10 * w8) % q;

    return ECPointFp(
      curve,
      curve.fromBigInteger(x3),
      curve.fromBigInteger(y3),
      z3,
    );
  }

  /// 倍点（jsbn 系投影坐标公式，λ1 = 3·x1² + a·z1²）。
  ECPointFp twice() {
    if (isInfinity()) return this;
    if (y!.toBigInteger().sign == 0) return curve.infinity;

    final x1 = x!.toBigInteger();
    final y1 = y!.toBigInteger();
    final z1 = z;
    final q = curve.q;
    final a = curve.a.toBigInteger();

    final w1 = (x1 * x1 * BigInt.from(3) + a * (z1 * z1)) % q;
    final w2 = (y1 * BigInt.from(2) * z1) % q;
    final w3 = (y1 * y1) % q;
    final w4 = (w3 * x1 * z1) % q;
    final w5 = (w2 * w2) % q;
    final w6 = (w1 * w1 - w4 * BigInt.from(8)) % q;

    final x3 = (w2 * w6) % q;
    final y3 = (w1 * (w4 * BigInt.from(4) - w6) - w5 * BigInt.from(2) * w3) % q;
    final z3 = (w2 * w5) % q;

    return ECPointFp(
      curve,
      curve.fromBigInteger(x3),
      curve.fromBigInteger(y3),
      z3,
    );
  }

  /// 标量乘 k·P（jsbn 的 3k 二进制展开法）。
  ECPointFp multiply(BigInt k) {
    if (isInfinity()) return this;
    if (k.sign == 0) return curve.infinity;

    final k3 = k * BigInt.from(3);
    final neg = negate();
    var qPoint = this;

    for (var i = k3.bitLength - 2; i > 0; i--) {
      qPoint = qPoint.twice();
      final k3Bit = (k3 >> i).isOdd;
      final kBit = (k >> i).isOdd;
      if (k3Bit != kBit) {
        qPoint = qPoint.add(k3Bit ? this : neg);
      }
    }

    return qPoint;
  }
}

/// 椭圆曲线 y² = x³ + ax + b（素域 GFp）。
class ECCurveFp {
  ECCurveFp(this.q, BigInt a, BigInt b) {
    this.a = fromBigInteger(a);
    this.b = fromBigInteger(b);
    infinity = ECPointFp(this, null, null);
  }

  /// 域模数。
  final BigInt q;

  /// 系数 a。
  late final ECFieldElementFp a;

  /// 系数 b。
  late final ECFieldElementFp b;

  /// 无穷远点。
  late final ECPointFp infinity;

  /// 由整数构造域元素。
  ECFieldElementFp fromBigInteger(BigInt x) => ECFieldElementFp(q, x);

  /// 解析点的 hex 编码，支持：
  /// - `00` 无穷远点
  /// - `02`/`03` 压缩点（x + y 奇偶前缀）
  /// - `04`/`06`/`07` 未压缩点
  ///
  /// 非法前缀返回 null；格式非法抛 [FormatException]/[RangeError]。
  ECPointFp? decodePointHex(String s) {
    if (s.length < 2) {
      throw FormatException('point hex too short', s);
    }
    switch (int.parse(s.substring(0, 2), radix: 16)) {
      case 0:
        return infinity;
      case 2:
      case 3:
        final x = fromBigInteger(BigInt.parse(s.substring(2), radix: 16));
        var y = fromBigInteger(x
            .multiply(x.square())
            .add(x.multiply(a))
            .add(b)
            .toBigInteger()
            .modPow(q ~/ BigInt.from(4) + BigInt.one, q));
        final prefix = BigInt.parse(s.substring(0, 2), radix: 16) - BigInt.two;
        if (y.toBigInteger() % BigInt.two != prefix) {
          y = y.negate();
        }
        return ECPointFp(this, x, y);
      case 4:
      case 6:
      case 7:
        final len = (s.length - 2) ~/ 2;
        final xHex = s.substring(2, 2 + len);
        final yHex = s.substring(2 + len, 2 + 2 * len);
        return ECPointFp(
          this,
          fromBigInteger(BigInt.parse(xHex, radix: 16)),
          fromBigInteger(BigInt.parse(yHex, radix: 16)),
        );
      default:
        return null;
    }
  }
}
