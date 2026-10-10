/// ASN.1 DER 编解码，针对 SM2 签名的 (r, s)。
///
/// 移植自 sm-crypto-js/src/sm2/asn1.js。解码侧严格校验 DER 规范编码，
/// 拒绝任何非规范编码（INTEGER 前导 00 填充、SEQUENCE 长度不一致、
/// 错误 tag、尾随字节等），避免签名可延展性（signature malleability）问题。
/// 校验失败抛 [FormatException]。
library;

/// 正整数的 DER INTEGER value 编码（js `bigintToValue` 正数分支）。
String _bigintToValue(BigInt bigint) {
  if (bigint.isNegative) {
    throw ArgumentError.value(bigint, 'bigint', 'must be non-negative');
  }
  var h = bigint.toRadixString(16);
  if (h.length.isOdd) {
    h = '0$h'; // 补齐到整字节
  } else if (!RegExp(r'^[0-7]').hasMatch(h)) {
    h = '00$h'; // 非 0 开头（高位为 1），补一个全 0 字节避免被解析为负数
  }
  return h;
}

String _encodeLength(String v) {
  final n = v.length ~/ 2; // 字节数
  var nHex = n.toRadixString(16);
  if (nHex.length.isOdd) nHex = '0$nHex';

  if (n < 128) {
    return nHex; // 短格式
  }
  // 长格式：首字节 = 0x80 + 长度字段字节数
  final head = 128 + nHex.length ~/ 2;
  return head.toRadixString(16) + nHex;
}

/// ASN.1 DER 编码 SM2 签名 (r, s)（js `encodeDer`）。
String encodeDer(BigInt r, BigInt s) {
  final rValue = _bigintToValue(r);
  final sValue = _bigintToValue(s);
  final rTlv = '02' + _encodeLength(rValue) + rValue;
  final sTlv = '02' + _encodeLength(sValue) + sValue;
  final v = rTlv + sTlv;
  return '30' + _encodeLength(v) + v;
}

/// 解析 TLV 的 length 字段。
///
/// 严格校验 DER 规范：短格式（首字节 < 0x80）；长格式长度字节数最小、
/// 无前导 0、值 < 128 必须用短格式。返回 (值字节数, length 字段字节数)。
(int len, int lenOfL) _parseLength(String str, int start) {
  if (start + 2 > str.length) {
    throw const FormatException('invalid DER: length field truncated');
  }
  final first = int.parse(str.substring(start, start + 2), radix: 16);
  if (first < 0x80) return (first, 1);

  final numBytes = first & 0x7f;
  if (numBytes == 0) {
    throw const FormatException('invalid DER: indefinite length not allowed');
  }
  if (numBytes > 4) {
    throw const FormatException('invalid DER: length too large');
  }
  if (start + 2 + numBytes * 2 > str.length) {
    throw const FormatException('invalid DER: length field truncated');
  }
  final lenHex = str.substring(start + 2, start + 2 + numBytes * 2);
  final len = int.parse(lenHex, radix: 16);
  if (len < 0x80) {
    throw const FormatException(
      'invalid DER: length not minimally encoded (should use short form)',
    );
  }
  if (lenHex.substring(0, 2) == '00') {
    throw const FormatException(
      'invalid DER: length has leading zero byte',
    );
  }
  return (len, 1 + numBytes);
}

/// 解析一个 TLV，返回 (tag, valueHex, nextStart)。
(String tag, String valueHex, int nextStart) _parseTlv(String str, int start) {
  if (start + 2 > str.length) {
    throw const FormatException('invalid DER: tag field truncated');
  }
  final tag = str.substring(start, start + 2);
  final (len, lenOfL) = _parseLength(str, start + 2);
  final valueStart = start + 2 + lenOfL * 2;
  final valueEnd = valueStart + len * 2;
  if (valueEnd > str.length) {
    throw const FormatException('invalid DER: value truncated');
  }
  return (tag, str.substring(valueStart, valueEnd), valueEnd);
}

/// 校验 DER INTEGER 的 value 为最小编码：非空、非负、无多余前导 00。
void _assertMinimalInteger(String valueHex) {
  if (valueHex.isEmpty) {
    throw const FormatException('invalid DER: INTEGER is empty');
  }
  final firstByte = int.parse(valueHex.substring(0, 2), radix: 16);
  if (firstByte & 0x80 != 0) {
    throw const FormatException('invalid DER: INTEGER is negative');
  }
  if (firstByte == 0x00 && valueHex.length > 2) {
    final secondByte = int.parse(valueHex.substring(2, 4), radix: 16);
    if (secondByte & 0x80 == 0) {
      throw const FormatException(
        'invalid DER: INTEGER has non-minimal leading zero',
      );
    }
  }
}

/// 解析 ASN.1 DER 编码的 SM2 签名（js `decodeDer`）。
///
/// 严格校验规范编码，任何违规抛 [FormatException]。
({BigInt r, BigInt s}) decodeDer(String input) {
  if (input.length.isOdd) {
    throw const FormatException(
      'invalid DER: input must be a hex string of even length',
    );
  }

  // 外层 SEQUENCE
  if (input.substring(0, 2) != '30') {
    throw const FormatException('invalid DER: expected SEQUENCE (0x30)');
  }
  final (seqLen, seqLenOfL) = _parseLength(input, 2);
  final seqValueOffset = 2 + seqLenOfL * 2;
  // SEQUENCE 长度必须与剩余输入完全一致（禁止尾部多余字节 / 长度不一致）
  if (seqValueOffset + seqLen * 2 != input.length) {
    throw const FormatException(
      'invalid DER: SEQUENCE length does not match input length',
    );
  }

  // 内部第一个 INTEGER: R
  final (rTag, rValueHex, rNext) = _parseTlv(input, seqValueOffset);
  if (rTag != '02') {
    throw const FormatException('invalid DER: expected INTEGER (0x02) for R');
  }
  _assertMinimalInteger(rValueHex);

  // 内部第二个 INTEGER: S
  final (sTag, sValueHex, sNext) = _parseTlv(input, rNext);
  if (sTag != '02') {
    throw const FormatException('invalid DER: expected INTEGER (0x02) for S');
  }
  _assertMinimalInteger(sValueHex);

  // S 必须刚好到 SEQUENCE 末尾
  if (sNext != input.length) {
    throw const FormatException(
      'invalid DER: trailing bytes inside SEQUENCE',
    );
  }

  return (
    r: rValueHex.isEmpty ? BigInt.zero : BigInt.parse(rValueHex, radix: 16),
    s: sValueHex.isEmpty ? BigInt.zero : BigInt.parse(sValueHex, radix: 16),
  );
}
