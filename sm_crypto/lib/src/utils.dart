/// 与 sm-crypto-js/src/sm2/utils.js 语义对齐的编解码工具。
library;

import 'dart:convert';

/// 左补 `0` 至 [num] 个字符（js `leftPad`）。
String leftPad(String input, int num) {
  if (input.length >= num) return input;
  return '0' * (num - input.length) + input;
}

/// 字节数组转小写 hex 串（js `arrayToHex`）。
String bytesToHex(List<int> arr) {
  final sb = StringBuffer();
  for (final b in arr) {
    sb.write((b & 0xff).toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}

/// hex 串转字节数组（js `hexToArray`）；奇数长度按 js 语义左补一个 `0`。
List<int> hexToBytes(String hexStr) {
  var s = hexStr;
  if (s.length.isOdd) s = '0$s';
  final out = <int>[];
  for (var i = 0; i < s.length; i += 2) {
    out.add(int.parse(s.substring(i, i + 2), radix: 16));
  }
  return out;
}

/// utf8 串转字节数组（js `utf8ToHex` + `hexToArray` 的组合）。
List<int> utf8ToBytes(String input) => utf8.encode(input);

/// 字节数组转 utf8 串（js `arrayToUtf8`）。
///
/// 非法 utf8 输入抛 [FormatException]（js 抛 `Error('Malformed UTF-8 data')`）。
String bytesToUtf8(List<int> arr) => utf8.decode(arr, allowMalformed: false);

/// 统一二进制入参：[String] 按 utf8 编码，[List<int>]（含 `Uint8List`）按字节直通。
///
/// 对应 js 中 `typeof msg === 'string' ? ... : Array.prototype.slice.call(msg)`。
List<int> toBytes(dynamic input) {
  if (input is String) return utf8ToBytes(input);
  if (input is List<int>) return List<int>.from(input);
  throw ArgumentError.value(input, 'input', 'must be String or List<int>');
}
