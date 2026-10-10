/// 国密算法 SM2、SM3、SM4 的纯 Dart 实现。
///
/// API 与 [sm-crypto](https://github.com/juneandgreen/sm-crypto)（js）对齐，
/// 输出与 js 版可互操作。用法对照见 README。
library sm_crypto_flutter;

export 'src/sm2.dart' show KeyPair, SM2, SM2Point;
export 'src/sm3.dart' show SM3;
export 'src/sm4.dart' show SM4;
