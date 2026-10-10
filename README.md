# sm_crypto_flutter

[![pub package](https://img.shields.io/pub/v/sm_crypto_flutter.svg)](https://pub.dev/packages/sm_crypto_flutter)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

国密算法 SM2、SM3、SM4 的纯 Dart 实现 —— [sm-crypto](https://github.com/juneandgreen/sm-crypto)（js）
的 Dart 复刻，密文、签名、杂凑与 js 版**双向互操作**（实测通过）。

## 仓库结构

| 路径                                       | 说明                                                            |
| ------------------------------------------ | --------------------------------------------------------------- |
| [`sm_crypto_flutter/`](sm_crypto_flutter)  | 发布到 pub.dev 的纯 Dart 包，用法见其 [README](sm_crypto_flutter/README.md) |
| `docs/plans/`                              | 设计文档（API 映射、关键决策、测试策略）                        |
| `docs/publishing.md`                       | 发布手册（首版手动 + tag 触发自动发布）                         |
| `.github/workflows/`                       | `ci.yml`（analyze / test / publish dry-run）、`publish.yml`（tag → pub.dev） |

## 开发

```bash
cd sm_crypto_flutter
dart pub get
dart analyze
dart test        # 75 项，含与 sm-crypto-js 的互操作向量
```

与 js 版的双向互操作验证需要额外 clone 参考实现（不入库）：

```bash
git clone https://github.com/juneandgreen/sm-crypto sm-crypto-js
cd sm-crypto-js && npm install
```

## 发布

见 [`docs/publishing.md`](docs/publishing.md)。

## 协议

MIT
