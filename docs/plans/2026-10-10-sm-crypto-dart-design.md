# 用 Dart 复刻 sm-crypto（js）— 设计文档

日期：2026-10-10
状态：已定稿（用户不在场，自主决策；如有异议可按「备选方案」回退）

## 1. 背景与目标

工作区内有两份参考资料：

- `sm-crypto-js/`：国密 SM2/SM3/SM4 的 js 实现（juneandgreen/sm-crypto），是本次复刻的
  **行为基准**。API 为 `sm2.doEncrypt/doDecrypt/doSignature/doVerifySignature`、
  `sm3(msg, {key})`、`sm4.encrypt/decrypt`，全程 hex 串/字节数组进出。
- `gm_crypto/`：已有 Flutter 插件（flutter_sm 副本），纯 Dart 实现了 SM2/SM3/SM4 的
  **核心子集**，可复用其椭圆曲线、SM3、SM4 底层代码，但 API 命名与功能覆盖面均与
  js 版不一致（缺公钥压缩、HMAC、`hash:false` 纯签名、`output:'array'`、
  严格 DER 校验等）。

目标：产出一个**纯 Dart 包 `sm_crypto_flutter`**，API 与语义对齐 sm-crypto-js，
输出与 js 版**可互操作**（同一输入密文/签名/hmac 互通），并以 js 测试向量作为
验收基准。

## 2. 关键决策

| 决策点 | 结论 | 理由 |
|---|---|---|
| 产物形态 | 纯 Dart package（不依赖 Flutter） | 算法无平台通道需求；可同时用于 Flutter / Dart VM / 测试 |
| 落点 | 工作区根下新建 `sm_crypto_flutter/`，`gm_crypto` 不动 | gm_crypto 定位为实现参考；避免破坏其插件结构 |
| API 风格 | 镜像 js 的函数名与选项语义，以 `SM2/SM3/SM4` 静态方法呈现 | 跨端团队可对照 js 文档直接使用；与 gm_crypto 的类风格兼容 |
| 入参形态 | msg/key 接受 `String`（utf8 或 hex 视语义）或 `List<int>` | 忠实镜像 js 的 `string \| Array` 双态入参 |
| options 对象 | js `{hash, der, userId, ...}` → Dart 命名参数 | Dart 惯用法，语义一一对应 |
| 随机源 | `Random.secure()`；`generateKeyPairHex([random])` 保留自定义随机数入口 | js 的 `new BigInteger(a,b,c)` 透传语义收敛为「十进制/十六进制字符串或 BigInt」 |
| 不做 | jsbn `SecureRandom` 类注入（`generateKeyPairHex(256, SecureRandom)`） | YAGNI；Dart 侧无等价生态，安全随机数由 `Random.secure()` 保证 |

### 备选方案（未采纳）

- **改造 gm_crypto**：其 API 命名（`SM2.signature`）与 js 不对齐，且混有 Flutter
  插件壳（android/ios 空实现），改造面大于新建；保留原样作参考价值更高。
- **Flutter 插件包**：算法纯 Dart，平台壳零收益，徒增维护成本。

## 3. API 映射表

| sm-crypto-js | sm_crypto_flutter (Dart) | 说明 |
|---|---|---|
| `sm2.generateKeyPairHex(a?)` | `SM2.generateKeyPairHex([dynamic random])` → `KeyPair` | random 支持十进制字符串/`BigInt`（js 透传 BigInteger 构造器的收敛） |
| `sm2.compressPublicKeyHex(pk)` | `SM2.compressPublicKeyHex(pk)` | 130 位 → 66 位，非法长度抛 `ArgumentError` |
| `sm2.comparePublicKeyHex(a,b)` | `SM2.comparePublicKeyHex(a,b)` | 解压后点等价判断 |
| `sm2.verifyPublicKey(pk)` | `SM2.verifyPublicKey(pk)` | 点在曲线、非无穷远 |
| `sm2.doEncrypt(msg, pk, mode)` | `SM2.doEncrypt(msg, pk, [mode = 1])` | mode 1=C1C3C2，0=C1C2C3；msg 为 String(utf8)/`List<int>`；返回 hex |
| `sm2.doDecrypt(ct, sk, mode, {output})` | `SM2.doDecrypt(ct, sk, [mode = 1], {output = 'string'})` | 失败返回 `''` / `[]`（与 js 一致，不抛异常） |
| `sm2.doSignature(msg, sk, {hash,der,publicKey,userId,pointPool})` | `SM2.doSignature(msg, sk, {hash = true, der = false, publicKey, userId, pointPool})` | `hash:false` 为纯签名 |
| `sm2.doVerifySignature(msg, sig, pk, {hash,der,userId})` | `SM2.doVerifySignature(msg, sig, pk, {hash = true, der = false, userId})` | 非法输入一律 `false` |
| `sm2.getPublicKeyFromPrivateKey(sk)` | `SM2.getPublicKeyFromPrivateKey(sk)` | 返回 `04`+x+y |
| `sm2.getPoint()` | `SM2.getPoint()` → `SM2Point{k, x1, privateKey, publicKey}` | 供 pointPool 加速签名 |
| `sm3(msg)` | `SM3.hash(msg)` | 返回 hex |
| `sm3(msg, {key})` | `SM3.hash(msg, {key})` / `SM3.hmac(msg, key)` | key 为 hex 串或 `List<int>` |
| `sm4.encrypt(msg, key, opts)` | `SM4.encrypt(msg, key, {padding = 'pkcs#7', mode, iv, output = 'string'})` | mode `'cbc'`/其余=ECB；iv/key 为 hex 串或字节 |
| `sm4.decrypt(ct, key, opts)` | `SM4.decrypt(ct, key, {padding = 'pkcs#7', mode, iv, output = 'string'})` | 输出 utf8 串（encrypt 为 hex 串），`output:'array'` 出字节 |

错误语义对齐：`doEncrypt` 非法公钥抛异常；`doDecrypt` 失败静默返回空；
`doVerifySignature` 任何非法输入返回 `false`；`sm4` 参数/填充非法抛
`ArgumentError`（消息与 js 的 `'key is invalid'` 等一致）。

## 4. 架构与文件结构

```
sm_crypto_flutter/
├── pubspec.yaml              # name: sm_crypto_flutter，零运行时依赖
├── analysis_options.yaml
├── README.md                 # 用法 + 与 js 版的 API 对照
├── CHANGELOG.md
├── lib/
│   ├── sm_crypto_flutter.dart # 导出 SM2/SM3/SM4/KeyPair/SM2Point
│   └── src/
│       ├── sm2.dart          # 对外 API：加解密、签名验签、密钥工具
│       ├── sm3.dart          # 杂凑 + HMAC-SM3
│       ├── sm4.dart          # 分组密码：ECB/CBC、pkcs#5/#7/none
│       ├── ec.dart           # GFp 椭圆曲线（点加/倍点/Jacobian、点压缩解压）
│       ├── asn1.dart         # DER 编解码（严格规范校验，防签名延展）
│       └── utils.dart        # hex/utf8/leftPad/常量
└── test/
    ├── sm2_test.dart         # 移植 js test/sm2.test.js 行为用例
    ├── sm3_test.dart         # 移植 js 固定向量
    ├── sm4_test.dart         # 移植 js 固定向量
    └── interop_test.dart     # node 生成的 js↔dart 互操作向量
```

数据流（SM2 加密，与 js 相同）：
`k 随机 → C1=kG → (x2,y2)=kP → C3=SM3(x2‖M‖y2) → t=KDF(x2‖y2) → C2=M⊕t → 按 mode 拼接`。
签名：`e=SM3(Z‖M)（hash:true 时）→ r=(e+x1) mod n → s=(1+dA)⁻¹(k−r·dA) mod n`，
der:true 时对 (r,s) 做 DER SEQUENCE 编码。Z 值 = SM3(ENTL‖UID‖a‖b‖Gx‖Gy‖Px‖Py)。

## 5. 关键实现要点

1. **DER 严格校验**：`decodeDer` 必须复刻 js 的全部拒绝规则——长度字段最小编码、
   INTEGER 无多余前导 00、不接受负数、SEQUENCE 长度与输入严格一致、无尾随字节。
   否则会引入 js 版已修掉的签名可延展性问题。
2. **公钥压缩**：`decodePointHex` 需支持 `02/03` 前缀的 x 奇偶解压
   （`y²=x³+ax+b` 开方：`y = ((x³+ax+b)^((p+1)/4)) mod p`，p≡3 mod 4）。
3. **HMAC-SM3**：块长 64 字节；key > 64 先 SM3；ipad 0x36/opad 0x5c。
4. **KDF 计数器**：`ct` 从 1 起、大端 4 字节、每 32 字节（SM3 输出长）递增。
5. **utf8 边界**：js 对非法 utf8 抛 `Malformed UTF-8 data`；Dart 侧用
   `utf8.decode(..., allowMalformed: false)` 抛 `FormatException`（语义等价，异常类型不同）。
6. **`doSignature(msg, ..., hash:false)`**：e = msg 的 utf8/字节序列按大端整数解释；
   空消息 e=0（jsbn 行为），Dart 需显式处理空 hex。

## 6. 测试策略

1. **固定向量移植**：js `test/sm3.test.js`（含中文/四字节码点/碰撞 case）、
   `test/sm4.test.js`（ECB/CBC、padding、输出形态）全部向量原样移植。
2. **行为移植**：js `test/sm2.test.js` 全部行为断言（往返、压缩公钥、
   非法 c1/r/s/公钥、userId 语义、DER 延展性拒绝）移植为 Dart 测试。
3. **互操作向量**：用 `node` 直接 require `sm-crypto-js/src`（sm3/sm4 无依赖，
   sm2 需 `jsbn`）生成固定输入的期望输出，落地为 `interop_test.dart` 常量。
4. 验收命令：`cd sm_crypto_flutter && dart pub get && dart test`（环境受限时降级为
   自带 mini runner 的 `dart run tool/run_tests.dart`）。

## 7. 与 js 版的已知偏差

| 偏差 | 说明 |
|---|---|
| `generateKeyPairHex(256, SecureRandom)` 不支持 | 随机源收敛为 `Random.secure()` + 可选自定义随机数 |
| `pointPool` 类型为 `List<SM2Point>` | js 为混挂 `k/x1` 的 keypair 对象数组，Dart 用显式类 |
| 异常类型 | js 抛 `Error`，Dart 抛 `ArgumentError`/`FormatException`，消息文本保持一致 |
| `arrayToUtf8` 非法输入 | js 抛 `Error('Malformed UTF-8 data')`，Dart 抛 `FormatException` |
