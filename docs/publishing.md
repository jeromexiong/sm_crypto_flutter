# 发布到 pub.dev

- 包：`sm_crypto_flutter`（目录 `sm_crypto_flutter/`）
- 仓库：https://github.com/jeromexiong/sm_crypto_flutter
- 发布方式：**首版本地手动** + **后续 tag 触发 GitHub Actions 自动发布**（对齐 `identity_verification_flutter`）

> ✅ 链路已验证（2026-10-10）：`0.1.0` 本地手动发布（08:41 UTC）；
> `0.1.1` 由 `git push origin v0.1.1` 触发的 Actions（OIDC）自动发布（08:47 UTC），
> run 全绿——说明 pub.dev 的 repository + tag-pattern 配置与 workflow 对得上。

## 1. 首次发布（必须手动，且只能做一次）

pub.dev 的限制：*自动发布只能用于已存在的包*（“Today, you can only automate publishing of
existing packages. To create a new package, you must publish the first version using
`dart pub publish`.”）。所以首个版本必须在本机交互式发布。

```bash
cd sm_crypto_flutter

# 干跑：检查文件清单、pubspec 字段、LICENSE、description 长度（60~180 字符）
dart pub publish --dry-run

# 正式发布：会打印一个 pub.dev 授权链接，浏览器打开并确认，然后自动上传
dart pub publish
```

发布完成后包地址：https://pub.dev/packages/sm_crypto_flutter

## 2. 打开自动发布（首个版本上线后做一次）

1. 打开 https://pub.dev/packages/sm_crypto_flutter/admin
2. 找到 **Automated publishing** → **Enable publishing from GitHub Actions**
3. Repository 填 `jeromexiong/sm_crypto_flutter`
4. Tag pattern 填 `v{{version}}`
5. （可选，更安全）**Require GitHub Actions environment** 填 `pub.dev`；
   同时在本仓库 Settings → Environments 建同名环境，并在
   `.github/workflows/publish.yml` 的 publish job 上加 `environment: pub.dev`

⚠️ pub.dev 上的 tag-pattern 必须与 `.github/workflows/publish.yml` 里 `on.push.tags`
的模式一致，否则 Actions 即使触发也不会被授权发布。

## 3. 后续版本（自动发布）

```bash
# 1) 改 sm_crypto_flutter/pubspec.yaml 的 version，并在 CHANGELOG.md 补条目
# 2) 提交 + 打 tag（版本号必须与 tag 一致）
git commit -am "chore(release): sm_crypto_flutter v0.1.1"
git tag v0.1.1
git push origin main --tags
```

push tag 后 workflow：`verify-tag`（tag 必须在 main 上）→ `publish`
（`dart-lang/setup-dart` 用 GitHub OIDC 换取 pub 凭据 → `dart pub publish --force`）。
发布结果可在 https://github.com/jeromexiong/sm_crypto_flutter/actions 查看。

## 发布前自检清单

- [ ] `dart analyze` 与 `dart test` 全绿（CI 也会跑）
- [ ] `dart pub publish --dry-run` 无 error
- [ ] `CHANGELOG.md` 有对应版本条目
- [ ] `pubspec.yaml` 的 `version` 与 tag 一致
- [ ] `LICENSE` 在包目录内（pub.dev 强制要求）
- [ ] README 里的版本号/测试数量等描述与实际一致

## 已知约束备忘

- 发布后 **不能撤回或覆盖**同一版本号，只能发布新版本（必要时在 pub.dev 上
  Admin → Retract 标记撤回，但已下载的副本仍可解析）。
- 本包不依赖 Flutter，纯 Dart：CI 只需 `dart`，不需要 `flutter`。
- 本地互操作验证需要外部 clone 的 `sm-crypto-js/`（不入库），与发布无关，
  详见包 README 的「开发与验证」。
