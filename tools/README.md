# tools/

构建与校验脚本。需要 Python 3.9+（只用标准库）；`gen_key.ps1` 需要 JDK（`keytool` + `java`）。
所有脚本默认按仓库布局取路径，可用环境变量覆盖（见各脚本头部）。

| 脚本 | 作用 |
| --- | --- |
| `apk_v2.py` | **公共模块**：ZIP/EOCD 访问、APK Signature Scheme v2 签名与自检、`resources.arsc` / manifest 字符串池原地改写、密钥读取 |
| `patch_hook.py` | 给上游 `upstream/PenBridge-Hook.apk` 打 5 处 DEX 补丁 + 改写应用名与说明，重算 DEX 校验和/签名，按 v2 重签 → `dist/PenBridge-Hook-v4.1.3-TB320FC.apk` |
| `patch_penhidctl.py` | 给上游 `upstream/PenHidCtl.apk` 改应用名（manifest 字面量）→ 重打包（条目顺序/压缩方式不变、STORED 条目 4 字节对齐）→ v2 重签 → `dist/PenHidCtl-v4.1.3-TB320FC.apk` |
| `build_module_zip.py` | 把 `dist/` 的 Hook 同步进 `module/hook/`，按上游条目顺序/压缩方式打包 → `dist/PenBridge-Module-v4.1.3-TB320FC.zip` |
| `verify_dex.py` | 校验 DEX 的 Adler-32 校验和与 SHA-1 签名、补丁落点、字符串表有序性 |
| `validate_digest_algo.py` | 重算 v2 内容摘要并与签名块内嵌摘要比对（与 `apksigner` 的算法交叉验证） |
| `manifest_dump.py` | 打印 APK 二进制 manifest 的 package / versionName / uses-sdk 等（检查改名是否生效） |
| `dex_disasm.py` | 小 DEX 反汇编器（排查补丁落点）：`<类名子串>`、`@refs <字符串子串>`、`@callers <方法名子串>` |
| `gen_key.ps1` + `KeyExport.java` | 生成自签 RSA 密钥并导出 `build/keys/{params.txt,cert.der,spki.der}` |

典型流程：

```bash
pwsh tools/gen_key.ps1
python tools/patch_hook.py
python tools/patch_penhidctl.py
python tools/build_module_zip.py
python tools/verify_dex.py
python tools/validate_digest_algo.py dist/PenBridge-Hook-v4.1.3-TB320FC.apk
```

说明：APK 打包/v2 签名的公共代码集中在 `apk_v2.py`，两个 patch 脚本只保留各自的对象差异；
一次性分析脚本（DEX map / 字段引用 / 签名块 dump、上游 diff、shell 配平检查）已移除。
重构后重新构建的产物与重构前逐字节一致（sha256 见根 README）。
