# tools/

构建与校验脚本。需要 Python 3.9+（仅标准库），`gen_key.ps1` 需要 JDK（`keytool` + `java`）。
所有脚本默认按仓库布局取路径，可用环境变量覆盖（见各脚本头部注释）。

| 脚本 | 作用 |
| --- | --- |
| `gen_key.ps1` | 用 `keytool` 生成自签 RSA 密钥，并用 `KeyExport.java` 导出 `cert.der` / `spki.der` / `params.txt` 到 `build/keys/` |
| `patch_hook.py` | 给上游 `upstream/PenBridge-Hook.apk` 打 4 处 DEX 补丁，重算 DEX 校验和/签名，按 APK Signature Scheme v2 重新签名 → `dist/PenBridge-Hook-v4.1.3-TB320FC.apk`（内置签名自检） |
| `build_module_zip.py` | 把 `dist/` 的 Hook 同步进 `module/hook/`，再按上游条目顺序/压缩方式打包 → `dist/PenBridge-Module-v4.1.3-TB320FC.zip`（内置 ZIP 完整性校验） |
| `verify_dex.py` | 校验 DEX 的 Adler-32 校验和与 SHA-1 签名、4 处补丁落点、字符串表有序性 |
| `validate_digest_algo.py` | 重算 APK v2 内容摘要并与签名块内嵌摘要比对（用于交叉验证摘要算法是否与 `apksigner` 一致） |
| `manifest_dump.py` | 解析二进制 `AndroidManifest.xml`，打印 manifest / uses-sdk / application 属性 |
| `sigblock.py` | 打印 APK Signing Block 的 pair 列表与 v2/v3 signer 结构 |
| `dex_disasm.py` | 极小 DEX 反汇编器：`python dex_disasm.py <类名子串>`、`python dex_disasm.py @refs <字符串子串>`、`python dex_disasm.py @callers <方法名子串>` |
| `dex_map.py` | 打印 DEX 类列表与 map_list |
| `dex_fieldrefs.py` | 查找引用某个字段的代码位置 |
| `diff_module.py` | 与上游模块树逐文件 diff（需先把上游 zip 解到 `upstream/module-upstream/`） |
| `shell_balance.py` | 粗粒度检查 shell 脚本的 `case/esac`、`if/fi`、`do/done` 配平，并与上游对比 |
| `KeyExport.java` | 从 PKCS#12 导出证书 DER / SubjectPublicKeyInfo DER / RSA 参数（`gen_key.ps1` 调用；也可 `java tools/KeyExport.java …` 单独用） |

典型流程：

```bash
pwsh tools/gen_key.ps1
python tools/patch_hook.py
python tools/build_module_zip.py
python tools/verify_dex.py
```
