# PenBridge TB320FC / AP501U 构建
本项目全程由deepseek4.1flash构建

把 [ACLaniakea/coloros-pad-fixes](https://github.com/ACLaniakea/coloros-pad-fixes) 发布的
**PenBridge-Module v4.1.3**（联想手写笔桥接 KernelSU 模块 + LSPosed Hook）适配到
**联想拯救者 Y700 二代 / Legion Tab（TB320FC）**，并把配套手写笔型号标定为
**联想 AP501U**（商品名 Lenovo Tab Pen Plus，Picasso / LPP+USI2.0）。

上游模块的生效设备是 **TB710FU（小新 Pad Pro GT，SM8650Q / pineapple）**，与本机不是同一
平台，直接安装会被模块自带的设备门禁挡掉，所以本仓库做了下面的改动。

> 这是**衍生构建**，不是上游官方发布。原始代码作者为 **ACLaniakea**，许可证 GPL-3.0。

## 改了什么

| 项目 | 上游 v4.1.3 | 本构建 |
| --- | --- | --- |
| 生效设备（Root 服务 `service.sh`） | `ro.soc.model` 含 `SM8650Q` 且 `ro.board.platform` 含 `pineapple` | 任一机型身份属性含 `TB320FC`（`ro.product.device` / `ro.product.vendor.device` / `ro.product.model` / `ro.product.name` 等 13 个，空值跳过） |
| 生效设备（Hook `DeviceGate.supported()`） | 同上两条 SoC 判定 | 放开（DEX 内直接返回 true），设备约束交由 Root 服务保证 |
| 手写笔型号 | `Lenovo Tab Pen Pro` | `Lenovo Tab Pen Plus (AP501U)`；识别关键字增加 `ap501u` / `ap500u` / `tab pen plus` / `picasso` |
| Hook 笔卡片标题匹配 | `Lenovo Tab Pen Pro` + `String.equals` | `Lenovo Tab Pen` + `String.contains`（界面显示带 `(AP501U)` 后缀也能命中） |
| Hook 内核 uevent 快照的笔名 | 每次都写 `name=Lenovo Tab Pen Pro` | 不再写笔名字段，笔名统一由 Root 服务发布，避免两个发布方互相覆盖 |
| Hook APK 签名 | 上游作者密钥 | 本构建重新用新密钥按 APK Signature Scheme v2 签名（**安装前必须卸载旧 Hook**） |
| Hook APK 显示名 / 说明 | `联想平板 Pro GT - 手写笔桥接` + 上游说明文案 | `TB320FC - 手写笔桥接 (AP501U)` + TB320FC/AP501U 文案（`resources.arsc` 原地改写） |
| PenHidCtl.apk 应用名 | `联想平板 Pro GT - 手写笔系统服务` | `TB320FC - 手写笔系统服务`（manifest 字面量，重打包 + 重签名；包名不变） |

逐项说明、上机验证命令、已知边界见 [`module/TB320FC-PORT-NOTES.md`](module/TB320FC-PORT-NOTES.md)。

## 目录结构

```
module/                       KernelSU 模块源（service.sh / customize.sh / module.prop / system/ / bin/ / hook/ …）
  hook/PenBridge-Hook-v4.1.3-TB320FC.apk     已打补丁并重签名的 Hook（随模块下发）
  TB320FC-PORT-NOTES.md       改动与验证详情
dist/                         构建产物（可直接安装）
  PenBridge-Module-v4.1.3-TB320FC.zip
  PenBridge-Hook-v4.1.3-TB320FC.apk
tools/                        构建与校验脚本（apk_v2.py 为公共 APK/v2 签名模块；见 tools/README.md）
upstream/                     （不入库）放上游未打补丁的产物，复现构建时用
LICENSE                       GPL-3.0（沿用上游许可）
NOTICE.md                     出处、致谢、第三方材料说明
```

## 安装
**TB320FC 请确认使用卡鱼大佬的 ColorOS 16.0.10.500**

1. **先卸载旧 Hook**（签名换了，不卸载无法覆盖安装）：
   `adb uninstall com.aclaniakea.lenovopenbridge`
2. KernelSU 安装 `dist/PenBridge-Module-v4.1.3-TB320FC.zip`；
3. 安装 `dist/PenBridge-Hook-v4.1.3-TB320FC.apk`；
4. LSPosed 中启用该模块，作用域按 APK 提示勾选：`android`、`com.oplus.ipemanager`、
   `com.heytap.mydevices`、`com.coloros.note`、`com.oplus.exsystemservice`、
   `com.oplus.healthservice`、`com.oplus.wirelesssettings`、`com.oplus.screenshot`；
5. **完整重启**（不要只重启 zygote）。

上机自检：

```bash
adb shell getprop ro.product.device          # 期望能看出 TB320FC
adb shell su -c 'head -5 /data/adb/modules/lenovo_pen_bridge/pen-bridge.log'
# 期望首行： service start device=ro.product.device=TB320FC pen=Lenovo Tab Pen Plus (AP501U)
```

若日志出现 `unsupported device: target=TB320FC`，说明机型属性里没有 `TB320FC`；日志会同时
列出 `ro.product.*` / `ro.soc.model` / `ro.board.platform` 的真实取值，按实际值改
`module/service.sh` 顶部的 `PEN_TARGET_DEVICE`（或属性列表）后重新打包即可。

## 复现构建

```bash
# 0) 准备上游未打补丁的产物（从上游 Release 下载）
#    upstream/PenBridge-Module-v4.1.3.zip
#    upstream/PenBridge-Hook.apk          ← 从上游模块的 hook/ 目录里取出

# 1) 生成签名密钥（自签，仅本模块使用），并导出证书/公钥/RSA 参数
pwsh tools/gen_key.ps1
#    -> build/keys/penbridge-tb320fc.p12（口令 penbridge）、cert.der、spki.der、params.txt

# 2) 给 Hook 打补丁并重新签名
python tools/patch_hook.py
#    -> dist/PenBridge-Hook-v4.1.3-TB320FC.apk（同时打印 4 处补丁与签名自检结果）

# 2b) 给 PenHidCtl 改应用名并重签名（会重打包该 APK，保持条目对齐）
python tools/patch_penhidctl.py
#    -> dist/PenHidCtl-v4.1.3-TB320FC.apk

# 3) 打包模块（会把 dist 的 Hook 同步进 module/hook/ 再打包）
python tools/build_module_zip.py
#    -> dist/PenBridge-Module-v4.1.3-TB320FC.zip
```

`tools/patch_hook.py` 只改 4 处 2 字节指令，不增删、不改动任何 DEX 字符串，因此 APK 内部
布局（条目偏移、压缩方式、`resources.arsc` / `.so` 对齐）与上游完全一致；`AndroidManifest.xml`
逐字节相同。

## 校验

```bash
python tools/verify_dex.py                 # DEX 校验和/签名、4 处补丁落点、字符串表有序性
python tools/validate_digest_algo.py dist/PenBridge-Hook-v4.1.3-TB320FC.apk
                                           # 重算 v2 内容摘要并与签名块内嵌摘要比对
python tools/manifest_dump.py              # 打印 Hook 的 manifest 关键属性
```

`tools/validate_digest_algo.py` 的算法已用真实已签名 APK 交叉验证（上游 Hook 本体 + 另一个
第三方 APK）：重算摘要与它们签名块内嵌摘要逐字节一致，说明分块摘要实现与 `apksigner` 相同
（按「条目内容 / 中央目录 / EOCD（中央目录偏移改为签名块起始）」三段各自分块，块摘要
`SHA256(0xa5 ‖ uint32le(块长) ‖ 块)`，总摘要 `SHA256(0x5a ‖ uint32le(块数) ‖ 各块摘要)`）。

本仓库当前 `dist/` 产物的 SHA-256：

```
PenBridge-Module-v4.1.3-TB320FC.zip   AA83917BF949ACBE023D081806F2309F689FB3F7124AF87F8657A7098C1CD92E
PenBridge-Hook-v4.1.3-TB320FC.apk     61D49B128B9CB49D930B76D579725A2DE278DE609015DD2AE4CBD117EB69E43C
```

## 已知边界（需要上机确认的部分）

- 设备相关节点仍是上游 TB710FU 的路径，本构建没有改也没有自动探测：`/proc/pen_wakeup_mode`、
  `/proc/pen_wakeup_switch`、`/proc/support_pen`、`/sys/devices/virtual/lenovo_penraw/lenovo_penraw/uevent`、
  `/sys/devices/virtual/factory/interface/hw_info/pen1_hall`、`pen2_hall`、
  CPS8601 的 `…/9c0000.qcom,qupv3_i2c_geni_se/98c000.i2c/i2c-2/2-0041/uevent`，
  以及 `bin/pen-cps-gpio` 固定操作的 `/dev/gpiochip0` 第 10、108 号线。脚本对每个节点都有
  可读/可写判断，缺失时只跳过并记日志；若 TB320FC 的移植系统不是同一套节点，按日志给出的
  实际路径改 `service.sh` 顶部常量即可。
- Hook 内的 HID product id 白名单 `{24993, 25134, 24959}` 未改：AP501U 靠名字（`LENOVO_NAMES`）
  已能识别；若实测有漏认，需要补上 AP501U 的 product id。
- Hook 的 `META-INF/` 里保留了上游的 v1（JAR）签名文件，内容已过期；平台在有 v2 签名时按 v2
  校验、不再看 v1（本构建 targetSdk 35，本来就要求 v2+）。若需要 v1 也干净，用 `apksigner`
  配合自备密钥重签即可。
- `PenHidCtl.apk` 的应用名已改，但**它的签名也变了**：包名不变，若设备上装过上游模块，`com.aclaniakea.penhidctl` 的旧签名记录可能让系统忽略该包；处理办法见 [`module/TB320FC-PORT-NOTES.md`](module/TB320FC-PORT-NOTES.md) 第 6 节（`pm uninstall --user 0 com.aclaniakea.penhidctl` 后完整重启）。

## 免责声明与许可

- 刷机、root、安装 LSPosed 模块均有风险，请自行评估并做好备份。
- 代码沿用上游许可 **GPL-3.0**（见 [`LICENSE`](LICENSE)）。本仓库是上游代码的衍生作品，
  版权归原作者及贡献者。
- 分发的二进制里包含上游项目/联想原厂的组件（Hook APK、`PenHidCtl.apk`、`lsposed-path-sync.jar`、
  编译好的 `pen-cps-gpio`），这些材料不因随本仓库分发而改变原有权利归属；请确认自己的
  合法使用范围。详见 [`NOTICE.md`](NOTICE.md)。

## 致谢

- 上游项目 [ACLaniakea/coloros-pad-fixes](https://github.com/ACLaniakea/coloros-pad-fixes)
  与作者 **ACLaniakea**（PenBridge 手写笔桥接模块、LSPosed Hook、`PenHidCtl` 等）。
- 上游工具链与文档中提到的 AOSP `apksig`、LSPosed、KernelSU 项目。
