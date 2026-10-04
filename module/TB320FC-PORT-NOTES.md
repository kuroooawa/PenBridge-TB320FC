# TB320FC / AP501U 适配说明（相对上游 PenBridge-Module v4.1.3）

本模块由上游 `PenBridge-Module-v4.1.3.zip`（作者 ACLaniakea，目标设备 TB710FU /
小新 Pad Pro GT / SM8650Q + pineapple）修改而来。本构建把**生效设备改为 TB320FC**
（联想拯救者 Y700 二代 / Legion Tab，SM8475），**配套手写笔型号改为 AP501U**
（商品名 Lenovo Tab Pen Plus，Picasso / LPP+USI2.0）。

---

## 1. 判定"生效设备"的位置与改法

上游有两处硬门禁，本构建两处都改了：

| 位置 | 上游 | 本构建 |
| --- | --- | --- |
| `service.sh`（Root 服务） | `ro.soc.model` 含 `SM8650Q` 且 `ro.board.platform` 含 `pineapple` | 任一 `ro.product.*` 身份属性含 `TB320FC`（见下） |
| `hook/PenBridge-Hook.apk` → `DeviceGate.supported()` | 同上两条 SoC 判定 | 已放开（DEX 层面直接返回 true），设备约束由 Root 服务负责 |

Root 服务检查的属性（空值跳过，大小写不敏感，子串匹配）：

```
ro.product.device            ro.product.vendor.device     ro.product.odm.device
ro.product.product.device    ro.product.system.device     ro.product.system_ext.device
ro.product.model             ro.product.vendor.model      ro.product.odm.model
ro.product.product.model     ro.product.name              ro.product.board
ro.build.product
```

换目标机型只需要改 `service.sh` 顶部的 `PEN_TARGET_DEVICE=TB320FC`。

> 为什么 Hook 里不是同样按机型判定？Hook 是已编译的 APK，其 DEX 字符串表是定长且按内容
> 排序的，无法在不重排整张表的情况下新增 `ro.product.device` / `TB320FC` 这类新字符串。
> 强行改动会破坏 DEX 的字符串有序性（ART 校验风险）。因此 Hook 侧放开，真正的"只在
> TB320FC 上生效"由 Root 服务（`service.sh` 启动即退出，未匹配设备不会做任何事）保证。
> 如果你想自己从源码重编 Hook 并加回机型判定，改 `DeviceGate.supported()` 即可。

## 2. 手写笔型号 AP501U

| 项目 | 上游 | 本构建 |
| --- | --- | --- |
| 状态广播里的笔名（`--es name`） | `Lenovo Tab Pen Pro` | `Lenovo Tab Pen Plus (AP501U)`（`PEN_MODEL_NAME`） |
| 已配对设备识别关键字 | `*pen*` `*stylus*` `*pencil*` `*lenovo*` `*xiaoxin*` `*yoga*` `*picasso*` | 原有关键字全部保留，另加 `ap501u` `ap500u` `tab pen plus` `picasso`（`PEN_MODEL_KEYWORDS`） |
| Hook 里笔卡片标题匹配串 | `Lenovo Tab Pen Pro`（`equals` 精确匹配） | `Lenovo Tab Pen`（`contains` 包含匹配），因此 `Lenovo Tab Pen Plus`、`Lenovo Tab Pen Plus (AP501U)` 都能命中 |
| Hook 里内核 uevent 快照发布的笔名 | 每条 uevent 都写 `name=Lenovo Tab Pen Pro` | 该条 intent 不再写笔名字段，笔名由 Root 服务统一发布，避免两个发布方来回覆盖 |

已配对笔的选择逻辑（`find_bonded_pen_mac` / `resolve_pen_mac`）不变：优先用
`ipe_pencil_mac_addr`，失效时按上述名称规则在 `bt_config.conf` 里挑一支笔并把地址写回。

## 3. Hook APK（`hook/PenBridge-Hook.apk`）的 DEX 补丁

只改 4 处 2 字节指令，不改字符串内容、不增删字符串，APK 布局（各条目偏移、对齐、
压缩方式）与上游完全一致，只更新 ZIP CRC、DEX 校验和/签名，然后按 **APK Signature
Scheme v2** 重新签名：

| # | 类 / 方法 | 改动 |
| --- | --- | --- |
| P1 | `DeviceGate.supported()` | 方法体改为 `const/4 v0, #1; return v0`（门禁放开，见第 1 节） |
| P2 | `CardBatteryHooks.refreshPenCard()` | 卡片标题查找串 `Lenovo Tab Pen Pro` → `Lenovo Tab Pen Plus` |
| P3 | `CardBatteryHooks.collectTextViews()` | `String.equals` → `String.contains`，容忍笔名后的 `(AP501U)` 后缀 |
| P4 | `LenovoPenUEventBridge.onUEvent()` | uevent 快照的 `name` 附加项键名改掉，笔名交由 Root 服务发布 |

### 签名变化（重要）

- 上游 Hook 用的是作者的密钥，无法沿用，本构建用**新生成的密钥**签名：
  `build/keys/penbridge-tb320fc.p12`（storepass / keypass 均为 `penbridge`，别名 `penbridge`，
  RSA 2048，自签，仅用于本模块，不是可信密钥）。
- 因此**必须先卸载旧的 `com.aclaniakea.lenovopenbridge`**，再安装本构建的
  `PenBridge-Hook-v4.1.3-TB320FC.apk`（否则 Android 会因为签名不一致拒绝覆盖安装）。
  模块内 `hook/PenBridge-Hook.apk` 与这个独立安装包是同一份、同一签名。
- `META-INF/` 里上游的 v1（JAR）签名文件保留原样、内容已过期；平台在有 v2 签名时
  按 v2 校验，不再看 v1，属正常现象。若要一份 v1 也干净的重签产物，用你自己的
  `apksigner`（v2/v3）重签即可，例如：
  `apksigner sign --ks penbridge-tb320fc.p12 --ks-pass pass:penbridge --out out.apk in.apk`

## 4. 安装步骤

1. KernelSU 里安装 `PenBridge-Module-v4.1.3-TB320FC.zip`；
2. 卸载旧的手写笔 Hook：`adb uninstall com.aclaniakea.lenovopenbridge`（或在系统设置里卸载）；
3. 安装本构建的 `PenBridge-Hook-v4.1.3-TB320FC.apk`；
4. LSPosed 里启用该模块，作用域按 APK 提示勾选（`android`、`com.oplus.ipemanager`、
   `com.heytap.mydevices`、`com.coloros.note`、`com.oplus.exsystemservice`、
   `com.oplus.healthservice`、`com.oplus.wirelesssettings`、`com.oplus.screenshot`）；
5. **完整重启**（不要只重启 zygote）。

## 5. 上机验证

```bash
# 1) 设备身份（应能看到 TB320FC）
adb shell getprop ro.product.device; adb shell getprop ro.product.model; adb shell getprop ro.product.name

# 2) Root 服务是否认为设备匹配、笔名是否按本构建发布
adb shell su -c 'head -20 /data/adb/modules/lenovo_pen_bridge/pen-bridge.log'
#    期望首行形如： service start device=ro.product.device=TB320FC pen=Lenovo Tab Pen Plus (AP501U)

# 3) 若看到 unsupported device，说明机型属性里没有 TB320FC：
adb shell su -c 'cat /data/adb/modules/lenovo_pen_bridge/pen-bridge.log'
#    此时把日志里列出的真实属性值发出来，改 service.sh 的 PEN_TARGET_DEVICE 或属性列表即可。

# 4) 笔是否被识别（连接后）
adb shell settings get global lenovo_pen_link_connected
adb shell settings get global ipe_pencil_battery_level
adb shell dumpsys bluetooth_manager | grep -i hogp
```

## 6. 已知边界 / 需要你上机确认的点

- **设备相关节点仍是上游 TB710FU 的路径**，本构建没有改也没有自动探测。TB320FC 的
  ColorOS 移植如果不是基于同一套联想 ZUI 内核节点，下面这些路径可能不存在（脚本对每个
  节点都有 `-r`/`-w` 判断，不存在时只是跳过并记日志，不会崩）：
  - `/proc/pen_wakeup_mode`、`/proc/pen_wakeup_switch`、`/proc/support_pen`
  - `/sys/devices/virtual/lenovo_penraw/lenovo_penraw/uevent`
  - `/sys/devices/virtual/factory/interface/hw_info/pen1_hall`、`pen2_hall`
  - CPS8601：`/sys/devices/platform/soc/9c0000.qcom,qupv3_i2c_geni_se/98c000.i2c/i2c-2/2-0041/uevent`
  - `bin/pen-cps-gpio` 固定操作 `/dev/gpiochip0` 的第 10、108 号线
  上机后对着 `pen-bridge.log` 看哪些路径缺失，按实际内核节点改 `service.sh` 顶部常量即可。
- **笔的 HID product id 白名单**（Hook 内 `PenBridgeConstants.LENOVO_PRODUCTS = {24993, 25134, 24959}`）
  没有改：AP501U 的名字落在 `LENOVO_NAMES` 里，按名字即可识别；若实测发现按 product id
  判定的路径漏认，需要改这三个整数（需要先拿到 AP501U 的 HID product id）。
- **笔名显示**：Root 服务发布的笔名是 `Lenovo Tab Pen Plus (AP501U)`；Hook 侧的卡片查找
  已放宽为包含匹配，因此无论界面显示 `Lenovo Tab Pen Plus` 还是带 `(AP501U)` 后缀都能命中。
- `system/priv-app/aclpenhid/` 与 `customize.sh` 里原先写的 `penhidctl` 目录名不一致，
  本构建把脚本里的路径改成实际目录 `aclpenhid`（仅影响安装提示是否打印；priv-app 扫描
  与 `privapp-permissions` 白名单都按包名走，本来就不受影响）。

## 7. 构建产物与可复现性

| 产物 | 说明 |
| --- | --- |
| `PenBridge-Module-v4.1.3-TB320FC.zip` | 完整 KernelSU 模块（含打过补丁并重签名的 Hook 副本） |
| `PenBridge-Hook-v4.1.3-TB320FC.apk` | 独立安装用的 Hook（与模块内副本字节一致） |
| `build/keys/penbridge-tb320fc.p12` | 本次使用的自签名密钥（口令 `penbridge`） |
| `build/patch_hook.py` | 打补丁 + 重签名脚本（含自检） |
| `build/verify_dex.py` | 校验 DEX 校验和/签名、补丁落点、字符串表有序性 |
| `build/validate_digest_algo.py` | 用真实已签名 APK 交叉验证 v2 内容摘要算法 |

`build/patch_hook.py` 的 v2 摘要算法已用两个真实签名 APK 交叉验证（上游 Hook 本体、
另一个第三方 APK）：重算出的内容摘要与它们签名块里内嵌的摘要逐字节一致，说明本脚本的
分块摘要实现与 `apksigner` 相同（按"条目内容 / 中央目录 / EOCD（中央目录偏移改为签名块
起始）"三段分别分块，块摘要 `SHA256(0xa5 || uint32le(块长) || 块)`，总摘要
`SHA256(0x5a || uint32le(块数) || 各块摘要)`）。
