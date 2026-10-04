# 联想手写笔桥接 — Root 模块（TB320FC / AP501U 构建）

模块 ID：`lenovo_pen_bridge`，作者 ACLaniakea，上游版本 4.1.3。本文档描述本构建相对上游
Release 的差异，完整改动与验证步骤见同目录的 [`TB320FC-PORT-NOTES.md`](TB320FC-PORT-NOTES.md)。

- **生效设备：TB320FC**（联想拯救者 Y700 二代 / Legion Tab）。判定方式是按机型身份属性
  （`ro.product.device` / `ro.product.vendor.device` / `ro.product.model` / `ro.product.name` 等，
  任一包含 `TB320FC` 即通过），不再依赖上游的 `SM8650Q` + `pineapple` SoC 判定。
  目标机型写在 `service.sh` 顶部的 `PEN_TARGET_DEVICE`，换机只改这一行。
- **配套手写笔：联想 AP501U**（商品名 Lenovo Tab Pen Plus，Picasso / LPP+USI2.0）。
  发布给 ColorOS 设置页/设备空间的笔名是 `Lenovo Tab Pen Plus (AP501U)`（`PEN_MODEL_NAME`），
  已配对设备识别关键字包含 `ap501u` / `ap500u` / `tab pen plus` / `picasso`。
- 内置 Hook 副本（`hook/PenBridge-Hook.apk`）的 DEX 已按本机型与笔型打过补丁并**用新密钥
  重新签名**，详见 `TB320FC-PORT-NOTES.md`；独立安装包见构建输出的 `PenBridge-Hook-v4.1.3-TB320FC.apk`。
- Hall/CPS/BLE 状态监控与真实磁吸胶囊广播；
- 开机按已绑定手写笔地址调用原厂 CoreService `CONNECT_PENCIL`，不以磁吸为前提；
- 设置页断开调用 `DISCONNECT_PENCIL`，由配套 Hook 执行真实 GATT 断开；
- `PenHidCtl.apk`（priv-app，无启动器）HID 控制辅助；
- 不监听屏幕状态、不做唤醒回放，状态只跟随真实 Hall/GATT/Root 事件；
  `pen_wakeup_*` 节点只在开机按需写一次；
- 模块内含与独立安装包同签名的 Hook 副本，只用于 LSPosed 的早期稳定读取；不执行 `pm install`、不覆盖 `/data/app`。

作用域：`com.oplus.ipemanager`、`com.heytap.mydevices` 等（见 `scope.list`），由用户手动勾选。
