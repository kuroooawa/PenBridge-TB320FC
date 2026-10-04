# 出处、许可与第三方材料

## 上游

- 项目：[ACLaniakea/coloros-pad-fixes](https://github.com/ACLaniakea/coloros-pad-fixes)
  （联想小新 Pad Pro GT / TB710FU / SM8650Q 的 ColorOS 16 移植适配项目）
- 上游产物：`PenBridge-Module-v4.1.3.zip`、`PenBridge-Hook-v4.1.3.apk`、`PenHidCtl-v4.1.3.apk`
- 上游作者：**ACLaniakea**
- 上游许可：GPL-3.0（上游 README「许可证与第三方材料」一节）；内核模块部分为 GPL-2.0

本仓库是上述 PenBridge 手写笔桥接模块的**衍生构建**：把生效设备从 TB710FU 改为 TB320FC，
把配套笔型标定为 AP501U，并对 Hook 的 DEX 做最小改动后重新签名。除下述改动外，模块逻辑、
脚本与二进制均来自上游发布。

## 本仓库相对上游的改动

1. `module/service.sh`
   - 设备门禁：`ro.soc.model` + `ro.board.platform`（SM8650Q / pineapple）→ 机型身份属性包含
     `TB320FC`；新增 `device_matches_target()`，不匹配时把真实属性写进日志并退出。
   - 新增 `PEN_MODEL_NAME` / `PEN_MODEL_KEYWORDS`；状态广播的 `name` 改用
     `Lenovo Tab Pen Plus (AP501U)`；`pen_name_matches()` 增加 `ap501u` 等关键字。
2. `module/customize.sh`
   - 安装提示文案更新为 TB320FC / AP501U；`HIDCTL_APK` 路径由不存在的
     `system/priv-app/penhidctl/` 修正为实际目录 `system/priv-app/aclpenhid/`。
3. `module/module.prop`、`module/README.md`、新增 `module/TB320FC-PORT-NOTES.md`：说明性文案。
4. `module/hook/PenBridge-Hook-v4.1.3-TB320FC.apk`（= `dist/PenBridge-Hook-v4.1.3-TB320FC.apk`）
   - `DeviceGate.supported()` → 恒真（设备约束移到 Root 服务）；
   - `CardBatteryHooks.refreshPenCard()` 的卡片标题查找串 → `Lenovo Tab Pen Plus`；
   - `CardBatteryHooks.collectTextViews()` 的比较由 `String.equals` 改为 `String.contains`；
   - `LenovoPenUEventBridge.onUEvent()` 的 `name` 附加项键名改掉（笔名由 Root 服务发布）；
   - `resources.arsc` 里的应用显示名与模块说明改成 TB320FC/AP501U 文案；
   - 重新按 APK Signature Scheme v2 签名（新自签密钥，未随仓库分发）。
5. `module/system/priv-app/aclpenhid/PenHidCtl-v4.1.3-TB320FC.apk`
   - `AndroidManifest.xml` 的应用名 `联想平板 Pro GT - 手写笔系统服务` → `TB320FC - 手写笔系统服务`（重打包 + 重签名，其余条目与上游逐字节一致）。
   以上均为 2 字节指令级修改，未增删或改写任何 DEX 字符串。

## 第三方 / 原厂材料

仓库与 `dist/` 中包含的二进制来自上游发布或联想原厂运行时，其权利仍归原权利人：

- `module/hook/PenBridge-Hook-v4.1.3-TB320FC.apk`（上游 LSPosed Hook，本仓库改写 DEX 并重签名）
- `module/system/priv-app/aclpenhid/PenHidCtl-v4.1.3-TB320FC.apk`（上游 HID 控制辅助 priv-app，本仓库改了应用名并重签名）
- `module/bin/lsposed-path-sync.jar`（上游 LSPosed 路径同步工具）
- `module/bin/pen-cps-gpio`（上游编译的 CPS GPIO 占位程序）

这些材料**不因随本仓库分发而获得 GPL 再授权**。请在使用/再分发前自行确认合法来源与适用许可，
不要用于绕过设备、账号或服务的安全机制。

## 商标

Lenovo、Legion、拯救者、ColorOS、OPPO、Android 等名称与商标归各自权利人所有；本仓库与上述
公司无关联，也未获其背书。
