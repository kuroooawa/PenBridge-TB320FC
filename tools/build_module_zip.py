"""Rebuild the KernelSU module zip for the TB320FC build.

Reads the module tree from `module/`, embeds the re-signed Hook APK from `dist/`, and writes
`dist/PenBridge-Module-v4.1.3-TB320FC.zip`.

When the upstream release zip is available in `upstream/`, it is used to reproduce the upstream
entry order / compression method / unix mode exactly; otherwise a built-in default layout is
used (same entries either way).

Environment overrides: PENBRIDGE_MODULE, PENBRIDGE_UPSTREAM_ZIP, PENBRIDGE_OUT_ZIP, PENBRIDGE_DIST.
"""
import hashlib
import os
import shutil
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE = os.environ.get("PENBRIDGE_MODULE", os.path.join(ROOT, "module"))
DIST = os.environ.get("PENBRIDGE_DIST", os.path.join(ROOT, "dist"))
UPSTREAM_ZIP = os.environ.get("PENBRIDGE_UPSTREAM_ZIP",
                             os.path.join(ROOT, "upstream", "PenBridge-Module-v4.1.3.zip"))
OUT_ZIP = os.environ.get("PENBRIDGE_OUT_ZIP",
                         os.path.join(DIST, "PenBridge-Module-v4.1.3-TB320FC.zip"))
HOOK_APK = os.path.join(DIST, "PenBridge-Hook-v4.1.3-TB320FC.apk")

DEFAULT_ORDER = [
    "README.md", "action.sh", "bin/pen-cps-gpio", "customize.sh", "module.prop",
    "post-fs-data.sh", "service.sh",
    "system/etc/permissions/privapp-permissions-com.aclaniakea.penhidctl.xml",
    "system/priv-app/aclpenhid/PenHidCtl.apk", "uninstall.sh",
    "bin/lsposed-path-sync.jar", "hook/PenBridge-Hook.apk",
    "TB320FC-PORT-NOTES.md",
]
STORE_EXT = (".apk", ".jar", ".zip")


def upstream_layout():
    if not os.path.isfile(UPSTREAM_ZIP):
        return None
    with zipfile.ZipFile(UPSTREAM_ZIP) as up:
        return {i.filename: (i.compress_type, i.external_attr) for i in up.infolist()}


def main():
    # keep the module's embedded Hook in sync with the re-signed standalone APK
    if os.path.isfile(HOOK_APK):
        target = os.path.join(MODULE, "hook", "PenBridge-Hook.apk")
        shutil.copyfile(HOOK_APK, target)
        print("module/hook/PenBridge-Hook.apk <- dist/%s" % os.path.basename(HOOK_APK))

    up = upstream_layout()
    if up is None:
        print("upstream zip not found (%s); using the built-in entry layout" % UPSTREAM_ZIP)
        up = {}
        order = list(DEFAULT_ORDER)
    else:
        order = list(up.keys())
        for name in DEFAULT_ORDER:
            if name not in order and os.path.isfile(os.path.join(MODULE, name)):
                order.append(name)

    os.makedirs(DIST, exist_ok=True)
    with zipfile.ZipFile(OUT_ZIP, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as out:
        for name in order:
            src = os.path.join(MODULE, name.replace("/", os.sep))
            with open(src, "rb") as fh:
                data = fh.read()
            if name in up:
                method, attr = up[name]
            else:
                method = (zipfile.ZIP_STORED if name.lower().endswith(STORE_EXT)
                          else zipfile.ZIP_DEFLATED)
                attr = (0o100755 if name.endswith(".sh") else 0o100644) << 16
            zi = zipfile.ZipInfo(name, date_time=(2026, 10, 4, 0, 0, 0))
            zi.compress_type = method
            zi.external_attr = attr
            out.writestr(zi, data)
            print("%-64s method=%d size=%-8d sha256=%s"
                  % (name, method, len(data), hashlib.sha256(data).hexdigest()[:16]))

    print("\nwrote %s (%d bytes)" % (OUT_ZIP, os.path.getsize(OUT_ZIP)))

    with zipfile.ZipFile(OUT_ZIP) as z:
        bad = z.testzip()
        assert bad is None, "zip corrupt at %s" % bad
        names = z.namelist()
        assert names == order, "entry order changed"
        hook = z.read("hook/PenBridge-Hook.apk")
        print("zip entries: %d, testzip clean" % len(names))
        if os.path.isfile(HOOK_APK):
            standalone = open(HOOK_APK, "rb").read()
            print("hook/PenBridge-Hook.apk == dist standalone: %s (%d bytes, sha256 %s)"
                  % (hook == standalone, len(hook), hashlib.sha256(hook).hexdigest()[:32]))


if __name__ == "__main__":
    main()
