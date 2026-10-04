"""Report the exact differences between the upstream module and this TB320FC build."""
import difflib
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 上游解包目录（把上游 zip 解到 upstream/module-upstream/）
UP = os.environ.get("PENBRIDGE_UPSTREAM_TREE", os.path.join(ROOT, "upstream", "module-upstream"))
NEW = os.environ.get("PENBRIDGE_MODULE", os.path.join(ROOT, "module"))

FILES = ["service.sh", "customize.sh", "module.prop", "README.md"]
KEYWORDS = ["case", "esac", "if", "fi", "do", "done", "while", "for"]

for name in FILES:
    a = open(os.path.join(UP, name), encoding="utf-8").read().splitlines()
    b = open(os.path.join(NEW, name), encoding="utf-8").read().splitlines()
    print("=" * 78)
    print(name, ": %d -> %d lines" % (len(a), len(b)))
    for line in difflib.unified_diff(a, b, lineterm="", n=2, fromfile="upstream/" + name,
                                     tofile="build/" + name):
        print(line)

# crude shell structure balance check for the single edited script
src = open(os.path.join(UP, "service.sh"), encoding="utf-8").read()
dst = open(os.path.join(NEW, "service.sh"), encoding="utf-8").read()
print("=" * 78)
print("service.sh keyword counts (upstream -> build)")
for kw in KEYWORDS:
    cu = sum(1 for line in src.splitlines() if line.strip().startswith(kw + " ") or line.strip() == kw
             or line.strip() in (kw + ")", "esac"))
    cd = sum(1 for line in dst.splitlines() if line.strip().startswith(kw + " ") or line.strip() == kw
             or line.strip() in (kw + ")", "esac"))
    print("   %-6s %3d -> %3d %s" % (kw, cu, cd, "" if cu == cd or kw in ("if", "case", "for", "while") else "  <-- changed"))
