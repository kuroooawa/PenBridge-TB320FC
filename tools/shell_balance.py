"""Whole-word structural balance check for the modified shell scripts vs upstream."""
import re
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UP = os.environ.get("PENBRIDGE_UPSTREAM_TREE", os.path.join(ROOT, "upstream", "module-upstream"))
NEW = os.environ.get("PENBRIDGE_MODULE", os.path.join(ROOT, "module"))
WORDS = ["case", "esac", "if", "then", "elif", "else", "fi", "for", "while", "until", "do", "done"]


def counts(path):
    src = open(path, encoding="utf-8").read()
    # strip comments (naive, fine for these files: no '#' inside strings on the same line except URLs)
    lines = []
    for line in src.splitlines():
        idx = line.find("#")
        lines.append(line[:idx] if idx >= 0 else line)
    text = "\n".join(lines)
    return {w: len(re.findall(r"\b%s\b" % w, text)) for w in WORDS}


for name in ["service.sh", "customize.sh", "post-fs-data.sh", "action.sh", "uninstall.sh"]:
    a = counts(os.path.join(UP, name))
    b = counts(os.path.join(NEW, name))
    print("=== %s" % name)
    print("    upstream: case=%d esac=%d if=%d then=%d fi=%d do=%d done=%d for=%d while=%d"
          % (a["case"], a["esac"], a["if"], a["then"], a["fi"], a["do"], a["done"], a["for"], a["while"]))
    print("    build   : case=%d esac=%d if=%d then=%d fi=%d do=%d done=%d for=%d while=%d"
          % (b["case"], b["esac"], b["if"], b["then"], b["fi"], b["do"], b["done"], b["for"], b["while"]))
    ok = (b["case"] == b["esac"] and b["if"] == b["fi"] and b["do"] == b["done"]
          and b["case"] == a["case"] + (2 if name == "service.sh" else 0)
          and b["esac"] == a["esac"] + (2 if name == "service.sh" else 0)
          and b["if"] == a["if"] + (1 if name == "service.sh" else 0)
          and b["fi"] == a["fi"] + (1 if name == "service.sh" else 0))
    print("    balance : case/esac=%s if/fi=%s do/done=%s  %s"
          % (b["case"] == b["esac"], b["if"] == b["fi"], b["do"] == b["done"], "OK" if ok else "CHECK"))
