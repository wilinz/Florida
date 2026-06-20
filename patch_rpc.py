#!/usr/bin/env python3
# 替代 0001-Florida-string_frida_rpc.patch: 不依赖行号, 防 frida 文档注释漂移
# 作用: 把 "frida:rpc" 字面量藏成双重 base64 (静态扫描扫不到, 运行时值不变)
import sys

path = sys.argv[1]
src = open(path, encoding="utf-8").read()

method = (
    '\t\tpublic string getRpcStr(bool quote){\n'
    '\t\t\tstring result = (string) GLib.Base64.decode((string) GLib.Base64.decode("Wm5KcFpHRTZjbkJq"));\n'
    '\t\t\tif(quote){\n'
    '\t\t\t\treturn "\\"" + result + "\\"";\n'
    '\t\t\t}else{\n'
    '\t\t\t\treturn result;\n'
    '\t\t\t}\n'
    '\t\t}\n\n'
)

# 锚点: 构造函数结尾 (Object (peer: peer); } ), 之后插入 helper
anchor = '\t\t\tObject (peer: peer);\n\t\t}\n'
assert anchor in src, "constructor anchor not found"
if 'getRpcStr' not in src:
    src = src.replace(anchor, anchor + '\n' + method, 1)

# 3 处字面量替换
repls = [
    ('.add_string_value ("frida:rpc")', '.add_string_value (getRpcStr(false))'),
    ('json.index_of ("\\"frida:rpc\\"")', 'json.index_of (getRpcStr(true))'),
    ('type != "frida:rpc"', 'type != getRpcStr(false)'),
]
for old, new in repls:
    assert old in src, "literal not found: %r" % old
    src = src.replace(old, new, 1)

open(path, "w", encoding="utf-8").write(src)
print("[*] patched rpc.vala (string_frida_rpc) via python")
