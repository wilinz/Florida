#!/usr/bin/env python3
# Florida 后处理 (ELF/Android) — 增强版去特征
# 由 embed-agent.py 在嵌入 agent .so 前调用; 入参为 frida-agent-<flavor>.so
#
# 处理内容:
#   1. 符号: frida_agent_main->main, 含 frida/FRIDA 的符号 -> 随机 (lief)
#   2. .rodata 特征type串倒序: FridaScriptEngine/GLib-GIO/GDBusProxy/GumScript (lief)
#   3. ★增强: 原地等长倒序 "cosmetic 源码路径/断言串"(__FILE__/g_return断言路径), 消除
#      大量 frida/gum/glib/gdbus/gobject 明文(这些串从不被解析, 倒序安全; 是梆梆pn等
#      内存扫描的主要特征面)。纯字节级, 不依赖lief。
#   4. 线程名等长替换: gum-js-loop/gmain/gdbus + pool-frida/pool-spawner (sed -b)
import sys
import random
import os
import re

RCHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def log(msg):
    print(f"\033[1;31;40m{msg}\033[0m")


# ---- 3. cosmetic 字符串原地倒序 (纯字节, 无lief) ----
# 判据: 是源码路径/断言串(含 '/' 且带 .c/.cpp/.h/.vala/.py 或 subprojects/glib 目录),
#   且含特征token。这些是编译器嵌入的 __FILE__ / GLib g_return_if_fail 源路径, 纯cosmetic。
COSMETIC_TOKENS = (b"frida", b"gum", b"Gum", b"GLib", b"glib", b"GDBus",
                   b"gdbus", b"GObject", b"gobject", b"capstone", b"quickjs", b"QuickJS")
PATH_HINT = re.compile(
    rb'(subprojects/|/glib/|\.\./|\.vala|\.cpp|\.cc|\.hpp|\.h\b|\.c\b|\.py\b|-isystem|/frida|frida/)')


def is_cosmetic(s: bytes) -> bool:
    if len(s) < 6 or len(s) > 4000:
        return False
    # 必含特征token
    if not any(t in s for t in COSMETIC_TOKENS):
        return False
    # 排除功能性: D-Bus对象路径 /re/frida, 协议 frida:rpc, GObject type名(裸标识符)
    if b'/re/frida' in s or b'frida:rpc' in s or b're.frida' in s:
        return False
    # 排除格式串(含%, 倒序会破坏printf参数消费→可能崩)
    if b'%' in s:
        return False
    # (a) 源码路径/build串 (__FILE__/断言) — 纯cosmetic
    if PATH_HINT.search(s):
        return True
    # (b) C/C++ 声明签名 (嵌入的gum头/CModule + V8绑定错误签名) — cosmetic(不用CModule就无影响)
    #     判据: 有空格 + 括号/分号/星号(声明特征), 排除裸type名(无空格的单标识符如GumScript)
    if b' ' in s and (b'(' in s or b';' in s or (b'*' in s and b',' in s)):
        return True
    return False


def reverse_cosmetic_strings(path: str) -> int:
    data = bytearray(open(path, "rb").read())
    n = 0
    i = 0
    L = len(data)
    while i < L:
        if 32 <= data[i] < 127:
            j = i
            while j < L and 32 <= data[j] < 127:
                j += 1
            # [i, j) 是可打印串; 要求以 \0 结尾(真C字符串)
            if j < L and data[j] == 0:
                s = bytes(data[i:j])
                if is_cosmetic(s):
                    data[i:j] = s[::-1]
                    n += 1
            i = j + 1
        else:
            i += 1
    open(path, "wb").write(data)
    return n


# ---- 4. 线程/pool 名等长替换 ----
def patch_thread_names(path: str):
    for tag, ln in (("gum-js-loop", 11), ("gmain", 5), ("gdbus", 5),
                    ("pool-frida", 10), ("pool-spawner", 12), ("gdbus-proxy", 11)):
        rnd = "".join(random.sample(RCHARS, ln))
        log(f"[*] thread `{tag}` -> `{rnd}`")
        os.system(f"sed -b -i s/{tag}/{rnd}/g {path}")


if __name__ == "__main__":
    input_file = sys.argv[1]
    log(f"[*] Patch frida-agent (enhanced): {input_file}")

    # 1+2: lief 符号 + type串 (可用则用, 不可用则跳过, 由字节级兜底部分token)
    try:
        import lief
        binary = lief.parse(input_file)
        if binary:
            random_name = "".join(random.sample(RCHARS, 5))
            log(f"[*] symbols `frida` -> `{random_name}`")
            for symbol in binary.symbols:
                if symbol.name == "frida_agent_main":
                    symbol.name = "main"
                if "frida" in symbol.name:
                    symbol.name = symbol.name.replace("frida", random_name)
                if "FRIDA" in symbol.name:
                    symbol.name = symbol.name.replace("FRIDA", random_name)
            for section in binary.sections:
                if section.name != ".rodata":
                    continue
                for patch_str in ["FridaScriptEngine", "GLib-GIO", "GDBusProxy", "GumScript"]:
                    for addr in section.search_all(patch_str):
                        patch = [ord(n) for n in list(patch_str)[::-1]]
                        binary.patch_address(section.file_offset + addr, patch)
            binary.write(input_file)
            log("[*] lief symbol/type patch done")
        else:
            log("[*] Not elf (lief), skip symbol patch")
    except ImportError:
        log("[*] lief not available, skip symbol patch (字节级兜底继续)")
    except Exception as e:
        log(f"[*] lief patch error: {e} (继续字节级)")

    # 3: cosmetic 源码路径/断言串 原地倒序 (纯字节)
    try:
        cnt = reverse_cosmetic_strings(input_file)
        log(f"[*] cosmetic strings reversed: {cnt} (源码路径/断言, 消除frida/gum/glib明文)")
    except Exception as e:
        log(f"[*] cosmetic reverse error: {e}")

    # 4: 线程名
    patch_thread_names(input_file)

    log("[*] Patch Finish (enhanced)")
