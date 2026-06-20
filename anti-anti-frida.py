#!/usr/bin/env python3
# Florida 后处理 (ELF/Android): 重命名 agent 符号 + 混淆特征字符串/线程名
# 由 embed-agent.py 在嵌入 agent .so 前调用; 入参为 frida-agent-<flavor>.so
import lief
import sys
import random
import os


def log_color(msg):
    print(f"\033[1;31;40m{msg}\033[0m")


if __name__ == "__main__":
    input_file = sys.argv[1]
    random_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    log_color(f"[*] Patch frida-agent: {input_file}")

    binary = lief.parse(input_file)
    if not binary:
        log_color("[*] Not elf, exit")
        sys.exit(0)

    random_name = "".join(random.sample(random_charset, 5))
    log_color(f"[*] Patch `frida` to `{random_name}`")

    for symbol in binary.symbols:
        if symbol.name == "frida_agent_main":
            symbol.name = "main"
        if "frida" in symbol.name:
            symbol.name = symbol.name.replace("frida", random_name)
        if "FRIDA" in symbol.name:
            symbol.name = symbol.name.replace("FRIDA", random_name)

    # 特征字符串: 原地倒序 (长度不变, 静态扫描扫不到原串)
    all_patch_string = ["FridaScriptEngine", "GLib-GIO", "GDBusProxy", "GumScript"]
    for section in binary.sections:
        if section.name != ".rodata":
            continue
        for patch_str in all_patch_string:
            for addr in section.search_all(patch_str):
                patch = [ord(n) for n in list(patch_str)[::-1]]
                log_color(f"[*] Patch .rodata @ {hex(section.file_offset + addr)} {patch_str} -> {''.join(list(patch_str)[::-1])}")
                binary.patch_address(section.file_offset + addr, patch)

    binary.write(input_file)

    # 线程名 (用 GNU sed -b 原地等长替换)
    for tag, n in (("gum-js-loop", 11), ("gmain", 5), ("gdbus", 5)):
        rnd = "".join(random.sample(random_charset, n))
        log_color(f"[*] Patch `{tag}` to `{rnd}`")
        os.system(f"sed -b -i s/{tag}/{rnd}/g {input_file}")

    log_color("[*] Patch Finish")
