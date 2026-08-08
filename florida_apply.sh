#!/usr/bin/env bash
# Florida 反检测改动 — 版本无关的确定性替换 (取代易漂的 git am)
# 用法: ./florida_apply.sh <frida-core-dir>   (即 frida/subprojects/frida-core)
set -u
CORE="${1:?usage: florida_apply.sh <frida-core-dir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"

say() { printf '\033[1;32m[florida]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[florida]\033[0m %s\n' "$*"; }

# 跨平台 in-place sed (字面量替换, 用 perl 避免正则转义地狱)
repl() { # repl <file> <old> <new>
  local f="$1" old="$2" new="$3"
  [ -f "$f" ] || { warn "skip(missing): $f"; return 0; }
  if ! grep -qF -- "$old" "$f"; then
    if grep -qF -- "$new" "$f"; then warn "already: $(basename "$f") <- $old"; return 0; fi
    warn "not found in $(basename "$f"): $old"; return 0
  fi
  OLD="$old" NEW="$new" perl -0777 -i -pe '
    my ($o,$n)=($ENV{OLD},$ENV{NEW});
    my $i=index($_,$o); if($i>=0){ substr($_,$i,length($o))=$n; }
  ' "$f"
  say "patched $(basename "$f"): $old -> $new"
}

# 0001 rpc.vala (字符串藏 base64) — 复用 python
python3 "$HERE/patch_rpc.py" "$CORE/lib/base/rpc.vala" || warn "rpc.vala python patch issue"

# 0003 frida_agent_main -> main  (各平台 host-session + agent-container + test)
for f in src/agent-container.vala src/darwin/darwin-host-session.vala \
         src/freebsd/freebsd-host-session.vala src/linux/linux-host-session.vala \
         src/qnx/qnx-host-session.vala src/windows/windows-host-session.vala \
         tests/test-agent.vala; do
  repl "$CORE/$f" '"frida_agent_main"' '"main"'
done

# 0002 agent .so 随机前缀 (linux)
F="$CORE/src/linux/linux-host-session.vala"
repl "$F" 'agent = new AgentDescriptor (PathTemplate ("frida-agent-<arch>.so"),' \
          'var random_prefix = GLib.Uuid.string_random();
			agent = new AgentDescriptor (PathTemplate (random_prefix + "-<arch>.so"),'
repl "$F" 'new AgentResource ("frida-agent-arm.so", new Bytes.static (emulated_arm.data), tempdir),' \
          'new AgentResource (random_prefix + "-arm.so", new Bytes.static (emulated_arm.data), tempdir),'
repl "$F" 'new AgentResource ("frida-agent-arm64.so", new Bytes.static (emulated_arm64.data), tempdir),' \
          'new AgentResource (random_prefix + "-arm64.so", new Bytes.static (emulated_arm64.data), tempdir),'

# 0006 droidy: 别在意外命令上抛错
repl "$CORE/src/droidy/droidy-client.vala" \
  'throw new Error.PROTOCOL ("Unexpected command");' \
  'break; // throw new Error.PROTOCOL ("Unexpected command");'

# 0008 frida-glue.c: g_set_prgname
F="$CORE/src/frida-glue.c"
if [ -f "$F" ] && ! grep -qF 'g_set_prgname ("ggbond")' "$F"; then
  perl -0777 -i -pe 's/(frida_init_with_runtime \(FridaRuntime rt\)\s*\{)/$1\n    g_set_prgname ("ggbond");\n/' "$F" \
    && say "patched frida-glue.c: g_set_prgname"
else warn "frida-glue.c: skip/already"; fi

# 0009 memfd 名字 -> jit-cache
repl "$CORE/lib/base/linux.vala" \
  'Linux.syscall (LinuxSyscall.MEMFD_CREATE, name, flags)' \
  'Linux.syscall (LinuxSyscall.MEMFD_CREATE, "jit-cache", flags)'

# frida-gum 0001: gum.c g_set_prgname ("frida") -> ("ggbond")
repl "$CORE/../frida-gum/gum/gum.c" 'g_set_prgname ("frida")' 'g_set_prgname ("ggbond")'

# frida-gum 0002: 可执行内存走 memfd("jit-cache") 消除匿名可执行段
#   根治: 梆梆pn等加固扫 /proc/self/maps 找"无文件backing的可执行映射"(匿名rwx/r-x)判定注入。
#   gum 的 trampoline/代码岛默认 MAP_ANONYMOUS mmap 可执行页 = 匿名可执行段 = 被抓。
#   改成 memfd(jit-cache) + MAP_SHARED → 显示为 /memfd:jit-cache(deleted), 混进JIT白名单。
#   注: agent .so 早已memfd化(0009); 此处补 gum 运行时代码分配这块痕迹。
#   用裸 syscall(__NR_memfd_create) 避开 bionic memfd_create 的 __ANDROID_API__>=30 门槛(同0009思路)。
GMEM="$CORE/../frida-gum/gum/backend-posix/gummemory-posix.c"
# (a) 补 sys/syscall.h include (提供 __NR_memfd_create)
repl "$GMEM" \
  '#include <sys/mman.h>' \
  '#include <sys/mman.h>
#include <sys/syscall.h>'
# (b) 可执行页走 memfd
repl "$GMEM" \
  '  result = mmap (address, size, prot, base_flags | region_flags, -1, 0);' \
  '  result = MAP_FAILED;
  if ((prot & PROT_EXEC) != 0)
  {
    int _florida_mfd = (int) syscall (__NR_memfd_create, "jit-cache", 0U);
    if (_florida_mfd != -1)
    {
      if (ftruncate (_florida_mfd, size) == 0)
        result = mmap (address, size, prot,
            (base_flags & ~(MAP_PRIVATE | MAP_ANONYMOUS)) | MAP_SHARED | region_flags,
            _florida_mfd, 0);
      close (_florida_mfd);
    }
  }
  if (result == MAP_FAILED)
    result = mmap (address, size, prot, base_flags | region_flags, -1, 0);'

# anti-anti-frida.py 后处理 (ELF): 放入 frida-core/src 并挂到 embed-agent.py
# 注意: 仅对 ELF 生效 (Android/Linux); macOS(Mach-O) 会 lief 解析后 exit(0) 跳过
cp "$HERE/anti-anti-frida.py" "$CORE/src/anti-anti-frida.py"
say "installed anti-anti-frida.py"

EMBED="$CORE/src/embed-agent.py"
if [ -f "$EMBED" ] && ! grep -qF 'anti-anti-frida.py' "$EMBED"; then
  # 在写出 agent .so 后、其被读取嵌入前插入后处理调用; 用 priv_dir/f"frida-agent-{flavor}.so"
  # 路径相对 embed-agent.py 自身, 不依赖 CI 目录结构
  python3 - "$EMBED" <<'PYEOF'
import sys, re
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
# 锚点: android/linux flavor 循环里 copy 之后 (此时 embedded_agent 已是真实 .so)
anchor = '                shutil.copy(agent, embedded_agent)\n'
hook = (
    '                import os as _os\n'
    '                _aaf = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "anti-anti-frida.py")\n'
    '                _rc = _os.system("python3 " + _aaf + " " + str(embedded_agent))\n'
    '                print("anti-anti-frida finished" if _rc == 0 else f"anti-anti-frida error: {_rc}")\n'
)
if anchor not in s:
    print("[florida] WARN: embed-agent.py anchor not found; anti-anti-frida not hooked", file=sys.stderr)
else:
    s = s.replace(anchor, anchor + hook, 1)
    open(p, "w", encoding="utf-8").write(s)
    print("[florida] hooked anti-anti-frida.py into embed-agent.py")
PYEOF
else
  warn "embed-agent.py: skip/already/missing"
fi

say "done"
