# PlatformIO extra script for [env:native]: build_flags only reach the compiler, so
# pass the sanitizer (and, when enabled, coverage) flags to the linker as well.
Import("env")  # noqa: F821  (provided by PlatformIO/SCons)

link = [f for f in env.get("BUILD_FLAGS", []) if f.startswith(("-fsanitize", "--coverage"))]  # noqa: F821
env.Append(LINKFLAGS=link)  # noqa: F821
