"""Rebuild kernel.elf (committed, so tests don't need a cross compiler).

Requires: pip install ziglang
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ZIG = [sys.executable, "-m", "ziglang"]
T = ["-target", "x86-freestanding-none"]


def run(*args: str) -> None:
    subprocess.run([*ZIG, *args], check=True, cwd=HERE)


run("cc", *T, "-ffreestanding", "-fno-pie", "-fno-stack-protector", "-O0", "-g",
    "-fno-omit-frame-pointer", "-fno-sanitize=undefined", "-c", "kernel.c", "-o", "kernel.o")
run("cc", *T, "-c", "boot.s", "-o", "boot.o")
run("cc", *T, "-nostdlib", "-static", "-no-pie", "-Wl,-T,linker.ld", "-Wl,--build-id=none",
    "-o", "kernel.elf", "boot.o", "kernel.o")
for f in ("kernel.o", "boot.o"):
    os.remove(os.path.join(HERE, f))
print("built kernel.elf")
