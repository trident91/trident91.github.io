---
title: House of Botcake
date: 2021-05-14 10:01:07
categories: Notes
tags:
    - ctf
    - pwn
    - heap
---

## House of Botcake
2.27中也可使用, 绕过tcache double free的检测.

- 利用结果: 使malloc返回任意地址
- 要求: 存在double free

#### 利用方式
使用0x100 (chunk size: 0x110)来演示:

1. listTrash = malloc(0x100) * 7
2. prev = malloc(0x100)
3. a = malloc(0x100) # the victim
4. malloc (0x10) #padding
5. free(listTrash[i]) for i in [0,7) # fill up tcachebin
6. free(a)  # free a; a in unsortedbin
7. free(prev) # prev consolidate with a
8. malloc(0x100); # get one chunk from tcache
9. free(a) # free victim again, now it is also in tcachebin
10. malloc(0x120) # 利用重叠申请到prev+victim合并产生的chunk
11. 改写victim的fd
12. malloc(0x100) # BOOM!

### 参考
[https://github.com/shellphish/how2heap/blob/master/glibc_2.31/house_of_botcake.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/house_of_botcake.c)