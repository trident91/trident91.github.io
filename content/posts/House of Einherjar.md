---
title: House of Einherjar
date: 2021-05-14 10:04:20
categories: Notes
tags:
    - ctf
    - pwn
    - heap
---

## House Of Einherjar


通过off-by-one/off-by-null, 申请任意地址

- 利用结果: 使malloc返回任意地址
- 要求: 堆泄露, off-by-null
- 适用版本: 本篇记录的是改进版的House of Einherjar, 适用于包括2.31的带tcache版本.

#### 利用方式
总结一下, 会用到三个chunk: a,b,c
- a: 在其中构造fake chunk
- b: victim, 在其中off-by-null溢出到c, 并修改c的prev_size,与fake chunk重叠
- c: 被溢出修改prev_size的chunk

一些细节如下:
- c的chunk大小应为0x100的倍数,这样off-by-null时就不会出问题
- fake_chunk -> size 要等于 c-> prev_size
- fake_chunk -> fd, fake_chunk -> bk 都指向fake_chunk, 以绕过unlink时的检查,也因此需要堆泄露

流程:
1. 申请a,b,c
2. 在B中改写`C->prev_size`, 同时通过OFF-BY-NULL写`C->prev_inuse`为0
3. 填满 `tcache[c -> size]`; 当然,情况允许的话,我们也可以直接申请大于tcache范围的chunk.
4. 释放c, 触发fake_chunk与c的合并
5. 申请fake_chunk+c的chunk, 叫他d
6. 桥豆麻袋! 此处需要先`malloc`并`free`一个b大小的chunk做padding.
7. 释放b
8. 开始攻击(tcache poisoning): 利用d修改 b->fd 为target
9. 申请两次,第二次申请获取到target!

#### 参考
[https://github.com/shellphish/how2heap/blob/master/glibc_2.31/house_of_einherjar.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/house_of_einherjar.c)
