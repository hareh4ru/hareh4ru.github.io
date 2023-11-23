---
published: false
---
## Introduction

---

glibc 2.34부터 malloc, free hook이 없어지면서 libc leak + AAW가 가능할 때에도 RIP Control이 조금 더 어려워졌다. 

하지만 glibc 2.35 libc leak + AAW가 가능한 상황에서 안정적으로 `system("sh")`가 가능한 FSOP에 대해 알아보자.

FSOP는 FILE 구조체가 어떻게 사용되는지 파악해야 한다. 

## `_IO_FILE` struct

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

fopen에서 반환되는 fp가 가리키는 FILE 구조체는 다음과 같이 생겼다. 


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

`FILE` (=`_IO_FILE`)은 gdb에서 `ptype struct [struct name]` 으로 확인할 수 있다.
stream의 입력, 출력을 위한 여러 멤버 변수들이 존재하는데 필요한 변수에 대해서만 차차 살펴보자.


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

`_IO_2_1_stdout_`은 libio/stdfiles.c에서 정의된다. `_IO_FILE_plus` 자료형으로 선언되며 `_IO_FILE` 내 `chain` 포인터로 `_IO_2_1_stdin_/out_/err_`이 연결되어 있는 것을 확인할 수 있다.


```c
// https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/libioP.h#L324
struct _IO_FILE_plus {
    FILE file;
    const struct _IO_jump_t *vtable;
}
```
`_IO_FILE_plus`는 `FILE` 구조체에 `_IO_jump_t` vtable이 추가된 버전이다. vtable이 어떻게 사용되며 검증되는지는 이후에 다룰 예정이다. 다시 stdout으로 넘어가자.

```c
// https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/stdio.c#L33
FILE *stdin = (FILE *) &_IO_2_1_stdin_;
FILE *stdout = (FILE *) &_IO_2_1_stdout_;
FILE *stderr = (FILE *) &_IO_2_1_stderr_;
```
`stdout`은 libio/stdio.c에서 정의하며, `_IO_2_1_stdout_`을 가리키는 `FILE*`이다.

정리하면 data 영역의 `stdout`은 libc 영역의 `_IO_2_1_stdout_`을 가리키는 `FILE*` (=`_IO_FILE*`) 포인터이다.
실제 `_IO_2_1_stdout_`은 `_IO_FILE` 구조체에 더해 `_IO_jump_t` vtable을 갖고 있다.
`_IO_FILE_plus`로 정의한 `_IO_2_1_stdout_` 을 `FILE`로 포장한 `stdout`으로 포장하여 stdio.h에서 제공하고 있다.


![stdout.png]({{site.baseurl}}/_posts/stdout.png)



## puts로 살펴보는 vtable 사용
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


```c
#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)
#define _IO_XSPUTN(FP, DATA, N) JUMP2 (__xsputn, FP, DATA, N)
#define JUMP2(FUNC, THIS, X1, X2) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS, X1, X2)

#define _IO_JUMPS_FUNC(THIS) (IO_validate_vtable((THIS)))
```
`_IO_sputn` -> `_IO_XSPUTN` -> `JUMP2(__xsputn, ...)` -> `_IO_JUMPS_FUNC(THIS)->__xsputn` 인 것을 확인할 수 있다.
이때 `_IO_JUMPS_FUNC` = `IO_validate_vtable`에서 vtable에 대한 검증이 존재하는 것을 확인할 수 있다.


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
검증은 넘겨준 vtable이 libc의 vtable section 안에 존재해야 한다는 것이다. 이 검증이 없었을 때에는 vtable을 fake table로 바꿔주기만 하면 RCE가 가능했다. 검증에 성공할 경우 인자로 받았던 vtable 포인터를 그대로 반환한다.

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
`_IO_jump_t` vtable은 위와 같이 생겼다. 앞서 실행 흐름을 다시 살펴보면 `_IO_sputn` -> `_IO_XSPUTN` -> `JUMP2(__xsputn, ...)` -> `_IO_JUMPS_FUNC(THIS)->__xsputn`이었다.

puts를 실행할 때 정리해보면 `_IO_2_1_stdout_.vtable->__xsputn`이 호출되는 것이다. 검증을 우회하고 임의 함수를 실행하기 위해 

1. vtable의 주소가 libc의 vtable section 내에 존재하면 된다.
2. `_wide_vtable`을 참조할 때는 검증이 존재하지 않음

위의 두 가지를 이용한다.


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
`_wide_vtable`을 참조하는 루틴 중 하나인 `_IO_WDOALLOCATE`을 살펴보면

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
앞서 살펴본 `io_vtable`의 jump에서 검증을 진행했던 것과 달리 바로 포인터로 캐스팅해주는 것을 확인할 수 있다.

이를 이용해서 FSOP는
1. `_IO_2_1_stdout_.vtable`이 `_wide_vtable`을 가리키도록 한다. (이 포스트에서 다루는 익스의 경우 `_IO_wfile_overflow`를 가리킨다.)  
2. 





