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
`_IO_FILE_plus`로 정의한 `_IO_2_1_stdout_` 을 `FILE`로 포장한 `stdout`을 stdio.h에서 제공하는 방식이다.





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

vtable은 이렇게 생겼음
