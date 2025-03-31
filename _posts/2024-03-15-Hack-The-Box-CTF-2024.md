---
published: true
layout: post
category: pwn
tags: HTBCTF-2024
date: 2024-03-15 00:00:00 +0900
excerpt_separator: <!--more-->
title: Hack The Box CTF 2024 Write-up

---
<!--more-->

Playing CTF offline with a foreign team was one of my dreams during the exchange program. Thanks to @vubar for accepting this stranger!

We solved every challenges except 1 web, and ranked 13th. I solved pwn challenges with @meowmeowxw and @verdic and it was a really nice experience to learn from. 

Below is a brief writeup of challenges we solved.

- pwn - Deathnote (medium)
- pwn - Maze of Mist (hard)
- pwn - Oracle (hard)
- pwn - Gloater (insane)



## pwn - deathnote (medium)

---

In menu 42, it gives arbitrary function call with the first parameter control. So we only need libc base to execute `system("/bin/sh")`. Freeing the note does not remove the pointer, so we still have the dangling pointer in the note array. Therefore, by executing `show` function with the freed note will leak the heap / libc base. 

Especially for the libc leak, we have to put a chunk to the unsorted bin. It is done by 8 malloc(0x80) calls and freeing all of them, where 7 frees will fill the tcache and the last freed chunk will be added to unsorted bin.



## pwn - Maze of Mist (hard)

---

A kernel image and a cpio file is give. 

```shell
chmod 0400 /root/flag.txt
chmod u+s /target

hostname arena
echo 0 >/proc/sys/kernel/randomize_va_space
```

`/init` in the extracted file system shows that ASLR is off and `/target` is a root-owned setuid binary.

```c
int vuln()
{
  int v0; // eax
  char addr[32]; // [esp+0h] [ebp-20h] BYREF

  v0 = sys_read(0, addr, 0x200u);
  return 0;
}
```

`/target` is a small 32-bit ELF with BOF, but it is statically linked so we cannot simply rop with libc gadgets. There aren't many usable gadgets in the binary, so the only left secton with the r-x permisson is vdso.

So the leftover process is

1. Dump the vdso section of process running in QEMU
2. Find gadgets to rop with syscall (int 0x80)
3. ROP



### 1. Dump VDSO section of process running in QEMU

It looked trivial to dump or debug process running inside QEMU. I put the statically compiled gdbserver inside the rootfs, and executed QEMU with the host-guest port forwarding option. And by running gdbserver in the guest OS with the forwarded port, I thought I could debug userland process inside QEMU. 

But for some reason, the port forwarding didn't work. So I gave up remote debugging. Instead , @meowmeowxw put statically compiled gdb into the guest and attached to `/target` to dump VDSO.

 

### 2. Find gadgets to rop with syscall (int 0x80)

We already have `int 0x80 ; xor eax, eax ; ret` gadget in the binary. Therefore we only need eax, ebx, ecx, edx control.

```
0x000015cd : pop ebx ; pop esi ; pop ebp ; ret
0x0000057a : pop edx ; pop ecx ; ret

0xf7ffc67e:  add    eax,DWORD PTR [ebp-0x20]
0xf7ffc681:  lea    edx,[ebx+edi*1]
0xf7ffc684:  adc    edx,DWORD PTR [ebp-0x1c]
0xf7ffc687:  add    esp,0x2c
0xf7ffc68a:  pop    ebx
0xf7ffc68b:  and    edx,0x7fffffff
0xf7ffc691:  pop    esi
0xf7ffc692:  pop    edi
0xf7ffc693:  pop    ebp
0xf7ffc694:  ret
```

Every gadget we need exists in the vdso section. However eax control was found manually since gadget tools failed to find one.



### 3. ROP

* We tried `execve("/bin/sh", 0, 0)` but it showed `applet not found error` since the default shell was set to busybox. 
* Therefore we tried `execve("/bin/sh", ["sh"], 0)` and we got a shell. But it didn't have a root permission.
* So we tried `setuid(0) ; execve("/bin/sh", ["sh"], 0)`, but we still failed to get a root shell. (Official write-up says that this would work, so maybe we made some mistake.)
* Finally we tried `setuid(0) ; execve("/bin/cat", ["/bin/cat", "/root/flag.txt"], 0)` and it succeeded.

We also tried `execve("/bin/aa", 0, 0)`, where `aa` is our custom, static binary which opens and prints `/root/flag.txt`. But there wasn't a write permission to the file system so it didn't work. 



## pwn - oracle (hard)

---

### Vulnerability

```c
void parse_headers() {
    // first input all of the header fields
    ssize_t i = 0;
    char byteRead;
    char header_buffer[MAX_HEADER_DATA_SIZE];

    while (1) {
        recv(client_socket, &byteRead, sizeof(byteRead), 0);

        // clean up the headers by removing extraneous newlines
        if (!(byteRead == '\n' && header_buffer[i-1] != '\r'))
            header_buffer[i] = byteRead;

        if (!strncmp(&header_buffer[i-3], "\r\n\r\n", 4)) {
            header_buffer[i-4] == '\0';
            break;
        }

        i++;
    }
```

In the `parse_headers()`, stack bof vuln exists and there is no canary. Therefore we only need libc base to ROP.

```c
void handle_plague() {
    // [...]
    char *plague_content = (char *)malloc(MAX_PLAGUE_CONTENT_SIZE);
    char *plague_target = (char *)0x0;

    long len = strtoul(get_header("Content-Length"), NULL, 10);

    if (len >= MAX_PLAGUE_CONTENT_SIZE) {
        len = MAX_PLAGUE_CONTENT_SIZE-1;
    }

    recv(client_socket, plague_content, len, 0);
    // [...]
    else { 
        dprintf(client_socket, NO_COMPETITOR, target_competitor);

        if (len) {
            write(client_socket, plague_content, len);
            write(client_socket, "\n", 1);
        }
    }

    free(plague_content);

    if (plague_target) {
        free(plague_target);
    }
}
```

There is a uninitialized variable leak vulnerability in `handle_plague()`. 

* It allocates `plague_content` which is sized `MAX_PLAGUE_CONTENT_SIZE`
* It then receives user input to `plague_content` by maximum size `len`. 
* Regardless of the user input length, it returns plague_content by size `len`.

Therefore

1. Trigger `handle_plague()` once. It will allocate `plague_content` and then free it, which will eventually put it into unsorted bin.
2. Trigger `handle_plague` again, and it will allocate `plague_content` from the unsorted bin, which will then have the address of `&main_arena`.  
3. Set the Content-Length longer than 0x8 and send a short input. The response will contain the `&main_arena` address.



### Exploit

With the libc base leak and stack BOF, it is sure that we can get the flag but there are two things to consider.

* First, server-client is connected by socket, not by port forwarding.

So after the exploit, we can not directly `system("/bin/sh")` to get a shell, but execute orw. Also the oracle receives one request per connection. Therefore the exploit consists of three connections.

1. Connection to make uninitialized chunk (socket_fd = 3)
2. Connection to leak libc base from uninitialized chunk (socket_fd = 4)
3. Connection to trigger BOF and orw (socket_fd = 5, flag_fd = 6)

The connections increase the file descriptors of the flag and socket we use in the orw payload (since it doesn't close one after connection), so they are 5 and 6 respectively.

Therefore the 3rd payload should look like below.(in a pseudo-c code)

```c
int socket_fd = 5;
int flag_fd = 6;
char* libc_rw = {writable section of libc};

// write /home/ctf/flag.txt at the libc's writable section
read(socket_fd, libc_rw, 0x100); 
// and then orw with the fds of socket and flag
open(libc_rw, 0, 0);
read(flag_fd, libc_rw, 0x100);
write(socket_fd, libc_rw, 0x100);
```



* Second, we should consider the effects of overwriting stack variable.

```c
char *parse_headers()
{
  char *result; // rax
  char s[1031]; // [rsp+0h] [rbp-430h] BYREF
  char buf; // [rsp+407h] [rbp-29h] BYREF
  char *v3; // [rsp+408h] [rbp-28h]
  char *delim; // [rsp+410h] [rbp-20h]
  __int64 v5; // [rsp+418h] [rbp-18h]
  char *src; // [rsp+420h] [rbp-10h]
  __int64 index; // [rsp+428h] [rbp-8h]
    
  for ( index = 0LL; ; ++index )
  {
    recv(client_socket, &buf, 1uLL, 0);
    if ( buf != '\n' || s[index - 1] == 13 )
      s[index] = buf;
      // [...]
  }
```

Our stack bof in `parse_headers` starts from  `s[1031]` using the `index` variable to access buffer. Before overwriting the return address, it will overwrite `index` which is at the bottom of the stack. If it is overwritten by improper value, we will not be able to overwrite the return address. So handle this to a proper value!

With these considerations, the exploit succeeded to get the flag.



## pwn - gloater (insane)

---

### Vulnerability

#1, #2 : Both `printf("... %s")` in `change_user()` and `set_super_taunt()` doesn't provide null-terminated string, so we leak stack / libc base with them. 

#3 : We also have a buffer overflow in BSS in the `change_user()`, that can overwrite `taunts`.



### Exploit

With the vuln #3, we will overwrite the last 2 bytes of taunts[0] to probabilistically point the fake chunk we can craft by `create_taunt()`. By removing taunts[0] (which will point our fake chunk), it will free two addresses.

* fake chunk we provide
* address written at fake chunk + 32 <= and it's controllable.

Since we can free arbitrary address, we will also write a fake chunk on the stack in advance. We will free it and use the next allocation to overwrite the return address. Writing the fake chunk can also be done by `create_taunt()`. 

In conclusion

1. Modify last 2 bytes of taunts[0] to point the fake chunk we will make in the next steps. 

2. Craft two fake chunks. One on the stack, the other on the heap. It can be crafted by `create_taunt()` at the same time since it writes user input on the stack first and then copy it to heap.
3. Remove taunts[0]. It will free both fake chunks we made.
4. Allocate with size of the stack fake chunk. Fill it with ROP payload. 
5. With 1-2 minute bruteforce, we can get the flag.
