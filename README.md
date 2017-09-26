# Musl libc for UEFI

## Introduction
This project is a an alpha version of a `libc` for UEFI. 

The aim of this project is to have a small libc with the most important features, such as file management and memory management. It's not designed to be very powerful nor optimised. This library doesn't provide any driver (for storage for example), it simply uses (U)EFI protocols.

## Compiling this project
To compile this project, you need EDK II, follow the instructions given on their official documentation page which can be find here: https://github.com/tianocore/tianocore.github.io/wiki/Getting-Started-with-EDK-II

## Launching the example

The file `main.c` contains a simple example of how to use the `musl libc`. You simply need to include the headers files required, as you would do in a regular Linux C program, and call the functions a regular `libc`.

After compiling this program, rename the generated `MuslLibC.efi` to `BOOTX64.EFI` and put it on a `FAT16` or `FAT32` USB key in:

`/EFI/BOOT/BOOTX64.EFI`

## How the port was made
Low level functions in the `musl libc` uses the assembly `syscall` instruction to tell the Linux kernel to do an operation. 

To do so, we can find MACROS `__syscallN(...)` (where 0 ≤ N ≤ 7) defined in the file `src/internal/syscall.h`. Those MACROS will be replaced by a assembly routine call called `__syscall` defined in `src/internal/x86_64/syscall.s`.

Thereby, to port this library, we only need to replace the call of assembly `syscall` instruction (contained in `__syscall` subroutine) by another function call that will reproduce the behaviour of this instruction depending on the registers value. That's why our port provides the C function `UefiSyscall(...)` in `Syscall/syscall.c`. The arguments of this function are respectively the values of registers: `rax`, `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`. The first argument, `rax`, determines the operation to reproduce. The whole Linux x64 syscall table can be found here: http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/

The source folder `Syscall` contains code that will reproduce the syscalls. For example, the file `Syscall/File.c` implements syscalls related to file management, such as `open`, `close`, `read`, `write`, etc... (Check header file to see the exhaustive list)

## How to continue implementing syscalls

To add syscall implementation, you only need to create a new .c and .h file in the `Syscall` folder, write your code.
Add a call to your function inside the `UefiSyscall()` matching its id (`rax` value).
Then add your file to the build configuration file, `MuslLibC.inf`, and that's it !

## Why this method of porting ?

Reimplementing syscalls lets us modify the least possible the original library, so updating it won't be a difficult task. Moreover, it will also simplify the portage of any other Linux library, as they also use syscalls for low-level functions call.

## What has been done

Memory and file management has been done on this project which means that you can use the following syscalls (not exhaustive):

**Memory management**

- mmap
- munmap
- brk
- malloc (not a syscall but depends on `brk`)

**File management**

- read
- write
- open
- close
- stat
- fstat
- writev
- readv
- dup
- dup2
- lseek
- rename
- unlink
- ftruncate
- truncate
- creat
- pread64
- pwrite64

Functions in `stdlib` are also functionnal as they don't depend on an syscall.
Functions in `stdio` that works (not exhaustive):
- sprintf
- printf
- fprintf
- putchar
- puts
- fopen
- fclose
- fwrite
- fread
- fgets
- fflush

## Known issues

Setting or reading `errno` can provoke a `Segmentation Fault` on real hardware (in UEFI, it will freeze the computer).

However, in Qemu with OVMF, this problem doesn't exist. A workaround consists in overriding the definition of `errno` for our syscalls implementations.
In that case, `errno` is a simple MACRO dereferencing an empty space in the memory (see `Syscall/File.h`).
By default, the workaround is used for compiling. Adding the building MACRO `-D QEMU` in `MuslLibC.inf` lets us switch back to the original libc errno implementation.

## IMPORTANT NOTE:
- For the moment, this library is **ONLY** compatible with **x86_64** architecture (it contains assembly code)

- This library also provides a function that **MUST** be called before exiting the program: `LibExit()`
This function will free the memory allocated by the library itself but also flush and close the opened file descriptors

