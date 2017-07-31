#ifndef FILE_H
#define FILE_H

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileInfo.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include "Time.h"

#include <fcntl.h>
#include <errno.h>
#include <sys/uio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef QEMU
int* __workaround_errno();

#undef errno
 #define errno *(__workaround_errno())
#endif

#define DEL_KEY 0x8

#define PAGE_SIZE 4096
#define PATH_MAX  4096
#define MAX_FILE 1024
#define STDIN_INDEX 0
#define INVALID_FD(X) (((X) < 0 || (X) >= MAX_FILE)	\
			|| (OpenedFiles[(X)].File == NOFILE))
#define INVALID_INDEX(X) ((X) < 0 || (X) >= MAX_FILE)
#define NOFILE ((VOID*) -1)
#define EMPTY_ASSOC {{(VOID*) 0, NULL},		\
		     {(VOID*) 1, NULL},		\
		     {(VOID*) 1, NULL}}
#define POS_END 0xFFFFFFFFFFFFFFFF

typedef UINT64 (*IOCTL_FUNCTION)(UINT64, UINT64, UINT64);

typedef struct {
  EFI_FILE_PROTOCOL* File;
  IOCTL_FUNCTION Ioctl;  
} FILE_ENTRY;

typedef struct {
  CHAR16 Buffer[PAGE_SIZE];
  UINTN Read;
  UINTN FilledSize;
} STDIN_BUFFER;

/* Syscall functions */

UINT64 Syscall_Read(UINT64, UINT64, UINT64);

UINT64 Syscall_Write(UINT64, UINT64, UINT64);

UINT64 Syscall_Open(UINT64, UINT64, UINT64);

UINT64 Syscall_Close(UINT64);

UINT64 Syscall_Stat(UINT64, UINT64);

UINT64 Syscall_Fstat(UINT64, UINT64);

UINT64 Syscall_Writev(UINT64, UINT64, UINT64);

UINT64 Syscall_Readv(UINT64, UINT64, UINT64);

UINT64 Syscall_Dup(UINT64);

UINT64 Syscall_Dup2(UINT64, UINT64);

UINT64 Syscall_Lseek(UINT64, UINT64, UINT64);

UINT64 Syscall_Rename(UINT64, UINT64);

UINT64 Syscall_Unlink(UINT64);

UINT64 Syscall_Ftruncate(UINT64, UINT64);

UINT64 Syscall_Truncate(UINT64, UINT64);

UINT64 Syscall_Creat(UINT64, UINT64);

UINT64 Syscall_Pread64(UINT64, UINT64, UINT64, UINT64);

UINT64 Syscall_Pwrite64(UINT64, UINT64, UINT64, UINT64);

VOID CloseAll(VOID);

/* Utils functions */
UINT64 Stat(EFI_FILE_PROTOCOL*, struct stat*);

UINT64 OperateAt(UINT64, UINT64, UINT64, UINT64,
		 UINT64 (*)(UINT64, UINT64, UINT64));

UINT64 TruncateFile(EFI_FILE_PROTOCOL*, UINT64);

CHAR16* GetUEFIString(const char*);

UINTN LookupFreeFd(VOID);

VOID Char8ToChar16(CONST CHAR8*, CHAR16*, UINTN);

VOID Char16ToChar8(CONST CHAR16*, CHAR8*, UINTN);

UINTN ReadLine(CHAR16*, UINTN);

EFI_STATUS InitStorage();

EFI_STATUS OpenFile(EFI_FILE_PROTOCOL** prot, CHAR16* filename, UINT64 mode, UINT64 attr);

EFI_STATUS Close(EFI_FILE_PROTOCOL* fd);

EFI_STATUS GetFileSize(EFI_FILE_PROTOCOL* fd, UINT64* filesize);

#endif
