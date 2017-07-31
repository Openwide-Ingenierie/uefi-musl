#ifndef MEMORYMAPPING_H
#define MEMORYMAPPING_H

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Uefi/UefiSpec.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <File.h>
#include <MmapList.h>

#include <sys/mman.h>

#define PAGESIZE 4096
#define HEAPRATIO(X) ((X)/2)

UINT64 Syscall_Brk(UINT64);

UINT64 Syscall_Mmap(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64);

UINT64 Syscall_Munmap(UINT64, UINT64);

VOID LibExit(VOID);

/** Internal Functions **/
UINT64 FileSize(EFI_FILE_PROTOCOL*);

VOID SetAttribute(EFI_PHYSICAL_ADDRESS, UINT64);

VOID PrintMap(VOID);

VOID GetMap(EFI_MEMORY_DESCRIPTOR**, UINTN*, UINTN*);

EFI_STATUS AllocateMaxSize(EFI_PHYSICAL_ADDRESS*, EFI_PHYSICAL_ADDRESS*);
/** **/

#endif
