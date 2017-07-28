#ifndef NANOSLEEP_H
#define NANOSLEEP_H

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileInfo.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>


UINTN Syscall_Nanosleep(UINTN, UINTN);

#endif
