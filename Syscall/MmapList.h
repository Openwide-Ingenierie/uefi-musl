#ifndef MMAPLIST_H
#define MMAPLIST_H

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Uefi/UefiSpec.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileInfo.h>

// (Sorted)List that will store the mapped memory associated with a file descriptor
struct _LIST_NODE {
  EFI_PHYSICAL_ADDRESS Addr;
  // Those two fields are required to check whether the file has been closed between map and unmap
  UINT64 Fd;
  UINT64 Offset;
  EFI_FILE_PROTOCOL* File;
  struct _LIST_NODE* Next;
};

typedef struct _LIST_NODE LIST_NODE;

typedef struct {
  LIST_NODE* Head;
} LIST;


BOOLEAN ListAdd(EFI_PHYSICAL_ADDRESS, UINT64, UINT64, EFI_FILE_PROTOCOL*);
LIST_NODE* ListGet(EFI_PHYSICAL_ADDRESS);
BOOLEAN ListDelete(EFI_PHYSICAL_ADDRESS);
BOOLEAN ListIsEmpty(VOID);
VOID ListFree(VOID);

#endif
