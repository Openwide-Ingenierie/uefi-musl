#include <MemoryMapping.h>

extern FILE_ENTRY OpenedFiles[MAX_FILE];

static EFI_PHYSICAL_ADDRESS Heap = -1;
static EFI_PHYSICAL_ADDRESS Break = -1;
static EFI_PHYSICAL_ADDRESS End = -1;

/** Function returning the number of pages required to have the
    required space (in byte) **/
static inline UINT64
LenToPages(UINT64 Length)
{
  return (Length/PAGESIZE) + !!(Length%PAGESIZE);
}

UINT64
Syscall_Brk(UINT64 Request)
{
  if(Heap == -1){
    if(EFI_ERROR(AllocateMaxSize(&Heap, &End))){
      goto outofmem;
    }
    Break = Heap;
  }
  
  if(Request == 0){
    return Break;
  }

  if(Break + Request >= End){
    goto outofmem;
  }
 
  Break += Request;

  if(Break < Heap){
    Break = Heap;
  }
  
  errno = 0;
  return 0;
  
 outofmem:
  errno = ENOMEM;
  return -1;
}

UINT64
Syscall_Mmap(UINT64 Addr, UINT64 Len,
	     UINT64 Prot, UINT64 Flags,
	     UINT64 Fd, UINT64 Off)
{
  /* FIXME
     Addr is ignored
     PROT is ignored as there is no memory protection on UEFI
     (memory by default is READ | WRITE | EXEC)
     FLAGS supported are MAP_SHARED (associated with a file) and MAP_ANONYMOUS (MAP_SHARED, as there i no other process running) 
  
  Print(L"mmap(Addr=%p, Len=%lx, PROT=%lx, Flags=%lx, Fd=%lx, Off=%lx)\n",
  Addr, Len, Prot, Flags, Fd, Off);*/
  
  if(Len == 0){
    errno = EINVAL;
    return -1;
  }
  
  // Allocate the number of pages required for mapping
  UINT64 NumPages = LenToPages(Len);
  EFI_PHYSICAL_ADDRESS MmAddr;
  EFI_STATUS St;
  St = gBS->AllocatePages(AllocateAnyPages, EfiLoaderData,
			  NumPages, &MmAddr);

  if(EFI_ERROR(St)){
    errno = ENOMEM;
    return -1;
  }

  // Reset the memory
  gBS->SetMem((VOID*) MmAddr, NumPages*PAGESIZE, 0);

  // Check the flags
  if(Flags & MAP_ANONYMOUS){
    return MmAddr;
  }

  // Associate the memory mapped with a file
  if(INVALID_FD(Fd)){
    gBS->FreePages(MmAddr, NumPages);
    errno = EBADF;
    return -1;
  }

  struct stat stats;
  UINT64 Res = Stat(OpenedFiles[Fd].File, &stats);
  if(Res < 0){
    gBS->FreePages(MmAddr, NumPages);
    return -1;
  }

  UINT64 Size = stats.st_size;
  if(Off >= Size){
    gBS->FreePages(MmAddr, NumPages);
    errno = EINVAL;
    return -1;
  }

  // Calculate how many byte to read from the file
  UINT64 ToRead = MIN(Size-Off, (NumPages*4096));
  UINT64 Read = Syscall_Pread64(Fd, MmAddr, ToRead, Off);
  if(Read < 0){
    gBS->FreePages(MmAddr, NumPages);
    return -1;
  }

  // Add the page and the file descriptor to the global list
  if(!ListAdd(MmAddr, Fd, Off, OpenedFiles[Fd].File)){
    Print(L"Couldn't add the address to MmapList\n");
    gBS->FreePages(MmAddr, NumPages);
    errno = EIO;
    return -1;
  }
  
  return MmAddr;
}

UINT64
Syscall_Munmap(UINT64 Addr, UINT64 Size)
{
  UINT64 NumPages = LenToPages(Size);
  EFI_PHYSICAL_ADDRESS PAddr = (EFI_PHYSICAL_ADDRESS) Addr;
  // Check whether the address is associated to a file
  LIST_NODE* Desc = ListGet(PAddr);
  if(Desc != NULL){
    UINT64 Fd = Desc->Fd;
    EFI_FILE_PROTOCOL* Current = OpenedFiles[Fd].File;
    if(Current == Desc->File){
      /* The file described by the current file descriptor
       * is still the same as the one given to mmap 
       * so we can write back */
      UINT64 Fsize = FileSize(Current);
      UINT64 NumPages = LenToPages(Size);
      UINT64 Offset = Desc->Offset;
      UINT64 ToWrite = MIN(Fsize-Offset, NumPages*4096);
      UINT64 Write = Syscall_Pwrite64(Fd, PAddr, ToWrite, Offset);
      if(Write < 0){
	Print(L"Couldn't write back data to the file\n");
	return -1;
      }
      // Remove the association from the list
      if(!ListDelete(PAddr)){
	Print(L"Error deleting from MmapList\n");
      }
    }
  }
  EFI_STATUS St = gBS->FreePages(PAddr, NumPages);
  if(EFI_ERROR(St)){
    errno = EINVAL;
    return -1;
  }
  return 0;
}

/** Function to get the memory mapping **/
UINT64
FileSize(EFI_FILE_PROTOCOL* File)
{
  struct stat stats;
  UINT64 Res = Stat(File, &stats);
  if(Res < 0){
    return -1;
  }  
  return stats.st_size;
}

VOID
GetMap(EFI_MEMORY_DESCRIPTOR** MemoryMap, UINTN* MemoryMapSize, UINTN* DescriptorSize)
{
  UINTN  EfiMapKey;
  UINT32 EfiDescriptorVersion;
  UINTN EfiMemoryMapSize = 0;
  UINTN EfiDescriptorSize;
  EFI_MEMORY_DESCRIPTOR* EfiMemoryMap;
  EfiMemoryMap = NULL;
  EFI_STATUS Status = gBS->GetMemoryMap (&EfiMemoryMapSize,
                                         EfiMemoryMap,
                                         &EfiMapKey,
                                         &EfiDescriptorSize,
                                         &EfiDescriptorVersion
                                         );
  do {
    EfiMemoryMap = (EFI_MEMORY_DESCRIPTOR *) AllocatePool (EfiMemoryMapSize);
    Status = gBS->GetMemoryMap (&EfiMemoryMapSize,
                                EfiMemoryMap,
                                &EfiMapKey,
                                &EfiDescriptorSize,
                                &EfiDescriptorVersion
                                );
    if (EFI_ERROR (Status)) {
      Print(L"Error %d\n", Status);
      FreePool (EfiMemoryMap);
    }
  } while (Status == EFI_BUFFER_TOO_SMALL);

  *MemoryMap = EfiMemoryMap;
  *MemoryMapSize = EfiMemoryMapSize;
  *DescriptorSize = EfiDescriptorSize;
}

VOID
PrintMap(VOID)
{
  EFI_MEMORY_DESCRIPTOR* Map;
  UINTN MemoryMapSize;
  UINTN DescriptorSize;
  GetMap(&Map, &MemoryMapSize, &DescriptorSize);
  
  UINTN Max = MemoryMapSize/DescriptorSize;
  
  CHAR8* Raw = (CHAR8*) Map;
  for(UINTN i = 0; i < Max; i++){
    EFI_MEMORY_DESCRIPTOR* Current = (EFI_MEMORY_DESCRIPTOR*)
      (Raw+i*DescriptorSize);
    Print(L"%p - %p - (type) %d - #Pages: %d, Attr: %d\n",
	  Current->PhysicalStart,
	  Current->VirtualStart,
	  Current->Type,
	  Current->NumberOfPages,
	  Current->Attribute);
  }
  FreePool(Map);
}

VOID
SetAttribute(EFI_PHYSICAL_ADDRESS Addr, UINT64 Attr)
{
  EFI_MEMORY_DESCRIPTOR* Map;
  UINTN MemoryMapSize;
  UINTN DescriptorSize;
  GetMap(&Map, &MemoryMapSize, &DescriptorSize);
  
  UINTN Max = MemoryMapSize/DescriptorSize;
  
  CHAR8* Raw = (CHAR8*) Map;
  for(UINTN i = 0; i < Max; i++){
    EFI_MEMORY_DESCRIPTOR* Current = (EFI_MEMORY_DESCRIPTOR*)
      (Raw+i*DescriptorSize);
    if(Current->PhysicalStart == Addr)
      Current->Attribute |= Attr;
  }
  FreePool(Map);
}


/** Function allocating the maximum pages possible on the machine
    and returning the address **/
EFI_STATUS
AllocateMaxSize(EFI_PHYSICAL_ADDRESS* Begin, EFI_PHYSICAL_ADDRESS* End)
{
  EFI_MEMORY_DESCRIPTOR* Map;
  UINTN MemoryMapSize;
  UINTN DescriptorSize;
  GetMap(&Map, &MemoryMapSize, &DescriptorSize);
  
  UINTN Max = MemoryMapSize/DescriptorSize;
  UINT64 MaxPages = 0;
  EFI_PHYSICAL_ADDRESS MaxAddr = 0;
  
  CHAR8* Raw = (CHAR8*) Map;
  for(UINTN i = 0; i < Max; i++){
    EFI_MEMORY_DESCRIPTOR* Current = (EFI_MEMORY_DESCRIPTOR*)
      (Raw+i*DescriptorSize);
    if(Current->Type != EfiConventionalMemory)
      continue;
    /*Print(L"%p - %p - %s - #Pages: %d\n",
	  Current->PhysicalStart,
	  Current->VirtualStart,
	  TypeToStr(Current->Type),
	  Current->NumberOfPages);*/
    if(Current->NumberOfPages > MaxPages){
      MaxAddr = Current->PhysicalStart;
      MaxPages = Current->NumberOfPages;
    }
  }
  MaxPages = HEAPRATIO(MaxPages);
  EFI_STATUS St = gBS->AllocatePages(AllocateAddress, EfiLoaderData, MaxPages, &MaxAddr);
  if(EFI_ERROR(St)){
    *Begin = -1;
    *End = -1;
    return St;
  }
  *Begin = MaxAddr;
  *End = MaxAddr + MaxPages * PAGESIZE;
  FreePool(Map);
  return EFI_SUCCESS;
}

VOID
HeapFree(VOID)
{
  gBS->FreePages(Heap, (End-Heap)/PAGESIZE);
  Heap = -1;
  End = -1;
  Break = -1;
}


VOID
LibExit(VOID)
{
  // Close all file descriptors
  CloseAll();
  // Free MMAP list
  ListFree();
  // Free Heap memory
  HeapFree();
}
