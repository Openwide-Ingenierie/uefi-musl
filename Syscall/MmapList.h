#ifndef MMAPLIST_H
#define MMAPLIST_H

// List that will store the mapped memory associated with a file descriptor
typedef struct {
  EFI_PHYSICAL_ADDRESS Addr;
  // Those two fields are required to check whether the file has been closed between map and unmap
  UINT64 Fd;
  EFI_FILE_PROTOCOL* File;
} list_node;


#endif
