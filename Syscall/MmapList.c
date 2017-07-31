#include "MmapList.h"

static LIST Mapping = {NULL};

static LIST_NODE*
NewNode(EFI_PHYSICAL_ADDRESS Addr,
	UINT64 Fd, UINT64 Offset,
	EFI_FILE_PROTOCOL* File)
{
  LIST_NODE* New = AllocatePool(sizeof(LIST_NODE));
  if(New == NULL){
    return NULL;
  }
  New->Addr = Addr;
  New->Fd = Fd;
  New->Offset = Offset;
  New->File = File;
  New->Next = NULL;
  return New;
}

BOOLEAN
ListAdd(EFI_PHYSICAL_ADDRESS Addr,
	UINT64 Fd, UINT64 Offset,
	EFI_FILE_PROTOCOL* File)
{
  if(ListIsEmpty()){
    Mapping.Head = NewNode(Addr, Fd, Offset, File);
    return TRUE;
  }
  // List is not empty
  LIST_NODE* Head = Mapping.Head;
  for(;;){
    if(Head->Next == NULL && Addr >= Head->Addr){
      if(Addr == Head->Addr){
	// Cannot add the node, the address already exists
	return FALSE;
      } else {
	LIST_NODE* Node = NewNode(Addr, Fd, Offset, File);
	Head->Next = Node;
      }
      return TRUE;
    }
    if(Addr == Head->Addr){
      return FALSE;
    } else if(Addr < Head->Addr){
      LIST_NODE* Node = NewNode(Head->Addr, Head->Fd, Head->Offset, Head->File);
      Node->Next = Head->Next;
      Head->Next = Node;
      Head->Addr = Addr;
      Head->Fd   = Fd;
      Head->Offset = Offset;
      Head->File = File;
      return TRUE;
    }
    Head = Head->Next;
  }
  return FALSE;
}

LIST_NODE*
ListGet(EFI_PHYSICAL_ADDRESS Addr)
{
  LIST_NODE* Head = Mapping.Head;
  while(Head != NULL){
    if(Head->Addr == Addr){
      return Head;
    } else if(Head->Addr > Addr){
      return NULL;
    }
    Head = Head->Next;
  }
  return NULL;
}

BOOLEAN
ListDelete(EFI_PHYSICAL_ADDRESS Addr)
{
  LIST_NODE* Head = Mapping.Head;
  if(Head == NULL){
    return FALSE;
  }
  if(Head->Addr == Addr){
    // The head of the list has to be deleted 
    Mapping.Head = Head->Next;
    FreePool(Head);
    return TRUE;
  }
  for(;;){
    if(Head->Next == NULL){
      return FALSE;
    }
    if(Head->Next->Addr == Addr){
      LIST_NODE* ToDelete = Head->Next;
      Head->Next = Head->Next->Next;
      FreePool(ToDelete);
    }
    Head = Head->Next;
  }
  return FALSE;
}

BOOLEAN
ListIsEmpty(VOID)
{
  return Mapping.Head == NULL;
}

VOID
ListFree(VOID)
{
  LIST_NODE* Head = Mapping.Head;
  while(Head != NULL){
    LIST_NODE* Next = Head->Next;
    FreePool(Head);
    Head = Next;
  }
}
