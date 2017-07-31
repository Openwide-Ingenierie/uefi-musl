#include "File.h"

#ifndef QEMU
static int __errno__;

int* __workaround_errno(){
  return &__errno__;
}
#endif

static EFI_GUID fileSystemProtocolGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
static EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* sfsprotocol = NULL;
static EFI_FILE_PROTOCOL* fprotocol = NULL; // Used for opening the disk

/* Table used for associating protocols to a file descriptors (index) */
FILE_ENTRY OpenedFiles[MAX_FILE] = EMPTY_ASSOC;
static UINTN NextFD = 3;

/* Syscall functions */
UINT64
Syscall_Read(UINT64 Fd, UINT64 Buffer, UINT64 Len)
{
  if(fprotocol == NULL){
    EFI_STATUS St = InitStorage();
    if(EFI_ERROR(St)){
      Print(L"Couldn't init storage: %d\n", St);
      errno = EOPNOTSUPP;
      return -1;
    }
  }

  if(INVALID_FD(Fd)){
    errno = EBADF;
    return -1;
  }
  
  EFI_FILE_PROTOCOL* File = OpenedFiles[Fd].File;
  CHAR8* Buffer8 = (CHAR8*) Buffer;

  if(File == STDIN_INDEX){
    static STDIN_BUFFER StdBuffer = { .Read = 0, .FilledSize = 0 };
    UINTN Remaining = (StdBuffer.FilledSize)-(StdBuffer.Read);
    if(Remaining == 0){
      UINT64 Read = ReadLine(StdBuffer.Buffer, PAGE_SIZE);
      StdBuffer.FilledSize = Read;
      StdBuffer.Read = 0;
      Remaining = Read;
    }
    UINTN ToRead = MIN(Len, Remaining);
    Char16ToChar8(StdBuffer.Buffer+StdBuffer.Read,
		  Buffer8,
		  ToRead);
    StdBuffer.Read += ToRead;
    errno = 0;
    return ToRead;
  }
  
  EFI_STATUS St = File->Read(File, &Len, Buffer8);
  if(EFI_ERROR(St)){
    errno = EIO;
    return -1;
  }
  errno = 0;
  return Len;
}

UINT64
Syscall_Write(UINT64 Fd, UINT64 Buffer, UINT64 Len)
{
  // Check whether protocols have already been initialized or not
  if(fprotocol == NULL){
    EFI_STATUS St = InitStorage();
    if(EFI_ERROR(St)){
      Print(L"Couldn't init storage: %d\n", St);
      errno = EOPNOTSUPP;
      return -1;
    }
  }

  // Check the file descriptor
  if(INVALID_FD(Fd)){
    errno = EBADF;
    return -1;
  }

  if(Len == 0){
    errno = 0;
    return 0;
  }
  
  CHAR8* Buffer8 = (CHAR8*) Buffer;
  EFI_FILE_PROTOCOL* File = OpenedFiles[Fd].File;
  if(File == (VOID*) 1 || File == (VOID*) 2){
    // Stderr and Stdout
    CHAR16* Buffer16 = AllocatePool((Len+1)*sizeof(CHAR16));
    Char8ToChar16(Buffer8, Buffer16, Len);
    Buffer16[Len] = 0;
    gST->ConOut->OutputString(gST->ConOut, Buffer16);
    FreePool(Buffer16);
    errno = 0;
    return Len;
  }
  
  EFI_STATUS St = File->Write(File, &Len, Buffer8);
  if(EFI_ERROR(St)){
    errno = EIO;
    return -1;
  }
  errno = 0;
  return Len;
}


UINT64
Syscall_Open(UINT64 Filename, UINT64 Flags, UINT64 Mode)
{
  UINTN Fd = NextFD++;
  if(Fd == MAX_FILE){
    // Search in the array an empty slot
    Fd = LookupFreeFd();
    NextFD--;
    if(Fd == -1){
      errno = EMFILE;
      return -1;
    }
  }
  EFI_FILE_PROTOCOL** File = &OpenedFiles[Fd].File;
  CHAR16* Buffer = GetUEFIString((const char*) Filename);
  UINT64 EFI_Flags = EFI_FILE_MODE_READ;
  if(Flags & ~O_RDONLY){
    EFI_Flags |= EFI_FILE_MODE_WRITE;
  }
  if(Flags & O_CREAT){
    EFI_Flags |= EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE;
  }
  if(Flags & O_TRUNC){
    EFI_Flags |= EFI_FILE_MODE_WRITE;
    // Delete the file if it exists
    EFI_STATUS St = OpenFile(File, Buffer, EFI_Flags, 0);
    if(EFI_ERROR(St)){
      Print(L"Cannot delete the file\n");
    } else {
      (*File)->Delete(*File);
    }
  }
  // FIXME: Test O_APPEND and add a flag in the structure for writing at the end
  
  EFI_STATUS St = OpenFile(File, Buffer, EFI_Flags, 0);
  FreePool(Buffer);
  if(St == EFI_NOT_FOUND){
    Print(L"Cannot open, not found\n");
    errno = ENOENT;
    return -1;
  } else if(EFI_ERROR(St)){
    Print(L"Cannot OpenFile (UEFI protocol): error %d\n", St);
    goto error;
  }
  /*  if(Flags & O_APPEND){
    (*File)->SetPosition(*File, POS_END);
    }*/
  errno = 0;
  return Fd;
 error:
  errno = EIO;
  return -1;
}

UINT64
Syscall_Close(UINT64 Fd)
{
  if(INVALID_FD(Fd)){
    goto badfd;
  }
  EFI_FILE_PROTOCOL* File = OpenedFiles[Fd].File;
  if(File == NULL){
    goto badfd;
  }
  // Check whether the Fd has been duplicated
  for(UINTN i = 3; i < MAX_FILE; i++){
    if(OpenedFiles[i].File == File && i != Fd){
      // Fd duplicated, so we don't need to close the file
      goto setreturn;
    }
  }
  EFI_STATUS St = File->Close(File);
  if(EFI_ERROR(St)){
    errno = EIO;
    return -1;
  }
 setreturn:
  OpenedFiles[Fd].File = NOFILE;
  errno = 0;
  return 0;
 badfd:
  errno = EBADF;
  return -1;
}

VOID
CloseAll(VOID)
{
  for(UINTN i = 3; i < MAX_FILE; i++){
    if(OpenedFiles[i].File != NOFILE){
      Syscall_Close(i);
    }
  }
}

UINT64
Syscall_Stat(UINT64 Path, UINT64 Buf)
{
  EFI_FILE_PROTOCOL* File;
  const char* Name = (const char*) Path;
  struct stat* Status = (struct stat*) Buf;

  CHAR16* UEFIName = GetUEFIString(Name);

  EFI_STATUS St = OpenFile(&File, UEFIName, EFI_FILE_MODE_READ, 0);
  if(EFI_ERROR(St)){
    Print(L"Couldn't get file %s: error %d\n", Name, St);
    FreePool(UEFIName);
    goto error;
  }
  FreePool(UEFIName);

  UINT64 Res = Stat(File, Status);
  File->Close(File);
  return Res;
  
 error:
  errno = EACCES;
  return -1;
}

UINT64
Syscall_Fstat(UINT64 Fd, UINT64 Buf)
{
  if(INVALID_FD(Fd)){
    errno = EBADF;
    return -1;
  }
  
  return Stat(OpenedFiles[Fd].File, (struct stat*) Buf);
}

UINT64
Syscall_Writev(UINT64 Fd, UINT64 Vec, UINT64 Vlen){
  CONST struct iovec *Iov = (CONST struct iovec *) Vec;
  UINTN Written = 0, i, Nb;
  for(i = 0; i < Vlen; i++){
    Nb = Syscall_Write(Fd, (UINT64) Iov[i].iov_base, (UINT64) Iov[i].iov_len);
    if(Nb < 0){
      return Nb;
    }
    Written += Nb;
  }
  errno = 0;
  return Written;
}

UINT64
Syscall_Readv(UINT64 Fd, UINT64 Vec, UINT64 Vlen)
{
  CONST struct iovec *Iov = (CONST struct iovec *) Vec;
  UINTN Read = 0, Nb = 0;
  for(UINTN i = 0; i < Vlen; i++){
    if(Iov[i].iov_len == 0){
      continue;
    }
    Nb = Syscall_Read(Fd, (UINT64) Iov[i].iov_base, (UINT64) Iov[i].iov_len);
    if(Nb < 0){
      return Nb;
    }
    Read += Nb;
    if(Nb < (UINT64) Iov[i].iov_len){
      break;
    }
  }
  errno = 0;
  return Read;
}

UINT64
Syscall_Dup(UINT64 Fd)
{
  if(INVALID_FD(Fd)){
    errno = EBADF;
    return -1;
  }
  UINTN NewFd = LookupFreeFd();
  if(NewFd == -1){
    errno = EMFILE;
    return -1;
  }
  OpenedFiles[NewFd] = OpenedFiles[Fd];
  return NewFd;
}

UINT64
Syscall_Dup2(UINT64 Fd, UINT64 NewFd)
{
  if(INVALID_FD(Fd)){
    errno = EBADF;
    return -1;
  }
  if(Fd == NewFd){
    errno = 0;
    return NewFd;
  }
  if(INVALID_INDEX(NewFd)){
    errno = EBADF;
    return -1;
  }
  if(OpenedFiles[NewFd].File != NOFILE){
    Syscall_Close(NewFd);
  }
  OpenedFiles[NewFd] = OpenedFiles[Fd];
  return NewFd;
}

UINT64
Syscall_Lseek(UINT64 Fd, UINT64 Offset, UINT64 Whence)
{
  int fd = Fd;
  off_t offset = Offset;
  int whence = Whence;

  if(INVALID_FD(fd)){
    errno = EBADF;
    return -1;
  }

  EFI_FILE_PROTOCOL* File = OpenedFiles[Fd].File;
  EFI_STATUS St;
  UINT64 Cur;
  
  if(whence == SEEK_SET){
    St = File->SetPosition(File, offset);
    Cur = offset;
  } else if(whence == SEEK_CUR){
    File->GetPosition(File, &Cur);
    Cur += offset;
    St = File->SetPosition(File, Cur);
  } else if(whence == SEEK_END){
    // Set the cursor at the end (See UEFI Specification)
    File->SetPosition(File, POS_END);
    File->GetPosition(File, &Cur);
    Cur += offset;
    St = File->SetPosition(File, Cur);
  } else {
    errno = EINVAL;
    return -1;
  }

  if(St == EFI_UNSUPPORTED){
    errno = EINVAL;
    return -1;
  }
  
  errno = 0;
  return Cur;
}

UINT64
Syscall_Rename(UINT64 Old, UINT64 New)
{
  EFI_FILE_PROTOCOL* File;
  const char* OldName = (const char*) Old;
  const char* NewName = (const char*) New;

  // Convert char* to CHAR16*
  CHAR16* OldBuffer = GetUEFIString(OldName);
  
  // Open the old file to be able to replace the name
  UINT64 Mode = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE;
  EFI_STATUS St = OpenFile(&File, OldBuffer, Mode, 0);
  if(EFI_ERROR(St)){
    Print(L"Couldn't get file %s: error %d\n", OldBuffer, St);
    FreePool(OldBuffer);
    errno = EACCES;
    return -1;
  }
  FreePool(OldBuffer);

  EFI_GUID Type = EFI_FILE_INFO_ID;
  UINTN Size = sizeof(EFI_FILE_INFO)+PATH_MAX;
  UINT8* BInfo = AllocatePool(Size);
  gBS->SetMem(BInfo, Size, 0);
  St = File->GetInfo(File, &Type, &Size, BInfo);
  if(EFI_ERROR(St)){
    Print(L"Couldn't get file information: error %d\n", St);
    FreePool(BInfo);
    errno = EACCES;
    return -1;
  }

  // Got info of the file, changing its name
  EFI_FILE_INFO* Info = (EFI_FILE_INFO*) BInfo;
  UINTN OldLen = strlen(OldName) + 1;
  UINTN NewLen = strlen(NewName) + 1;
  Char8ToChar16(NewName, Info->FileName, NewLen);
  
  Info->Size = Size - OldLen + NewLen;
  St = File->SetInfo(File, &Type, Size - OldLen + NewLen, BInfo);
  if(EFI_ERROR(St)){
    Print(L"Couldn't get file information: error %d\n", St);
    FreePool(BInfo);
    errno = EACCES;
    return -1;
  }
  
  FreePool(BInfo);
  St = File->Close(File);
  if(EFI_ERROR(St)){
    Print(L"Couldn't close file: error %d\n", St);
    errno = EACCES;
    return -1;
  }
  
  errno = 0;
  return 0;
}

UINT64
Syscall_Unlink(UINT64 Filename)
{
  const char* Pathname = (const char*) Filename;
  CHAR16* Buffer16 = GetUEFIString(Pathname);
  UINT64 EFI_Flags = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE;
  EFI_FILE_PROTOCOL* File = NULL;
  EFI_STATUS St = OpenFile(&File, Buffer16, EFI_Flags, 0);
  if(EFI_ERROR(St)){
    Print(L"Cannot delete the file: %d\n", St);
    FreePool(Buffer16);
    errno = ENOENT;
    return -1;
  }
  // FIXME: We should check whether the file is already opened
  File->Delete(File);
  FreePool(Buffer16);
  errno = 0;
  return 0;
}

UINT64
Syscall_Ftruncate(UINT64 Fd, UINT64 Length)
{
  if(INVALID_FD(Fd)){
    errno = EBADF;
    return -1;
  }

  EFI_FILE_PROTOCOL* File = OpenedFiles[Fd].File;
  return TruncateFile(File, Length);
}

UINT64
Syscall_Truncate(UINT64 Filename, UINT64 Length)
{
  CHAR16* Buffer16 = GetUEFIString((const char*) Filename);
  EFI_FILE_PROTOCOL* File;
  UINT64 EFI_Flags = EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE;
  EFI_STATUS St = OpenFile(&File, Buffer16, EFI_Flags, 0);
  if(EFI_ERROR(St)){
    Print(L"Cannot open the file: %d\n", St);
    FreePool(Buffer16);
    errno = ENOENT;
    return -1;
  }
  // FIXME: Added bytes are not equal to 0
  UINT64 Res = TruncateFile(File, Length);  
  FreePool(Buffer16);
  return Res;
}

UINT64
Syscall_Creat(UINT64 Pathname, UINT64 Mode){
  return Syscall_Open(Pathname, O_CREAT|O_WRONLY|O_TRUNC, Mode);
}

UINT64
Syscall_Pread64(UINT64 Fd, UINT64 Buf, UINT64 Count, UINT64 Off)
{
  return OperateAt(Fd, Buf, Count, Off, Syscall_Read);
}

UINT64
Syscall_Pwrite64(UINT64 Fd, UINT64 Buf, UINT64 Count, UINT64 Off)
{
  return OperateAt(Fd, Buf, Count, Off, Syscall_Write);
}
/** End of syscall functions **/




/** Utils for previous syscalls **/

/* Fonction used to get stats from a file protocol 
   Only few fields of struct stat can be filled */
UINT64
Stat(EFI_FILE_PROTOCOL* File, struct stat* St)
{
  EFI_GUID Type = EFI_FILE_INFO_ID;
  UINTN Size = sizeof(EFI_FILE_INFO)+PATH_MAX;
  UINT8* BInfo = AllocatePool(Size);
  EFI_STATUS Status = File->GetInfo(File, &Type, &Size, BInfo);
  if(EFI_ERROR(Status)){
    Print(L"Couldn't get file information: error %d\n", Status);
    goto error;
  }
  // Set -1 to all fields
  gBS->SetMem(St, sizeof(struct stat), 0xff);

  EFI_FILE_INFO* UefiStat = (EFI_FILE_INFO*) BInfo;
  St->st_size = UefiStat->FileSize;
  St->st_atim = TimeToTimeSpec(UefiStat->LastAccessTime);
  St->st_mtim = TimeToTimeSpec(UefiStat->ModificationTime);
  St->st_ctim = St->st_mtim; // No real permissions on UEFI

  FreePool(BInfo);
  errno = 0;
  return 0;

 error:
  FreePool(BInfo);
  errno = EFAULT;
  return -1;
}

/* Function used to save the offset of a file, 
   call a function and then put back the cursor where it was
   Used for pread and pwrite */
UINT64
OperateAt(UINT64 Fd, UINT64 Buf, UINT64 Count, UINT64 Off,
	  UINT64 (*SyscallToCall)(UINT64, UINT64, UINT64))
{
  if(INVALID_FD(Fd)){
    errno = EBADF;
    return -1;
  }
  EFI_FILE_PROTOCOL* File = OpenedFiles[Fd].File;
  UINT64 OldPosition;
  EFI_STATUS St = File->GetPosition(File, &OldPosition);
  if(EFI_ERROR(St)){
    goto error;
  }
  St = File->SetPosition(File, Off);
  if(EFI_ERROR(St)){
    goto error;
  }
  UINT64 res = SyscallToCall(Fd, Buf, Count);
  File->SetPosition(File, OldPosition);
  return res;
 error:
  errno = EIO;
  return -1;
}

UINT64
TruncateFile(EFI_FILE_PROTOCOL* File, UINT64 Length)
{
  EFI_GUID Type = EFI_FILE_INFO_ID;
  UINTN Size = sizeof(EFI_FILE_INFO)+PATH_MAX;
  UINT8* BInfo = AllocatePool(Size);
  EFI_STATUS St = File->GetInfo(File, &Type, &Size, BInfo);
  if(EFI_ERROR(St)){
    Print(L"Couldn't get file information: error %d\n", St);
    goto error;
  }

  // Got info of the file, changing its name
  EFI_FILE_INFO* Info = (EFI_FILE_INFO*) BInfo;
  Info->FileSize = Length;
  Info->PhysicalSize = Length;
  St = File->SetInfo(File, &Type, Size, BInfo);
  if(EFI_ERROR(St)){
    Print(L"Couldn't get file information: error %d\n", St);
    goto error;
  }

  errno = 0;
  return 0;
 error:
  FreePool(BInfo);
  errno = EACCES;
  return -1;
}

CHAR16* GetUEFIString(const char* Str){
  UINTN Len = strlen(Str) + 1;
  CHAR16* Buffer16 = AllocatePool(Len*sizeof(CHAR16));
  Char8ToChar16(Str, Buffer16, Len);
  return Buffer16;
}

UINTN
LookupFreeFd(VOID)
{
  for(UINTN i = 3; i < MAX_FILE; i++){
    if(OpenedFiles[i].File == NOFILE){
      return i;
    }
  }
  return -1;
}

VOID
Char8ToChar16(CONST CHAR8* Buffer8, CHAR16* Buffer16, UINTN Size)
{
  for(UINTN i = 0; i < Size; i++){
    Buffer16[i] = Buffer8[i];
  }
}

VOID
Char16ToChar8(CONST CHAR16* Buffer16, CHAR8* Buffer8, UINTN Size)
{
  for(UINTN i = 0; i < Size; i++){
    Buffer8[i] = (CHAR8) Buffer16[i];
  }
}

static CHAR16 Spaces[] = {' ', ' ', ' ', ' ', ' ',
			  ' ', ' ', ' ', ' ', ' ',
			  ' ', ' ', ' ', ' ', ' ',
			  ' ', ' ', ' ', ' ', ' ',
			  ' ', ' ', ' ', ' ', ' ',
			  ' ', ' ', ' ', ' ', ' ',
			  ' ', ' ', ' ', ' ', ' ',
			  ' ', ' ', ' ', ' ', ' ', 0};

UINTN
ReadLine(CHAR16* Buffer, UINTN Size)
{
  UINTN EventIndex;
  EFI_INPUT_KEY Key;
  *Buffer = 0;
  UINTN i = 0;
  for(;;){
    gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &EventIndex);
    gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);
    CHAR16 CurChar = Key.UnicodeChar;
    // 0x8 is the code for Delete key
    if(CurChar != 0 && CurChar != DEL_KEY &&
       CurChar != '\r' && CurChar != '\n' &&
       i < Size-2){
      Buffer[i++] = CurChar;
    } else if(CurChar == DEL_KEY) {
      Buffer[--i] = 0;
    } else if (CurChar == '\r' || CurChar == '\n') {
      Buffer[i++] = '\r';
      Buffer[i++] = '\n';
      Print(L"\r\n");
      return i;
    }
    Buffer[i] = 0;
    Print(L"\r%s\r%s", Spaces, Buffer);
  }
  return i;
}

EFI_STATUS
InitStorage()
{
  EFI_STATUS s = gBS->LocateProtocol(&fileSystemProtocolGuid, NULL, (VOID**) &sfsprotocol);
  if( EFI_ERROR(s) ){
    return s;
  }
  s = sfsprotocol->OpenVolume(sfsprotocol, &fprotocol);
  UINTN i;
  for(i = 3; i < MAX_FILE; i++){
    OpenedFiles[i].File  = NOFILE;
    OpenedFiles[i].Ioctl = NULL;
  }
  return s;
}

EFI_STATUS
OpenFile(EFI_FILE_PROTOCOL** prot, CHAR16* filename, UINT64 mode, UINT64 attr)
{
  EFI_STATUS s;
  if(fprotocol == NULL){
    s = InitStorage();
    if(EFI_ERROR(s)){
      return s;
    }
  }
  s = fprotocol->Open(fprotocol, prot, filename, mode, attr);
  return s;
}

EFI_STATUS
GetFileSize(EFI_FILE_PROTOCOL* fd, UINT64* filesize)
{
  UINTN size = 128;
  VOID* buffer = AllocatePool(size);
  EFI_GUID infotype = EFI_FILE_INFO_ID;
  EFI_STATUS s = fd->GetInfo(fd, &infotype, &size, (VOID*) buffer);
  if(EFI_ERROR(s)){
    FreePool(buffer);
    return s;
  }
  *filesize = ((EFI_FILE_INFO*) buffer)->FileSize;
  FreePool(buffer);
  return EFI_SUCCESS;
}
