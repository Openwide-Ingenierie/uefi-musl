#include "Ioctl.h"
#include "File.h"
#include <bits/ioctl.h>
#include "pthread_impl.h"

extern FILE_ENTRY OpenedFiles[MAX_FILE];
extern int errno;

UINT64 __attribute__ ((noinline))
Syscall_Ioctl(UINT64 Fd, UINT64 Cmd, UINT64 Arg)
{
  if(Fd == 1 && Cmd == 0x5413){
    struct winsize* Win = (struct winsize*) Arg;
    // Get the number of row and column of the current console mode 
    UINTN Cols = 0;
    UINTN Rows = 0;
    EFI_STATUS St = gST->ConOut->QueryMode(gST->ConOut,
					   gST->ConOut->Mode->Mode,
					   &Cols, &Rows);
    if(EFI_ERROR(St)){
      Print(L"Cannot get current console mode size: %d\n", St);
      goto error;
    }
    // Get the current resolution of the screen
    EFI_GRAPHICS_OUTPUT_PROTOCOL* Graphics;
    EFI_GUID GuidGraphics = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
    St = gBS->LocateProtocol(&GuidGraphics, NULL, (VOID**) &Graphics);
    if(EFI_ERROR(St)){
      Print(L"Cannot locate graphic protocol : %d\n", St);
      goto error;
    }
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Infos = Graphics->Mode->Info;
    Win->ws_row = Rows;
    Win->ws_col = Cols;
    Win->ws_xpixel = Infos->HorizontalResolution;
    Win->ws_ypixel = Infos->VerticalResolution;
    errno = 0;
    return 0;
  error:
    errno = EIO;
    return -1;
  }
  Print(L"Unsupported IOCTL\n");
  errno = ENOSYS;
  return -1;
}

UINT64
Ioctl_Calls(UINT64 Fd, UINT64 Cmd, UINT64 Arg)
{
  errno = ENOSYS;
  return -1;
}

