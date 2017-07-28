#ifndef IOCTL_H
#define IOCTL_H

#include <Uefi.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <errno.h>

UINT64 Syscall_Ioctl(UINT64, UINT64, UINT64);

UINT64 Ioctl_Calls(UINT64, UINT64, UINT64);

#endif
