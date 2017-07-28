#ifndef TIME_H
#define TIME_H

#include <time.h>
#include <Library/UefiRuntimeServicesTableLib.h>

struct timespec TimeToTimeSpec(EFI_TIME);

UINT64 TimeToSeconds(EFI_TIME);

UINT64 Syscall_Time(UINT64);

#endif
