#include "Nanosleep.h"
#include <time.h>
#include <errno.h>

UINTN
Syscall_Nanosleep(UINTN Req, UINTN Rem)
{
  struct timespec* TimeReq = (struct timespec*) Req;
  struct timespec* TimeRem = (struct timespec*) Rem;
  
  // Test the given values
  if(TimeReq->tv_sec < 0
     || TimeReq->tv_sec < 0
     || TimeReq->tv_nsec > 999999999){
    errno = EINVAL;
    return -1;
  }

  // Calculate in micros (as Stall takes microseconds)
  UINTN ToSleep =
    (TimeReq->tv_sec * 1000000) +
    (TimeReq->tv_nsec / 1000);
  
  gBS->Stall(ToSleep);

  if(TimeRem != NULL){
    TimeRem->tv_sec = 0;
    TimeRem->tv_nsec = 0;
  }
  
  errno = 0;
  return 0;
}
