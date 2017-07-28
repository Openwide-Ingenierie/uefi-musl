#include "Time.h"

#include <Uefi.h>
#include <Library/UefiLib.h>

#define HTOS(X) ((X)*60*60)
#define DTOS(X) (HTOS(X)*24)
#define IS_LEAP(X) ((X)%4==0 && (((X)%100 != 0) || ((X)%400 == 0)))

static const short ElapsedDays[] =
  {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};

struct timespec
TimeToTimeSpec(EFI_TIME Time)
{
  UINT64 Seconds = TimeToSeconds(Time);
  struct timespec Ts = {Seconds, 0};
  return Ts;
}

UINT64
TimeToSeconds(EFI_TIME Rtc)
{
  if(Rtc.Year < 1970 ||
     Rtc.Month < 1   ||
     Rtc.Month > 12  ){
    return -1;
  }
     
  UINT64 DaysOfYears = 0, Y = 0;
  for(Y = 1970; Y < Rtc.Year; Y++){
    DaysOfYears += 365 + IS_LEAP(Y);
  }
  if(IS_LEAP(Y) && Rtc.Month > 2){
    ++DaysOfYears;
  }
  UINT64 Month = ElapsedDays[Rtc.Month-1];
  UINT64 Total =
    DTOS((Rtc.Day - 1 + Month)) +
    HTOS(Rtc.Hour) +
    Rtc.Minute * 60 +
    Rtc.Second;
  Total += DTOS(DaysOfYears);
  return Total;
}

UINT64
Syscall_Time(UINT64 Tloc)
{
  time_t* tloc = (time_t*) Tloc;
  EFI_TIME Rtc;
  gRT->GetTime(&Rtc, NULL);

  UINT64 Total = TimeToSeconds(Rtc);

  if(tloc != NULL){
    *tloc = Total;
  }
  return Total;
}
