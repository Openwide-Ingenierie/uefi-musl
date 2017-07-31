#include <Uefi.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiLib.h>
#include <Library/BaseMemoryLib.h>
#include <Uefi/UefiSpec.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Protocol/GraphicsOutput.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>
#include <MmapList.h>
#include <MemoryMapping.h>

#define BUFSIZE 128

VOID TestStdlib(VOID);
VOID TestStdio(VOID);
VOID TestUnistd(VOID);
VOID GetMemoryMapping(VOID);

EFI_STATUS EFIAPI
UefiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE *SystemTable)
{
  //TestStdlib();
  TestStdio();
  //TestUnistd();
  
  Print(L"\rPress any key to exit...");
  EFI_INPUT_KEY Key;
  UINTN EventIndex;
  gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &EventIndex);
  gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
  return EFI_SUCCESS;
}

VOID
TestExecMemory(VOID){
  UINT8* Fnc = AllocatePool(16);
  /* Code for instructions :
     48 c7 c0 2a 00 00 00   mov %rax, 42
     c3                     ret
  */
  UINT8 Code[] = {0x48, 0xc7, 0xc0, 0x2a, 00, 00, 00, 0xc3};
  for(UINT8 i = 0; i < sizeof(Code); i++){
    Fnc[i] = Code[i];
  }
  UINT64 (*MyFun)(VOID) = (UINT64 (*)(VOID)) Fnc;
  UINT64 Ret = MyFun();
  Print(L"Returned: %ld\n", Ret);
  FreePool(Fnc);
}

VOID
TestUnistd(VOID){
  char Buf[BUFSIZE];
  char Test[] = "Printed with write\r\n";
  write(1, Test, sizeof(Test));
  /* Test open/read/write */

  // Read an existing file
  const char* Filename = "file.txt"; 
  printf("Reading %s\r\n", Filename);
  int fd = open(Filename, O_RDONLY);
  if(fd < 1){
    perror("Couldn't open file");
  }
  Print(L"Print with fd:\n");
  int rd = read(fd, Buf, 5);
  if(rd < 0){
    perror("Error while reading");
  }
  write(1, Buf, rd);
  write(1, "\r\n", 2);
  Print(L"Print with dupped fd:\n");
  // Duplicate file descriptor with dup
  int cpy = dup(fd);
  close(fd);
  rd = read(cpy, Buf, 5);
  if(rd < 0){
    perror("Couldn't read");
  }
  write(1, Buf, rd);
  // Duplicate file descriptor with dup2
  int cpy2 = dup2(cpy, 5);
  close(cpy);
  if(cpy2 < 0){
    perror("Couldn't dup2");
  } else {
    Print(L"\nPrinted with dup2 fd:\n");
    rd = read(cpy2, Buf, BUFSIZE);
    if(rd < 0){
      perror("Couldn't read");
    }
    write(1, Buf, rd);
    //Print(L"Is a tty ? %d\n", isatty(cpy2));
    close(cpy2);
  }

  // Write a new file
  const char* Filename2 = "newfile.txt";
  const char ToWrite[] = "This is the new file created with UEFI\n";
  printf("\rWriting %s\r\n", Filename2);
  int fd2 = open(Filename2, O_RDWR | O_CREAT, 0644);
  if(fd2 < 1){
    perror("\rCouldn't open/create file");
  }
  int wr = write(fd2, ToWrite, sizeof(ToWrite)-1);
  if(wr < 1){
    perror("\rCouldn't write to the new file");
  }
  printf("Written %d bytes\r\n", wr);

  // Modifying the last word
  Print(L"Modifying the last word\n");
  off_t newoff = lseek(fd2, -5, SEEK_END);
  wr = write(fd2, "BLOP", 4);
  lseek(fd2, 0, SEEK_SET);
  write(fd2, "BLOP", 4);
  lseek(fd2, 5, SEEK_CUR);
  write(fd2, "BLOP", 4);
  
  Print(L"New offset: %d, written: %d\n", newoff, wr);
  close(fd2);

  // Read the created file
  printf("Content of %s:\r\n", Filename2);
  fd = open(Filename2, O_RDONLY);
  if(fd < 1){
    perror("Couldn't open file");
  }
  for(;;){
    int rd = read(fd, Buf, BUFSIZE);
    if(rd < 0){
      perror("Error while reading");
    }
    if(rd == 0){
      break;
    }
    write(1, Buf, rd);
  }
  close(fd);

  // Create a file and replace its text wih pwrite
  fd = open("bigfile.txt", O_CREAT | O_RDWR | O_TRUNC, 0644);
  if(fd < 0){
    Print(L"Cannot create file\n");
    return;
  } else {
    Print(L"File created !\n");
  }
  const char content[] = "New file containing data which will be replaced\r\n";
  const char replace[] = "Old";
  write(fd, content, sizeof(content) - 1);
  pwrite(fd, replace, sizeof(replace) - 1, 0);
  write(fd, content, sizeof(content) - 1);

  // Get a file size without opening it
  const char* filename = "file.txt";
  struct stat st;
  if(stat(filename, &st)){
    printf("Cannot stat file %s\r\n", filename);
  } else {
    printf("Size of %s: %ld bytes\r\n", filename, st.st_size);
  }

  
  // Truncate a fuile and rename it
  /*int res = ftruncate(fd, 1024);
  if(res < 0){
    Print(L"Cannot truncate the file\n");
    return;
  }

  Print(L"Truncated !\nLet's rename this file\n");
  res = rename("bigfile.bin", "smallfile.bin");
  if(res < 0){
    Print(L"Couldn't rename the file");
    return;
    }*/
  close(fd);
}

VOID
TestStdio(VOID)
{
  // Test for memset and sprintf
  char Buf[BUFSIZE];
  int Nb = sprintf(Buf, "Generated with sprintf: %d, %f, %s\r\n", 1024, 15.26, "this is a string");
  CHAR16 Buf16[BUFSIZE];
  memset(Buf16, 0, sizeof(CHAR16)*BUFSIZE);
  for(UINT8 i = 0; i <= Nb; i++)
    Buf16[i] = Buf[i];
  gST->ConOut->OutputString(gST->ConOut, Buf16);
  
  // Test printing functions
  const char Printchar[] = "Printed with putchar\r\n";
  for(UINT8 i = 0; i < sizeof(Printchar); i++){
    putchar(Printchar[i]);
  }
  printf("Printed with printf\r\n");
  puts("Printed with puts\r");

  // Test fopen
  printf("Test FILE* structure\r\n");
  FILE* file = fopen("file.txt", "w+");
  if(file == NULL){
    Print(L"Couldn't open file\n");
    return;
  }
  Print(L"File opened !\n");
  /*printf("Content of the file:\r\n");
  fgets(Buf, BUFSIZE-1, file);
  printf("%s\r\n", Buf);*/
  int res = fprintf(file, "This is a string written with function fprintf\n");
  if(res < 0) Print(L"Error with fprintf\n");

  res = fflush(file);
  if(res < 0) Print(L"Error with fflush\n");

  rewind(file);
  fgets(Buf, BUFSIZE-1, file);
  printf("Content:\r\n%s\r\n", Buf);
  fclose(file);

  // Test scanf
  /*printf("Type anything:\r\n");
  scanf("%s", Buf);
  printf("You typed \"%s\"\r\n", Buf);*/
}


// Functions for testing stdlib //
int CompareInt(const void* key, const void* oth){
  int k = *((int*) key);
  int o = *((int*) oth);
  if(k == o)
    return 0;
  if(k > o)
    return 1;
  else
    return -1;
}

VOID
TestStdlib(VOID)
{
  Print(L"abs(5)=%d abs(-5)=%d\n", abs(5), abs(-5));
  
  /* Test ato... */
  Print(L"atoi(0123456789)=%d\n", atoi("0123456789"));
  Print(L"atol(0123456789)=%d\n", atol("0123456789"));
  Print(L"atoll(0123456789)=%d\n", atoll("0123456789"));
  // atof to be determined (not printf with %f)
  
  /* Test bsearch */
  int Tab[] = {0, 1, 3, 5, 6, 7, 8, 9, 10};
  int Len = sizeof(Tab)/sizeof(int);
  int Nb;
  for(Nb = 0; Nb < 12; Nb++){
    void* Result = bsearch(&Nb, Tab, Len, sizeof(int), CompareInt);
    Print(L"Is %d in [0, 1, 3, 5, 6, 7, 8, 9, 10] ? %s\n",
	  Nb, (Result == NULL)?L"No":L"Yes");
  }

  /* Test div */
  div_t Res = div(11, 2);
  Print(L"div(11,2) = {%d, %d}\n", Res.quot, Res.rem);
  ldiv_t Lres = ldiv(6147483647, 3);
  Print(L"ldiv(6147483647, 3) = {%d, %d}\n", Lres.quot, Lres.rem);
  lldiv_t Llres = lldiv(6147483647, 3);
  Print(L"lldiv(6147483647, 3) = {%d, %d}\n", Llres.quot, Llres.rem);

  /* Float converters */
  /* Unsupported yet */
  /*int Sign, Decpt;
  char* Dec1 = ecvt(2.12000, 2, &Decpt, &Sign);
  Print(L"ecvt(2.1200, 2,...) = %s\n", Dec1);*/

  /* Sort array */
  int UnTab[] = {10, 9, 5, 8 ,6, 3, 7, 2, 0, 1};
  Len = sizeof(UnTab)/sizeof(int);
  int i;
  qsort(UnTab, Len, sizeof(int), CompareInt);
  Print(L"qsort([10, 9, 5, 8 ,6 3, 7, 2, 0, 1]) = [");
  for(i = 0; i < Len; i++){
    if(i != Len-1){
      Print(L"%d, ", UnTab[i]);
    } else {
      Print(L"%d] \n", UnTab[i]);
    }
  }

  /* Test strtol */
  char* Valid = NULL;
  long int Num1 = strtol("1001001", &Valid, 2);
  Print(L"strtol(1001001, ..., 2) = %d (Valid = %d)\n", Num1, !*Valid);
  Num1 = strtol("ff", &Valid, 16);
  Print(L"strtol(ff, ..., 16) = %d (Valid = %d)\n", Num1, !*Valid);
}
