#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/BaseMemoryLib.h>
#include <Uefi/UefiSpec.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/MemoryAllocationLib.h>

#include "File.h"
#include "Nanosleep.h"
#include "Ioctl.h"
#include "Time.h"
#include "MemoryMapping.h"
#include <syscall.h>
#include <errno.h>

UINT64 __attribute__ ((noinline))
UefiSyscall(UINT64 Rax, UINT64 Arg1, UINT64 Arg2, UINT64 Arg3, UINT64 Arg4,
	    UINT64 Arg5, UINT64 Arg6)
{
  switch(Rax){
  case SYS_read:
    return Syscall_Read(Arg1, Arg2, Arg3);
    
  case SYS_write:
    return Syscall_Write(Arg1, Arg2, Arg3);
    
  case SYS_open:
    return Syscall_Open(Arg1, Arg2, Arg3);
    
  case SYS_close:
    return Syscall_Close(Arg1);

  case SYS_lstat:
    // Links are treated as normal files as there are no links
    
  case SYS_stat:
    return Syscall_Stat(Arg1, Arg2);
    
  case SYS_fstat:
    return Syscall_Fstat(Arg1, Arg2);
    
  case SYS_poll:
    break;

  case SYS_lseek:
    return Syscall_Lseek(Arg1, Arg2, Arg3);
    
  case SYS_mmap:
    return Syscall_Mmap(Arg1, Arg2, Arg3, Arg4, Arg5, Arg6);

  case SYS_mprotect:
    break;

  case SYS_munmap:
    return Syscall_Munmap(Arg1, Arg2);

  case SYS_brk:
    return Syscall_Brk(Arg1);

  case SYS_rt_sigaction:
  case SYS_rt_sigprocmask:
  case SYS_rt_sigreturn:
    break;

  case SYS_ioctl:
    return Syscall_Ioctl(Arg1, Arg2, Arg3);
    
  case SYS_pread64:
    return Syscall_Pread64(Arg1, Arg2, Arg3, Arg4);

  case SYS_pwrite64:
    return Syscall_Pwrite64(Arg1, Arg2, Arg3, Arg4);

  case SYS_readv:
    return Syscall_Readv(Arg1, Arg2, Arg3);

  case SYS_writev:
    return Syscall_Writev(Arg1, Arg2, Arg3);

  case SYS_access:
  case SYS_pipe:
  case SYS_select:
  case SYS_sched_yield:
  case SYS_mremap:
  case SYS_msync:
  case SYS_mincore:
  case SYS_madvise:
  case SYS_shmget:
  case SYS_shmat:
  case SYS_shmctl:
    break;

  case SYS_dup:
    return Syscall_Dup(Arg1);
  case SYS_dup2:
    return Syscall_Dup2(Arg1, Arg2);
  case SYS_pause:
    break;
  case SYS_nanosleep:
    return Syscall_Nanosleep(Arg1, Arg2);

  case SYS_getitimer:
  case SYS_alarm:
  case SYS_setitimer:
    break;

  case SYS_getpid:
    // We have only one process, so let's return 1
    return 1;

  case SYS_sendfile:
  case SYS_socket:
  case SYS_connect:
  case SYS_accept:
  case SYS_sendto:
  case SYS_recvfrom:
  case SYS_sendmsg:
  case SYS_recvmsg:
  case SYS_shutdown:
  case SYS_bind:
  case SYS_listen:
  case SYS_getsockname:
  case SYS_getpeername:
  case SYS_socketpair:
  case SYS_setsockopt:
  case SYS_getsockopt:
  case SYS_clone:
  case SYS_fork:
  case SYS_vfork:
  case SYS_execve:
    break;
    
  case SYS_exit:
    Exit(Arg1);
    break;

  case SYS_wait4:
  case SYS_kill:
  case SYS_uname:
  case SYS_semget:
  case SYS_semop:
  case SYS_semctl:
  case SYS_shmdt:
  case SYS_msgget:
  case SYS_msgsnd:
  case SYS_msgrcv:
  case SYS_msgctl:
  case SYS_fcntl:
  case SYS_flock:
  case SYS_fsync:
  case SYS_fdatasync:
    break;
    
  case SYS_truncate:
    return Syscall_Truncate(Arg1, Arg2);
  case SYS_ftruncate:
    return Syscall_Ftruncate(Arg1, Arg2);

  case SYS_getdents:
  case SYS_getcwd:
  case SYS_chdir:
  case SYS_fchdir:
    break;
    
  case SYS_rename:
    return Syscall_Rename(Arg1, Arg2);

  case SYS_mkdir:
  case SYS_rmdir:
    break;
    
  case SYS_creat:
    return Syscall_Creat(Arg1, Arg2);
  case SYS_link:
    errno = EPERM;
    return -1;    
  case SYS_unlink:
    return Syscall_Unlink(Arg1);
  case SYS_symlink:
    errno = EPERM;
    return -1;
    
  case SYS_readlink:
  case SYS_chmod:
  case SYS_fchmod:
  case SYS_chown:
  case SYS_fchown:
  case SYS_lchown:
  case SYS_umask:
  case SYS_gettimeofday:
  case SYS_getrlimit:
  case SYS_getrusage:
  case SYS_sysinfo:
  case SYS_times:
    
    break;
  case SYS_ptrace:
    
    break;
  case SYS_getuid:
    
    break;
  case SYS_syslog:
    
    break;
  case SYS_getgid:
    
    break;
  case SYS_setuid:
    
    break;
  case SYS_setgid:
    
    break;
  case SYS_geteuid:
    
    break;
  case SYS_getegid:
    
    break;
  case SYS_setpgid:
    
    break;
  case SYS_getppid:
    // We have no ppid, so let's return 1
    return 1;
  case SYS_getpgrp:
    
    break;
  case SYS_setsid:
    
    break;
  case SYS_setreuid:
    
    break;
  case SYS_setregid:
    
    break;
  case SYS_getgroups:
    
    break;
  case SYS_setgroups:
    
    break;
  case SYS_setresuid:
    
    break;
  case SYS_getresuid:
    
    break;
  case SYS_setresgid:
    
    break;
  case SYS_getresgid:
    
    break;
  case SYS_getpgid:
    
    break;
  case SYS_setfsuid:
    
    break;
  case SYS_setfsgid:
    
    break;
  case SYS_getsid:
    
    break;
  case SYS_capget:
    
    break;
  case SYS_capset:
    
    break;
  case SYS_rt_sigpending:
    
    break;
  case SYS_rt_sigtimedwait:
    
    break;
  case SYS_rt_sigqueueinfo:
    
    break;
  case SYS_rt_sigsuspend:
    
    break;
  case SYS_sigaltstack:
    
    break;
  case SYS_utime:
    
    break;
  case SYS_mknod:
    
    break;
  case SYS_uselib:
    
    break;
  case SYS_personality:
    
    break;
  case SYS_ustat:
    
    break;
  case SYS_statfs:
    
    break;
  case SYS_fstatfs:
    
    break;
  case SYS_sysfs:
    
    break;
  case SYS_getpriority:
    
    break;
  case SYS_setpriority:
    
    break;
  case SYS_sched_setparam:
    
    break;
  case SYS_sched_getparam:
    
    break;
  case SYS_sched_setscheduler:
    
    break;
  case SYS_sched_getscheduler:
    
    break;
  case SYS_sched_get_priority_max:
    
    break;
  case SYS_sched_get_priority_min:
    
    break;
  case SYS_sched_rr_get_interval:
    
    break;
  case SYS_mlock:
    
    break;
  case SYS_munlock:
    
    break;
  case SYS_mlockall:
    
    break;
  case SYS_munlockall:
    
    break;
  case SYS_vhangup:
    
    break;
  case SYS_modify_ldt:
    
    break;
  case SYS_pivot_root:
    
    break;
  case SYS__sysctl:
    
    break;
  case SYS_prctl:
    
    break;
  case SYS_arch_prctl:
    
    break;
  case SYS_adjtimex:
    
    break;
  case SYS_setrlimit:
    
    break;
  case SYS_chroot:
    
    break;
  case SYS_sync:
    
    break;
  case SYS_acct:
    
    break;
  case SYS_settimeofday:
    
    break;
  case SYS_mount:
    
    break;
  case SYS_umount2:
    
    break;
  case SYS_swapon:
    
    break;
  case SYS_swapoff:
    
    break;
  case SYS_reboot:
    
    break;
  case SYS_sethostname:
    
    break;
  case SYS_setdomainname:
    
    break;
  case SYS_iopl:
    
    break;
  case SYS_ioperm:
    
    break;
  case SYS_create_module:
    
    break;
  case SYS_init_module:
    
    break;
  case SYS_delete_module:
    
    break;
  case SYS_get_kernel_syms:
    
    break;
  case SYS_query_module:
    
    break;
  case SYS_quotactl:
    
    break;
  case SYS_nfsservctl:
    
    break;
  case SYS_getpmsg:
    
    break;
  case SYS_putpmsg:
    
    break;
  case SYS_afs_syscall:
    
    break;
  case SYS_tuxcall:
    
    break;
  case SYS_security:
    
    break;
  case SYS_gettid:
    
    break;
  case SYS_readahead:
    
    break;
  case SYS_setxattr:
    
    break;
  case SYS_lsetxattr:
    
    break;
  case SYS_fsetxattr:
    
    break;
  case SYS_getxattr:
    
    break;
  case SYS_lgetxattr:
    
    break;
  case SYS_fgetxattr:
    
    break;
  case SYS_listxattr:
    
    break;
  case SYS_llistxattr:
    
    break;
  case SYS_flistxattr:
    
    break;
  case SYS_removexattr:
    
    break;
  case SYS_lremovexattr:
    
    break;
  case SYS_fremovexattr:
    
    break;
  case SYS_tkill:
    break;
    
  case SYS_time:
    return Syscall_Time(Arg1);
    
  case SYS_futex:
    break;
    
  case SYS_sched_setaffinity:
    break;
    
  case SYS_sched_getaffinity:
    break;
    
  case SYS_set_thread_area:
    
    break;
  case SYS_io_setup:
    
    break;
  case SYS_io_destroy:
    
    break;
  case SYS_io_getevents:
    
    break;
  case SYS_io_submit:
    
    break;
  case SYS_io_cancel:
    
    break;
  case SYS_get_thread_area:
    
    break;
  case SYS_lookup_dcookie:
    
    break;
  case SYS_epoll_create:
    
    break;
  case SYS_epoll_ctl_old:
    
    break;
  case SYS_epoll_wait_old:
    
    break;
  case SYS_remap_file_pages:
    
    break;
  case SYS_set_tid_address:
    
    break;
  case SYS_restart_syscall:
    
    break;
  case SYS_semtimedop:
    
    break;
  case SYS_fadvise64:
    
    break;
  case SYS_timer_create:
    
    break;
  case SYS_timer_settime:
    
    break;
  case SYS_timer_gettime:
    
    break;
  case SYS_timer_getoverrun:
    
    break;
  case SYS_timer_delete:
    
    break;
  case SYS_clock_settime:
    
    break;
  case SYS_clock_gettime:
    
    break;
  case SYS_clock_getres:
    
    break;
  case SYS_clock_nanosleep:
    
    break;
  case SYS_exit_group:
    
    break;
  case SYS_epoll_wait:
    
    break;
  case SYS_epoll_ctl:
    
    break;
  case SYS_tgkill:
    
    break;
  case SYS_utimes:
    
    break;
  case SYS_vserver:
    
    break;
  case SYS_mbind:
    
    break;
  case SYS_set_mempolicy:
    
    break;
  case SYS_get_mempolicy:
    
    break;
  case SYS_mq_open:
    
    break;
  case SYS_mq_unlink:
    
    break;
  case SYS_mq_timedsend:
    
    break;
  case SYS_mq_timedreceive:
    
    break;
  case SYS_mq_notify:
    
    break;
  case SYS_mq_getsetattr:
    
    break;
  case SYS_kexec_load:
    
    break;
  case SYS_waitid:
    
    break;
  case SYS_add_key:
    
    break;
  case SYS_request_key:
    
    break;
  case SYS_keyctl:
    
    break;
  case SYS_ioprio_set:
    
    break;
  case SYS_ioprio_get:
    
    break;
  case SYS_inotify_init:
    
    break;
  case SYS_inotify_add_watch:
    
    break;
  case SYS_inotify_rm_watch:
    
    break;
  case SYS_migrate_pages:
    
    break;
  case SYS_openat:
    
    break;
  case SYS_mkdirat:
    
    break;
  case SYS_mknodat:
    
    break;
  case SYS_fchownat:
    
    break;
  case SYS_futimesat:
    
    break;
  case SYS_newfstatat:
    
    break;
  case SYS_unlinkat:
    
    break;
  case SYS_renameat:
    
    break;
  case SYS_linkat:
    
    break;
  case SYS_symlinkat:
    errno = EPERM;
    return -1;
  case SYS_readlinkat:
    
    break;
  case SYS_fchmodat:
    
    break;
  case SYS_faccessat:
    
    break;
  case SYS_pselect6:
    
    break;
  case SYS_ppoll:
    
    break;
  case SYS_unshare:
    
    break;
  case SYS_set_robust_list:
    
    break;
  case SYS_get_robust_list:
    
    break;
  case SYS_splice:
    
    break;
  case SYS_tee:
    
    break;
  case SYS_sync_file_range:
    
    break;
  case SYS_vmsplice:
    
    break;
  case SYS_move_pages:
    
    break;
  case SYS_utimensat:
    
    break;
  case SYS_epoll_pwait:
    
    break;
  case SYS_signalfd:
    
    break;
  case SYS_timerfd_create:
    
    break;
  case SYS_eventfd:
    
    break;
  case SYS_fallocate:
    
    break;
  case SYS_timerfd_settime:
    
    break;
  case SYS_timerfd_gettime:
    
    break;
  case SYS_accept4:
    
    break;
  case SYS_signalfd4:
    
    break;
  case SYS_eventfd2:
    
    break;
  case SYS_epoll_create1:
    
    break;
  case SYS_dup3:
    
    break;
  case SYS_pipe2:
    
    break;
  case SYS_inotify_init1:
    
    break;
  case SYS_preadv:
    
    break;
  case SYS_pwritev:
    
    break;
  case SYS_rt_tgsigqueueinfo:
    
    break;
  case SYS_perf_event_open:
    
    break;
  case SYS_recvmmsg:
    
    break;
  case SYS_fanotify_init:
    
    break;
  case SYS_fanotify_mark:
    
    break;
  case SYS_prlimit64:
    
    break;
  case SYS_name_to_handle_at:
    
    break;
  case SYS_open_by_handle_at:
    
    break;
  case SYS_clock_adjtime:
    
    break;
  case SYS_syncfs:
    
    break;
  case SYS_sendmmsg:
    
    break;
  case SYS_setns:
    
    break;
  case SYS_getcpu:
    
    break;
  case SYS_process_vm_readv:
    
    break;
  case SYS_process_vm_writev:
    
    break;
  case SYS_kcmp:
    
    break;
  case SYS_finit_module:
    
    break;
  case SYS_sched_setattr:
    
    break;
  case SYS_sched_getattr:
    
    break;
  case SYS_renameat2:
    
    break;
  case SYS_seccomp:
    
    break;
  case SYS_getrandom:
    
    break;
  case SYS_memfd_create:
    
    break;
  case SYS_kexec_file_load:
    
    break;
  case SYS_bpf:
    
    break;
  case SYS_execveat:
    
    break;
  case SYS_userfaultfd:
    break;
  case SYS_membarrier:
    break;
  case SYS_mlock2:
    break;
  case SYS_copy_file_range:
    break;
  case SYS_preadv2:
    break;
  case SYS_pwritev2:
    break;
  case SYS_pkey_mprotect:
    break;
  case SYS_pkey_alloc:
    break;
  case SYS_pkey_free: 
    break;
  default:
    Print(L"Unsupported operation %d\n", Rax);
    break;
  }
  Print(L"Unsupported operation %d\n", Rax);
  errno = ENOSYS;
  return -1;
}
