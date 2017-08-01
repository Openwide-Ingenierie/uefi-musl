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
  case SYS_ptrace:
  case SYS_getuid:
  case SYS_syslog:
  case SYS_getgid:
  case SYS_setuid:
  case SYS_setgid:
  case SYS_geteuid:
  case SYS_getegid:
  case SYS_setpgid:
    
    break;
  case SYS_getppid:
    // We have no ppid, so let's return 1
    return 1;
  case SYS_getpgrp:
  case SYS_setsid:
  case SYS_setreuid:
  case SYS_setregid:
  case SYS_getgroups:
  case SYS_setgroups:
  case SYS_setresuid:
  case SYS_getresuid:
  case SYS_setresgid:
  case SYS_getresgid:
  case SYS_getpgid:
  case SYS_setfsuid:
  case SYS_setfsgid:
  case SYS_getsid:
  case SYS_capget:
  case SYS_capset:
  case SYS_rt_sigpending:
  case SYS_rt_sigtimedwait:
  case SYS_rt_sigqueueinfo:
  case SYS_rt_sigsuspend:
  case SYS_sigaltstack:
  case SYS_utime:
  case SYS_mknod:
  case SYS_uselib:
  case SYS_personality:
  case SYS_ustat:
  case SYS_statfs:
  case SYS_fstatfs:
  case SYS_sysfs:
  case SYS_getpriority:
  case SYS_setpriority:
  case SYS_sched_setparam:
  case SYS_sched_getparam:
  case SYS_sched_setscheduler:
  case SYS_sched_getscheduler:
  case SYS_sched_get_priority_max:
  case SYS_sched_get_priority_min:
  case SYS_sched_rr_get_interval:
  case SYS_mlock:
  case SYS_munlock:
  case SYS_mlockall:
  case SYS_munlockall:
  case SYS_vhangup:
  case SYS_modify_ldt:
  case SYS_pivot_root:
  case SYS__sysctl:
  case SYS_prctl:
  case SYS_arch_prctl:
  case SYS_adjtimex:
  case SYS_setrlimit:
  case SYS_chroot:
  case SYS_sync:
  case SYS_acct:
  case SYS_settimeofday:
  case SYS_mount:
  case SYS_umount2:
  case SYS_swapon:
  case SYS_swapoff:
  case SYS_reboot:
  case SYS_sethostname:
  case SYS_setdomainname:
  case SYS_iopl:
  case SYS_ioperm:
  case SYS_create_module:
  case SYS_init_module:
  case SYS_delete_module:
  case SYS_get_kernel_syms:
  case SYS_query_module:
  case SYS_quotactl:
  case SYS_nfsservctl:
  case SYS_getpmsg:
  case SYS_putpmsg:
  case SYS_afs_syscall:
  case SYS_tuxcall:
  case SYS_security:
  case SYS_gettid:
  case SYS_readahead:
  case SYS_setxattr:
  case SYS_lsetxattr:
  case SYS_fsetxattr:
  case SYS_getxattr:
  case SYS_lgetxattr:
  case SYS_fgetxattr:
  case SYS_listxattr:
  case SYS_llistxattr:
  case SYS_flistxattr:
  case SYS_removexattr:
  case SYS_lremovexattr:
  case SYS_fremovexattr:
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
  case SYS_io_setup:
  case SYS_io_destroy:
  case SYS_io_getevents:
  case SYS_io_submit:
  case SYS_io_cancel:
  case SYS_get_thread_area:
  case SYS_lookup_dcookie:
  case SYS_epoll_create:
  case SYS_epoll_ctl_old:
  case SYS_epoll_wait_old:
  case SYS_remap_file_pages:
  case SYS_set_tid_address:
  case SYS_restart_syscall:
  case SYS_semtimedop:
  case SYS_fadvise64:
  case SYS_timer_create:
  case SYS_timer_settime:
  case SYS_timer_gettime:
  case SYS_timer_getoverrun:
  case SYS_timer_delete:
  case SYS_clock_settime:
  case SYS_clock_gettime:
  case SYS_clock_getres:
  case SYS_clock_nanosleep:
  case SYS_exit_group:
  case SYS_epoll_wait:
  case SYS_epoll_ctl:
  case SYS_tgkill:
  case SYS_utimes:
  case SYS_vserver:
  case SYS_mbind:
  case SYS_set_mempolicy:
  case SYS_get_mempolicy:
  case SYS_mq_open:
  case SYS_mq_unlink:
  case SYS_mq_timedsend:
  case SYS_mq_timedreceive:
  case SYS_mq_notify:
  case SYS_mq_getsetattr:
  case SYS_kexec_load:
  case SYS_waitid:
  case SYS_add_key:
  case SYS_request_key:
  case SYS_keyctl:
  case SYS_ioprio_set:
  case SYS_ioprio_get:
  case SYS_inotify_init:
  case SYS_inotify_add_watch:
  case SYS_inotify_rm_watch:
  case SYS_migrate_pages:
  case SYS_openat:
  case SYS_mkdirat:
  case SYS_mknodat:
  case SYS_fchownat:
  case SYS_futimesat:
  case SYS_newfstatat:
  case SYS_unlinkat:
  case SYS_renameat:
  case SYS_linkat:
    break;
    
  case SYS_symlinkat:
    errno = EPERM;
    return -1;
  case SYS_readlinkat:
  case SYS_fchmodat:
  case SYS_faccessat:
  case SYS_pselect6:
  case SYS_ppoll:
  case SYS_unshare:
  case SYS_set_robust_list:
  case SYS_get_robust_list:
  case SYS_splice:
  case SYS_tee:
  case SYS_sync_file_range:
  case SYS_vmsplice:
  case SYS_move_pages:
  case SYS_utimensat:
  case SYS_epoll_pwait:
  case SYS_signalfd:
  case SYS_timerfd_create:
  case SYS_eventfd:
  case SYS_fallocate:
  case SYS_timerfd_settime:
  case SYS_timerfd_gettime:
  case SYS_accept4:
  case SYS_signalfd4:
  case SYS_eventfd2:
  case SYS_epoll_create1:
  case SYS_dup3:
  case SYS_pipe2:
  case SYS_inotify_init1:
  case SYS_preadv:
  case SYS_pwritev:
  case SYS_rt_tgsigqueueinfo:
  case SYS_perf_event_open:
  case SYS_recvmmsg:
  case SYS_fanotify_init:
  case SYS_fanotify_mark:
  case SYS_prlimit64:
  case SYS_name_to_handle_at:
  case SYS_open_by_handle_at:
  case SYS_clock_adjtime:
  case SYS_syncfs:
  case SYS_sendmmsg:
  case SYS_setns:
  case SYS_getcpu:
  case SYS_process_vm_readv:
  case SYS_process_vm_writev:
  case SYS_kcmp:
  case SYS_finit_module:
  case SYS_sched_setattr:
  case SYS_sched_getattr:
  case SYS_renameat2:
  case SYS_seccomp:
  case SYS_getrandom:
  case SYS_memfd_create:
  case SYS_kexec_file_load:
  case SYS_bpf:
  case SYS_execveat:
  case SYS_userfaultfd:
  case SYS_membarrier:
  case SYS_mlock2:
  case SYS_copy_file_range:
  case SYS_preadv2:
  case SYS_pwritev2:
  case SYS_pkey_mprotect:
  case SYS_pkey_alloc:
  case SYS_pkey_free: 
  default:
    Print(L"Unsupported operation %d\n", Rax);
    break;
  }
  Print(L"Unsupported operation %d\n", Rax);
  errno = ENOSYS;
  return -1;
}
