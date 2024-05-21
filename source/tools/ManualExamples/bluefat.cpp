/*
 *  ____  _            _____     _   
 * | __ )| |_   _  ___|  ___|_ _| |_ 
 * |  _ \| | | | |/ _ \ |_ / _` | __|
 * | |_) | | |_| |  __/  _| (_| | |_ 
 * |____/|_|\__,_|\___|_|  \__,_|\__|
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This is the BlueFat Pin interface.  The core BlueFat functionality is
 * implemented in bluefat.c.
 */

#include "../../../libbluefat/bluefat.c"

#include "pin.H"
#include <map>

/*
 * Global mutex.
 */
static PIN_MUTEX mutex;
static inline void bluefat_lock(void)
{
    PIN_MutexLock(&mutex);
}
static inline void bluefat_unlock(void)
{
    PIN_MutexUnlock(&mutex);
}

/*
 * Prototypes.
 */
VOID Fini(INT32 code, VOID *v);

static bool option_debug = false;

/*
 * Thread local data
 */
struct ThreadData
{
    int num;                        // Syscall number
    ADDRINT param[6];               // Syscall params
    ADDRINT scratch[4];
    uint8_t data[128] __attribute__((aligned(64)));
};

/*
 * Memory error location.
 */
struct Loc
{
    uintptr_t code:8;                // Error code (BLUEFAT_ERROR_*)
    uintptr_t loc:56;                // Error location (address)

    Loc(int code, const void *loc) : code((uintptr_t)code), loc((uintptr_t)loc)
    {
        ;
    }

    bool operator<(const Loc &l) const
    {
        if (l.code < code)
            return true;
        else if (l.code > code)
            return false;
        else
            return (l.loc < loc);
    }
};

/*
 * Memory error information.
 */
struct Error
{
    size_t count;
    uintptr_t ptr;
    size_t size;
    uintptr_t lb, ub;
    const char *image;
    off_t offset;

    Error() : count(0), ptr(0x0), size(0), lb(0x0), ub(0x0), image(NULL),
        offset(+0)
    {
        ;
    }
};

/*
 * Memory error log.
 */
static TLS_KEY tls_key = INVALID_TLS_KEY;
typedef std::map<Loc, Error> Errors;
static const uint8_t zero[128] __attribute__((aligned(64))) = {0}; 
static Errors errs;

/*
 * This function is called if an memory error is detected.
 */
static void *bluefat_memory_error(const void *loc, const void *ptr,
    size_t size, const struct bluefat_entry_s *entry, int code)
{
    if (option_debug ||
           (code != BLUEFAT_ERROR_READ_UNDERFLOW &&
            code != BLUEFAT_ERROR_READ_OVERFLOW))
    {
        Loc L(code, loc);
        Error err;
        std::pair<Errors::iterator, bool> i =
            errs.insert(std::make_pair(L, err));
        Error &E = i.first->second;
        E.count++;
        if (i.second)
        {
            // First error, so save some additional information:
            E.ptr = (uintptr_t)ptr;
            E.size = size;
            E.lb = (entry == NULL? 0: entry->lb);
            E.ub = (entry == NULL? 0: entry->lb + entry->size);
            PIN_LockClient();
            IMG img = IMG_FindByAddress((ADDRINT)loc);
            PIN_UnlockClient();
            if (IMG_Valid(img))
            {
                E.image  = strdup(IMG_Name(img).c_str());
                E.offset = (off_t)loc - (off_t)IMG_LowAddress(img);
            }
        }
    }

    switch (code)
    {
        case BLUEFAT_ERROR_READ_UAF:
            bluefat_read_uaf++; break;
        case BLUEFAT_ERROR_WRITE_UAF:
            bluefat_write_uaf++; break;
        case BLUEFAT_ERROR_READ_UNDERFLOW:
            bluefat_read_overflow++; break;
        case BLUEFAT_ERROR_WRITE_UNDERFLOW:
            bluefat_write_underflow++; break;
        case BLUEFAT_ERROR_READ_OVERFLOW:
            bluefat_read_overflow++; break;
        case BLUEFAT_ERROR_WRITE_OVERFLOW:
            bluefat_write_overflow++; break;
        default:
            break;
    }

    switch (code)
    {
        case BLUEFAT_ERROR_READ_UAF:
        case BLUEFAT_ERROR_WRITE_UNDERFLOW:
        case BLUEFAT_ERROR_WRITE_OVERFLOW:
        case BLUEFAT_ERROR_WRITE_UAF:
            // Hard errors == exit program
            Fini(EXIT_FAILURE, NULL);
            PIN_ExitProcess(EXIT_FAILURE);
            break;
        case BLUEFAT_ERROR_READ_UNDERFLOW:
        case BLUEFAT_ERROR_READ_OVERFLOW:
        {
            // Soft errors == zero data
            ThreadData *tld = (ThreadData *)PIN_GetThreadData(tls_key, 
                PIN_ThreadId());

            uintptr_t iptr = (uintptr_t)ptr;
            ptrdiff_t offset = (intptr_t)ptr - (intptr_t)entry->lb;
            void *src = (void *)(bluefat_get_base(entry) + offset);
            void *dst = NULL;
            uintptr_t delta = iptr & 0x3F;
            uintptr_t ub = entry->lb + entry->size;
            if (iptr + size <= entry->lb || iptr >= ub)
                dst = (void *)(zero + delta);
            else
            {
                dst = (void *)(tld->data + delta);
                uint8_t *dst8 = (uint8_t *)dst;
                const uint8_t *src8 = (const uint8_t *)src;
                for (size_t i = 0; i < size; i++)
                {
                    uintptr_t jptr = iptr + i;
                    dst8[i] = (jptr < entry->lb || jptr >= ub? 0x0: src8[i]);
                }
            }
            return dst;
        }
        default:
            break;
    }
    ptrdiff_t offset = (intptr_t)ptr - (intptr_t)entry->lb;
    return (void *)(bluefat_get_base(entry) + offset);
}

#include <iostream>
#include <fstream>
#include <signal.h>
using std::cerr;
using std::endl;
using std::ios;
using std::ofstream;
using std::string;

static ADDRINT ProcessAddress(ADDRINT originalEa, ADDRINT size, UINT32 access,
    ADDRINT iaddr);

static bool IsEncoded(ADDRINT addr)
{
    return bluefat_is_encoded((void *)addr);
}
static ADDRINT Decode(ADDRINT addr)
{
    ADDRINT addr1 = (ADDRINT)bluefat_marshall((void *)addr);
    return addr1;
}

typedef std::map<ADDRINT, size_t> StatFaults;
static StatFaults stat_faults;

#define READ    0x1
#define WRITE   0x2

static ADDRINT ProcessAddressRep(uint32_t rep, ADDRINT originalEa,
    ADDRINT size, UINT32 access, ADDRINT iaddr)
{
    if (rep == 0)
    {
        // Does not repeat == memory not accessed == do not check & translate
        return originalEa;
    }
    return ProcessAddress(originalEa, size, access, iaddr);
}

static ADDRINT ProcessAddress(ADDRINT originalEa, ADDRINT size, UINT32 access,
    ADDRINT iaddr)
{
    if (access == 0x0 || size == 0 || !IsEncoded(originalEa))
        return originalEa;
    ADDRINT decodedEa = (ADDRINT)bluefat_deref((const void *)originalEa, size,
        (access & WRITE) != 0, (void *)iaddr);
    return decodedEa;
}

static ADDRINT EncodeAddress(ADDRINT addr, ADDRINT size)
{
    ADDRINT addr1 = (ADDRINT)bluefat_encode((const void *)addr, (size_t)size);
    return addr1;
}

static ADDRINT RevokeAddress(ADDRINT addr)
{
    ADDRINT addr1 = (ADDRINT)bluefat_revoke((const void *)addr);
    return addr1;
}

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v)
{
    // Insert a call to ProcessAddress before every instruction
    for (UINT32 op = 0; op < INS_MemoryOperandCount(ins); op++)
    {
        UINT32 access = (INS_MemoryOperandIsRead(ins, op) ? READ : 0) |
                        (INS_MemoryOperandIsWritten(ins, op) ? WRITE : 0);
        if (access == 0x0)
            continue;
        if ((INS_MemoryBaseReg(ins) == REG_RSP &&
             INS_MemoryIndexReg(ins) == REG_INVALID()) ||
                INS_MemoryBaseReg(ins) == REG_RIP)
            continue;

        if (INS_HasRealRep(ins))
        {
            INS_InsertCall(ins, IPOINT_BEFORE,
                           AFUNPTR(ProcessAddressRep),
                           IARG_REG_VALUE, INS_RepCountRegister(ins),
                           IARG_MEMORYOP_EA, op,
                           IARG_MEMORYOP_SIZE, op,
                           IARG_UINT32, access,
                           IARG_INST_PTR,
                           IARG_RETURN_REGS, REG_INST_G0 + op,
                           IARG_CALL_ORDER, CALL_ORDER_LAST,
                           IARG_END);
        }
        else
        {
            INS_InsertCall(ins, IPOINT_BEFORE,
                           AFUNPTR(ProcessAddress),
                           IARG_MEMORYOP_EA, op,
                           IARG_MEMORYOP_SIZE, op,
                           IARG_UINT32, access,
                           IARG_INST_PTR,
                           IARG_RETURN_REGS, REG_INST_G0 + op,
                           IARG_CALL_ORDER, CALL_ORDER_LAST,
                           IARG_END);
        }
        INS_RewriteMemoryOperand(ins, op, REG(REG_INST_G0 + op));
    }

    if (INS_IsNop(ins) && INS_MemoryBaseReg(ins) == REG_R14 &&
            INS_MemoryIndexReg(ins) == REG_RSI)
    {
        // EncodeAddress
        INS_InsertCall(ins, IPOINT_BEFORE,
            AFUNPTR(EncodeAddress),
            IARG_REG_VALUE, REG_R14,
            IARG_REG_VALUE, REG_RSI,
            IARG_RETURN_REGS, REG_RAX,
            IARG_END);
    }
    if (INS_IsNop(ins) && INS_MemoryBaseReg(ins) == REG_R15)
    {
        // RevokeAddress
        INS_InsertCall(ins, IPOINT_BEFORE,
            AFUNPTR(RevokeAddress),
            IARG_REG_VALUE, REG_R15,
            IARG_RETURN_REGS, REG_RAX,
            IARG_END);
    }
}

VOID Fini(INT32 code, VOID *v)
{
    fprintf(stderr, "-----------------------------\n");
    for (Errors::iterator i = errs.begin(), iend = errs.end(); i != iend;
            ++i)
    {
        const Loc &L = i->first;
        const Error &E = i->second;
        switch (L.code)
        {
            case BLUEFAT_ERROR_READ_UNDERFLOW:
                fprintf(stderr, "\33[33mUNDERFLOW\33[0m: read=");
                break;
            case BLUEFAT_ERROR_READ_OVERFLOW:
                fprintf(stderr, "\33[33mOVERFLOW\33[0m: read=");
                break;
            case BLUEFAT_ERROR_READ_UAF:
                fprintf(stderr, "\33[31mUSE-AFTER-FREE\33[0m: read=");
                break;
            case BLUEFAT_ERROR_WRITE_UNDERFLOW:
                fprintf(stderr, "\33[31mUNDERFLOW\33[0m: write=");
                break;
            case BLUEFAT_ERROR_WRITE_OVERFLOW:
                fprintf(stderr, "\33[31mOVERFLOW\33[0m: write=");
                break;
            case BLUEFAT_ERROR_WRITE_UAF:
                fprintf(stderr, "\33[31mUSE-AFTER-FREE\33[0m: write=");
                break;
        }
        fprintf(stderr, "%zu, loc=%p [%s+0x%zx], ptr=%p, obj=",
                E.size, (void *)(uintptr_t)L.loc,
                    (E.image == NULL? "???": E.image), E.offset, (void *)E.ptr);
        if (E.lb != E.ub)
            fprintf(stderr, "[%+zd..%+zd]\n", E.lb - E.ptr, E.ub - E.ptr);
        else
            fprintf(stderr, "(free)\n");
    }

    fprintf(stderr, "-----------------------------\n");
    fprintf(stderr, "read.underflow     = %zu\n", bluefat_read_underflow);
    fprintf(stderr, "read.overflow      = %zu\n", bluefat_read_overflow);
    fprintf(stderr, "write.underflow    = %zu\n", bluefat_write_underflow);
    fprintf(stderr, "write.overflow     = %zu\n", bluefat_write_overflow);
    fprintf(stderr, "read.uaf           = %zu\n", bluefat_read_uaf);
    fprintf(stderr, "write.uaf          = %zu\n", bluefat_write_uaf);
    fprintf(stderr, "alloc.max          = %zu\n", bluefat_max_objects);
    fprintf(stderr, "alloc.max.bytes    = %zu\n", bluefat_max_bytes);
    fprintf(stderr, "cache.hit          = %zu\n", bluefat_cache_hit);
    size_t total = bluefat_cache_hit + bluefat_cache_miss;
    total = (total == 0? 1: total);
    fprintf(stderr, "cache.miss         = %zu (%.2f%%)\n", bluefat_cache_miss,
        (double)bluefat_cache_miss / (double)total * 100.0);
}

INT32 Usage()
{
    cerr << "This tool rewrites the memory operands including syscall arguments" << endl;
    cerr << endl
         << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

VOID ThreadStart(THREADID tid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    ThreadData *tld = new ThreadData;
    if (!PIN_SetThreadData(tls_key, tld, tid))
    {
        fprintf(stderr, "error: failed to set thread-local data\n");
        abort();
    }
}

VOID ThreadFini(THREADID tid, const CONTEXT* ctxt, INT32 code, VOID* v)
{
    ThreadData *tld = (ThreadData *)PIN_GetThreadData(tls_key, tid);
    delete tld;
}

#define warning(msg, ...)                                                   \
    fprintf(stderr, "\33[33mwarning\33[0m: " msg "\n", ##__VA_ARGS__)
#define error(msg, ...)                                                     \
    do {                                                                    \
        fprintf(stderr, "\33[33merror\33[0m: " msg "\n", ##__VA_ARGS__);    \
        abort();                                                            \
    } while (false)


void OnSyscall(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    ThreadData *tld = (ThreadData *)PIN_GetThreadData(tls_key, tid);
    tld->num = (int)PIN_GetSyscallNumber(ctxt, std);

    for (int i = 0; i < 6; i++)
        tld->param[i] = PIN_GetSyscallArgument(ctxt, std, i);
    for (int i = 0; i < 4; i++)
        tld->scratch[i] = 0x0;

    switch (tld->num)
    {
        case SYS_close:
        case SYS_lseek:
        case SYS_mmap:
        case SYS_mprotect:
        case SYS_munmap:
        case SYS_brk:
        case SYS_rt_sigreturn:
        case SYS_sched_yield:
        case SYS_mremap:
        case SYS_msync:
        case SYS_mincore:
        case SYS_madvise:
        case SYS_shmget:
        case SYS_shmat:
        case SYS_dup:
        case SYS_dup2:
        case SYS_pause:
        case SYS_getpid:
        case SYS_socket:
        case SYS_shutdown:
        case SYS_listen:
        case SYS_fork:
        case SYS_vfork:
        case SYS_exit:
        case SYS_kill:
        case SYS_semget:
        case SYS_semctl:
        case SYS_msgget:
        case SYS_flock:
        case SYS_fsync:
        case SYS_fdatasync:
        case SYS_ftruncate:
        case SYS_fchdir:
        case SYS_fchmod:
        case SYS_fchown:
        case SYS_umask:
        case SYS_ptrace:
        case SYS_getuid:
        case SYS_getgid:
        case SYS_setuid:
        case SYS_setgid:
        case SYS_geteuid:
        case SYS_getegid:
        case SYS_setpgid:
        case SYS_getppid:
        case SYS_getpgrp:
        case SYS_setsid:
        case SYS_setreuid:
        case SYS_setregid:
        case SYS_setresgid:
        case SYS_getpgid:
        case SYS_setfsuid:
        case SYS_setfsgid:
        case SYS_getsid:
        case SYS_uselib:
        case SYS_personality:
        case SYS_sysfs:
        case SYS_getpriority:
        case SYS_setpriority:
        case SYS_sched_getscheduler:
        case SYS_sched_get_priority_max:
        case SYS_sched_get_priority_min:
        case SYS_mlock:
        case SYS_munlock:
        case SYS_mlockall:
        case SYS_munlockall:
        case SYS_vhangup:
        case SYS_sync:
        case SYS_ioperm:
        case SYS_gettid:
        case SYS_readahead:
        case SYS_tkill:
        case SYS_io_destroy:
        case SYS_lookup_dcookie:
        case SYS_epoll_create:
        case SYS_remap_file_pages:
        case SYS_restart_syscall:
        case SYS_fadvise64:
        case SYS_timer_getoverrun:
        case SYS_timer_delete:
        case SYS_exit_group:
        case SYS_tgkill:
        case SYS_keyctl:
        case SYS_ioprio_set:
        case SYS_ioprio_get:
        case SYS_inotify_init:
        case SYS_inotify_rm_watch:
        case SYS_unshare:
        case SYS_tee:
        case SYS_sync_file_range:
        case SYS_timerfd_create:
        case SYS_eventfd:
        case SYS_fallocate:
        case SYS_eventfd2:
        case SYS_epoll_create1:
        case SYS_dup3:
        case SYS_inotify_init1:
        case SYS_fanotify_init:
        case SYS_fanotify_mark:
        case SYS_syncfs:
        case SYS_setns:
        case SYS_kcmp:
        case /*SYS_userfaultfd=*/323:
        case SYS_alarm:
            break;
        case SYS_open:
        case SYS_poll:
        case SYS_access:
        case SYS_pipe:
        case SYS_uname:
        case SYS_shmdt:
        case SYS_truncate:
        case SYS_getcwd:
        case SYS_chdir:
        case SYS_mkdir:
        case SYS_rmdir:
        case SYS_creat:
        case SYS_unlink:
        case SYS_chmod:
        case SYS_chown:
        case SYS_lchown:
        case SYS_sysinfo:
        case SYS_times:
        case SYS_rt_sigpending:
        case SYS_rt_sigsuspend:
        case SYS_mknod:
        case /*SYS__sysctl=*/156:
        case SYS_adjtimex:
        case SYS_chroot:
        case SYS_acct:
        case SYS_umount2:
        case SYS_swapon:
        case SYS_swapoff:
        case SYS_sethostname:
        case SYS_setdomainname:
        case SYS_delete_module:
        case SYS_time:
        case SYS_mq_unlink:
        case SYS_set_robust_list:
        case SYS_pipe2:
        case SYS_perf_event_open:
        case SYS_getrandom:
        case /*SYS_memfd_create=*/319:
            PIN_SetSyscallArgument(ctxt, std, 0, Decode(tld->param[0]));
            break;
        case SYS_read:
        case SYS_write:
        case SYS_fstat:
        case SYS_pread64:
        case SYS_pwrite64:
        case SYS_getitimer:
        case SYS_connect:
        case SYS_bind:
        case SYS_semop:
        case SYS_msgsnd:
        case SYS_msgrcv:
        case SYS_getdents:
        case SYS_getrlimit:
        case SYS_getrusage:
        case SYS_syslog:
        case SYS_getgroups:
        case SYS_setgroups:
        case SYS_ustat:
        case SYS_fstatfs:
        case SYS_sched_setparam:
        case SYS_sched_getparam:
        case SYS_sched_rr_get_interval:
        case SYS_modify_ldt:
        case SYS_setrlimit:
        case SYS_iopl:
        case SYS_flistxattr:
        case SYS_fremovexattr:
        case SYS_io_setup:
        case SYS_getdents64:
        case SYS_set_tid_address:
        case SYS_timer_gettime:
        case SYS_clock_settime:
        case SYS_clock_gettime:
        case SYS_clock_getres:
        case SYS_epoll_wait:
        case SYS_set_mempolicy:
        case SYS_mq_notify:
        case SYS_inotify_add_watch:
        case SYS_openat:
        case SYS_mkdirat:
        case SYS_mknodat:
        case SYS_fchownat:
        case SYS_unlinkat:
        case SYS_fchmodat:
        case SYS_faccessat:
        case SYS_vmsplice:
        case SYS_signalfd:
        case SYS_timerfd_gettime:
        case SYS_signalfd4:
        case SYS_clock_adjtime:
        case SYS_finit_module:
        case SYS_sched_setattr:
        case SYS_sched_getattr:
        case /*SYS_bpf=*/321:
            PIN_SetSyscallArgument(ctxt, std, 1, Decode(tld->param[1]));
            break;
        case SYS_shmctl:
        case SYS_sendfile:
        case SYS_msgctl:
        case SYS_rt_sigqueueinfo:
        case SYS_sched_setscheduler:
        case SYS_sched_setaffinity:
        case SYS_sched_getaffinity:
        case SYS_io_submit:
        case SYS_kexec_load:
        case SYS_fcntl:
        case SYS_ioctl:
        case /*SYS_seccomp=*/317:
            PIN_SetSyscallArgument(ctxt, std, 2, Decode(tld->param[2]));
            break;
        case SYS_socketpair:
        case SYS_setsockopt:
        case SYS_io_getevents:
        case SYS_epoll_ctl:
        case SYS_mbind:
        case SYS_rt_tgsigqueueinfo:
        case /*SYS_kexec_file_load=*/320:
            PIN_SetSyscallArgument(ctxt, std, 3, Decode(tld->param[3]));
            break;
        case SYS_reboot:
            PIN_SetSyscallArgument(ctxt, std, 4, Decode(tld->param[4]));
            break;
        case SYS_stat:
        case SYS_lstat:
        case SYS_nanosleep:
        case SYS_rename:
        case SYS_link:
        case SYS_symlink:
        case SYS_readlink:
        case SYS_gettimeofday:
        case SYS_sigaltstack:
        case SYS_utime:
        case SYS_statfs:
        case SYS_pivot_root:
        case SYS_settimeofday:
        case SYS_listxattr:
        case SYS_llistxattr:
        case SYS_removexattr:
        case SYS_lremovexattr:
        case SYS_utimes:
        case SYS_get_mempolicy:
        case SYS_capget:
        case SYS_capset:
            PIN_SetSyscallArgument(ctxt, std, 0, Decode(tld->param[0]));
            PIN_SetSyscallArgument(ctxt, std, 1, Decode(tld->param[1]));
            break;
        case SYS_arch_prctl:
        case SYS_init_module:
        case SYS_symlinkat:
            PIN_SetSyscallArgument(ctxt, std, 0, Decode(tld->param[0]));
            PIN_SetSyscallArgument(ctxt, std, 2, Decode(tld->param[2]));
            break;
        case SYS_mq_open:
            PIN_SetSyscallArgument(ctxt, std, 0, Decode(tld->param[0]));
            PIN_SetSyscallArgument(ctxt, std, 3, Decode(tld->param[3]));
            break;
        case SYS_rt_sigaction:
        case SYS_rt_sigprocmask:
        case SYS_accept:
        case SYS_getsockname:
        case SYS_getpeername:
        case SYS_fsetxattr:
        case SYS_fgetxattr:
        case SYS_io_cancel:
        case SYS_timer_create:
        case SYS_mq_getsetattr:
        case SYS_futimesat:
        case SYS_newfstatat:
        case SYS_readlinkat:
        case SYS_get_robust_list:
        case SYS_utimensat:
        case SYS_accept4:
            PIN_SetSyscallArgument(ctxt, std, 1, Decode(tld->param[1]));
            PIN_SetSyscallArgument(ctxt, std, 2, Decode(tld->param[2]));
            break;
        case SYS_wait4:
        case SYS_quotactl:
        case SYS_semtimedop:
        case SYS_renameat:
        case SYS_linkat:
        case SYS_splice:
        case SYS_process_vm_readv:
        case SYS_process_vm_writev:
        case /*SYS_renameat2=*/316:
            PIN_SetSyscallArgument(ctxt, std, 1, Decode(tld->param[1]));
            PIN_SetSyscallArgument(ctxt, std, 3, Decode(tld->param[3]));
            break;
        case SYS_sendto:
        case SYS_mq_timedsend:
        case SYS_epoll_pwait:
            PIN_SetSyscallArgument(ctxt, std, 1, Decode(tld->param[1]));
            PIN_SetSyscallArgument(ctxt, std, 4, Decode(tld->param[4]));
            break;
        case SYS_clone:
        case SYS_timer_settime:
        case SYS_clock_nanosleep:
        case SYS_migrate_pages:
        case SYS_timerfd_settime:
        case SYS_prlimit64:
            PIN_SetSyscallArgument(ctxt, std, 2, Decode(tld->param[2]));
            PIN_SetSyscallArgument(ctxt, std, 3, Decode(tld->param[3]));
            break;
        case SYS_waitid:
            PIN_SetSyscallArgument(ctxt, std, 2, Decode(tld->param[2]));
            PIN_SetSyscallArgument(ctxt, std, 4, Decode(tld->param[4]));
            break;
        case SYS_getsockopt:
            PIN_SetSyscallArgument(ctxt, std, 3, Decode(tld->param[3]));
            PIN_SetSyscallArgument(ctxt, std, 4, Decode(tld->param[4]));
            break;
        case SYS_setresuid:
        case SYS_getresuid:
        case SYS_getresgid:
        case SYS_rt_sigtimedwait:
        case SYS_setxattr:
        case SYS_lsetxattr:
        case SYS_getxattr:
        case SYS_lgetxattr:
        case SYS_add_key:
        case SYS_request_key:
        case SYS_getcpu:
            PIN_SetSyscallArgument(ctxt, std, 0, Decode(tld->param[0]));
            PIN_SetSyscallArgument(ctxt, std, 1, Decode(tld->param[1]));
            PIN_SetSyscallArgument(ctxt, std, 2, Decode(tld->param[2]));
            break;
        case SYS_futex:
            PIN_SetSyscallArgument(ctxt, std, 0, Decode(tld->param[0]));
            PIN_SetSyscallArgument(ctxt, std, 3, Decode(tld->param[3]));
            PIN_SetSyscallArgument(ctxt, std, 4, Decode(tld->param[4]));
            break;
        case SYS_select:
        case SYS_name_to_handle_at:
        case SYS_open_by_handle_at:
            PIN_SetSyscallArgument(ctxt, std, 1, Decode(tld->param[1]));
            PIN_SetSyscallArgument(ctxt, std, 2, Decode(tld->param[2]));
            PIN_SetSyscallArgument(ctxt, std, 3, Decode(tld->param[3]));
            break;
        case SYS_mq_timedreceive:
            PIN_SetSyscallArgument(ctxt, std, 1, Decode(tld->param[1]));
            PIN_SetSyscallArgument(ctxt, std, 3, Decode(tld->param[3]));
            PIN_SetSyscallArgument(ctxt, std, 4, Decode(tld->param[4]));
            break;
        case SYS_recvfrom:
            PIN_SetSyscallArgument(ctxt, std, 1, Decode(tld->param[1]));
            PIN_SetSyscallArgument(ctxt, std, 4, Decode(tld->param[4]));
            PIN_SetSyscallArgument(ctxt, std, 5, Decode(tld->param[5]));
            break;
        case SYS_move_pages:
            PIN_SetSyscallArgument(ctxt, std, 2, Decode(tld->param[2]));
            PIN_SetSyscallArgument(ctxt, std, 3, Decode(tld->param[3]));
            PIN_SetSyscallArgument(ctxt, std, 4, Decode(tld->param[4]));
            break;
        case SYS_mount:
            PIN_SetSyscallArgument(ctxt, std, 0, Decode(tld->param[0]));
            PIN_SetSyscallArgument(ctxt, std, 1, Decode(tld->param[1]));
            PIN_SetSyscallArgument(ctxt, std, 2, Decode(tld->param[2]));
            PIN_SetSyscallArgument(ctxt, std, 4, Decode(tld->param[4]));
            break;
        case SYS_ppoll:
            PIN_SetSyscallArgument(ctxt, std, 0, Decode(tld->param[0]));
            PIN_SetSyscallArgument(ctxt, std, 2, Decode(tld->param[2]));
            PIN_SetSyscallArgument(ctxt, std, 3, Decode(tld->param[3]));
            PIN_SetSyscallArgument(ctxt, std, 4, Decode(tld->param[4]));
            break;
        case SYS_prctl:
            // TODO: handle PR_SET_SECCOMP
            PIN_SetSyscallArgument(ctxt, std, 1, Decode(tld->param[1]));
            PIN_SetSyscallArgument(ctxt, std, 2, Decode(tld->param[2]));
            PIN_SetSyscallArgument(ctxt, std, 3, Decode(tld->param[3]));
            PIN_SetSyscallArgument(ctxt, std, 4, Decode(tld->param[3]));
            PIN_SetSyscallArgument(ctxt, std, 5, Decode(tld->param[4]));
            break;
        case SYS_pselect6:
            PIN_SetSyscallArgument(ctxt, std, 1, Decode(tld->param[1]));
            PIN_SetSyscallArgument(ctxt, std, 2, Decode(tld->param[2]));
            PIN_SetSyscallArgument(ctxt, std, 3, Decode(tld->param[3]));
            PIN_SetSyscallArgument(ctxt, std, 4, Decode(tld->param[4]));
            PIN_SetSyscallArgument(ctxt, std, 5, Decode(tld->param[5]));
            break;
        case SYS_readv:
        case SYS_writev:
        case SYS_preadv:
        case SYS_pwritev:
        {
            int iovcnt = (int)tld->param[2];
            struct iovec *iov = NULL;
            struct iovec *iov_0 =
                (struct iovec *)Decode((ADDRINT)tld->param[1]);
            if (iovcnt > 0)
                iov = new struct iovec[iovcnt];
            for (int i = 0; i < iovcnt; i++)
            {
                iov[i].iov_base = (void *)Decode((ADDRINT)iov_0[i].iov_base);
                iov[i].iov_len  = iov_0[i].iov_len;
            }
            PIN_SetSyscallArgument(ctxt, std, 1, (ADDRINT)iov);
            tld->scratch[0] = (ADDRINT)iov;
            break;
        }
        case SYS_sendmsg:
        case SYS_recvmsg:
        {
            struct msghdr *msg_0 =
                (struct msghdr *)Decode((ADDRINT)tld->param[1]);
            if (msg_0 == NULL)
                break;
            struct msghdr *msg = new struct msghdr;
            memcpy(msg, msg_0, sizeof(*msg));
            msg->msg_name = (void *)Decode((ADDRINT)msg->msg_name);
            struct iovec *iov_0 = msg->msg_iov;
            size_t iovcnt = msg->msg_iovlen;
            if (iov_0 != NULL)
            {
                struct iovec *iov = new struct iovec[iovcnt];
                for (size_t i = 0; i < iovcnt; i++)
                {
                    iov[i].iov_base =
                        (void *)Decode((ADDRINT)iov_0[i].iov_base);
                    iov[i].iov_len  = iov_0[i].iov_len;
                }
                msg->msg_iov = iov;
            }
            msg->msg_control = (void *)Decode((ADDRINT)msg->msg_control);
            PIN_SetSyscallArgument(ctxt, std, 1, (ADDRINT)msg);
            tld->scratch[0] = (ADDRINT)msg;
            tld->scratch[1] = (ADDRINT)msg_0;
            break;
        }
        case SYS_sendmmsg:
        case SYS_recvmmsg:
        {
            PIN_SetSyscallArgument(ctxt, std, 4, Decode(tld->param[4]));
            struct mmsghdr *msgvec_0 =
                (struct mmsghdr *)Decode((ADDRINT)tld->param[1]);
            int vlen = (int)tld->param[2];
            if (msgvec_0 == NULL || vlen == 0)
                break;
            struct mmsghdr *msgvec = new struct mmsghdr[vlen];
            memcpy(msgvec, msgvec_0, vlen * sizeof(msgvec[0]));
            for (int i = 0; i < vlen; i++)
            {
                struct msghdr *msg = &msgvec[i].msg_hdr;
                msg->msg_name = (void *)Decode((ADDRINT)msg->msg_name);
                struct iovec *iov_0 = msg->msg_iov;
                size_t iovcnt = msg->msg_iovlen;
                if (iov_0 != NULL)
                {
                    struct iovec *iov = new struct iovec[iovcnt];
                    for (size_t i = 0; i < iovcnt; i++)
                    {
                        iov[i].iov_base =
                            (void *)Decode((ADDRINT)iov_0[i].iov_base);
                        iov[i].iov_len  = iov_0[i].iov_len;
                    }
                    msg->msg_iov = iov;
                }
                msg->msg_control = (void *)Decode((ADDRINT)msg->msg_control);
            }
            PIN_SetSyscallArgument(ctxt, std, 1, (ADDRINT)msgvec);
            tld->scratch[0] = (ADDRINT)msgvec;
            tld->scratch[1] = (ADDRINT)msgvec_0;
            tld->scratch[2] = (ADDRINT)vlen;
            break;
        }
        case SYS_execve:
        {
            PIN_SetSyscallArgument(ctxt, std, 0, Decode(tld->param[0]));
            const char **argv_0 = (const char **)Decode((ADDRINT)tld->param[1]);
            const char **envp_0 = (const char **)Decode((ADDRINT)tld->param[2]);
            size_t narg = 0, nenv = 0;
            for (; argv_0 != NULL && argv_0[narg] != NULL; narg++)
                ;
            for (; envp_0 != NULL && envp_0[nenv] != NULL; nenv++)
                ;
            char **argv = (narg == 0? NULL: new char *[narg+1]);
            char **envp = (narg == 0? NULL: new char *[nenv+1]);
            for (size_t i = 0; i < narg+1; i++)
                argv[i] = (char *)Decode((ADDRINT)argv_0[i]);
            for (size_t i = 0; i < nenv+1; i++)
                envp[i] = (char *)Decode((ADDRINT)envp_0[i]);
            PIN_SetSyscallArgument(ctxt, std, 1, (ADDRINT)argv);
            PIN_SetSyscallArgument(ctxt, std, 2, (ADDRINT)envp);
            tld->scratch[0] = (ADDRINT)argv;
            tld->scratch[1] = (ADDRINT)envp;
            break;
        }
        case /*SYS_execveat=*/322:
            error("syscall (%d) is not yet implemented", tld->num);
        default:
            // Generic translation:
            warning("unknown syscall (%d); using generic handler", tld->num);
            for (int i = 0; i < 6; i++)
                PIN_SetSyscallArgument(ctxt, std, i, Decode(tld->param[i]));
            break;
    }
}

void OnSyscallDone(THREADID tid, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
    ThreadData *tld = (ThreadData *)PIN_GetThreadData(tls_key, tid);
    for (int i = 0; i < 6; i++)
        PIN_SetSyscallArgument(ctxt, std, i, tld->param[i]);
    switch (tld->num)
    {
        case SYS_readv:
        case SYS_writev:
        {
            struct iovec *iov = (struct iovec *)tld->scratch[0];
            if (iov != NULL)
                delete[] iov;
            break;
        }
        case SYS_sendmsg:
        case SYS_recvmsg:
        {
            struct msghdr *msg   = (struct msghdr *)tld->scratch[0];
            struct msghdr *msg_0 = (struct msghdr *)tld->scratch[1];
            if (msg_0 != NULL && tld->num == SYS_recvmsg)
            {
                msg_0->msg_namelen    = msg->msg_namelen;
                msg_0->msg_controllen = msg->msg_controllen; 
                msg_0->msg_flags      = msg->msg_flags;
            }
            if (msg != NULL)
            {
                if (msg->msg_iov != NULL)
                    delete[] msg->msg_iov;
                delete msg;
            }
            break;
        }
        case SYS_sendmmsg:
        case SYS_recvmmsg:
        {
            struct mmsghdr *msgvec   = (struct mmsghdr *)tld->scratch[0];
            struct mmsghdr *msgvec_0 = (struct mmsghdr *)tld->scratch[1];
            int vlen                = (int)tld->scratch[2];
            if (msgvec == NULL || vlen == 0)
                break;
            for (int i = 0; i < vlen; i++)
            {
                struct mmsghdr *msg_0 = msgvec_0 + i;
                struct mmsghdr *msg   = msgvec   + i;
                if (tld->num == SYS_recvmsg)
                {
                    msg_0->msg_len                = msg->msg_len;
                    msg_0->msg_hdr.msg_namelen    = msg->msg_hdr.msg_namelen;
                    msg_0->msg_hdr.msg_controllen =
                        msg->msg_hdr.msg_controllen; 
                    msg_0->msg_hdr.msg_flags      = msg->msg_hdr.msg_flags;
                }
                if (msg->msg_hdr.msg_iov != NULL)
                    delete[] msg->msg_hdr.msg_iov;
            }
            delete[] msgvec;
            break;
        }
        case SYS_execve:
        {
            char **argv = (char **)tld->scratch[0];
            char **envp = (char **)tld->scratch[1];
            if (argv != NULL)
                delete[] argv;
            if (envp != NULL)
                delete[] envp;
            break;
        }
        default:
            break;
    }
    intptr_t value = (intptr_t)PIN_GetContextReg(ctxt, REG_RAX);
    if (value == -EFAULT)
        warning("syscall (%d) failed with error (%ld): %s",
            tld->num, value, strerror(-value));
}

EXCEPT_HANDLING_RESULT PinBugWorkaround(THREADID tid,
    EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v)
{
    if (pExceptInfo->GetExceptCode() != EXCEPTCODE_PRIVILEGED_INS)
        return EHR_CONTINUE_SEARCH;
    const REG gprs[] =
    {
        REG_RAX, REG_RCX, REG_RDX, REG_RBX,
        REG_RBP, REG_RSI, REG_RDI,
        REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15,
    };
    for (size_t i = 0; i < sizeof(gprs) / sizeof(gprs[0]); i++)
    {
        ADDRINT val = PIN_GetPhysicalContextReg(pPhysCtxt, gprs[i]);
        val = Decode(val);
        PIN_SetPhysicalContextReg(pPhysCtxt, gprs[i], val);
    }
    return EHR_HANDLED;
}

int main(int argc, char *argv[])
{
    if (getenv("BLUEFAT_DEBUG") != NULL)
        option_debug = true;

    // Initialize pin
    if (PIN_Init(argc, argv))
        return Usage();

    // Initialize BlueFat
    PIN_MutexInit(&mutex);
    bluefat_init();

    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Register PIN bug handler(s)
    PIN_AddInternalExceptionHandler(PinBugWorkaround, NULL);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Syscall Handling function - Entry
    PIN_AddSyscallEntryFunction(OnSyscall, NULL);

    // Syscall Handling function - Exit
    PIN_AddSyscallExitFunction(OnSyscallDone, NULL);

    // TLS key
    tls_key = PIN_CreateThreadDataKey(NULL);

    // Thread start handler
    PIN_AddThreadStartFunction(ThreadStart, NULL);

    // Thread exit handler
    PIN_AddThreadFiniFunction(ThreadFini, NULL);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}

