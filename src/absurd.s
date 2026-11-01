// absurd — a static-file HTTP/1.1 server in AArch64 assembly for Linux, on io_uring.
//
// Startup (single thread, before any socket is accepted):
//   * bind one SO_REUSEPORT listener per thread, then drop to uid/gid 65534
//   * walk the document root with O_NOFOLLOW (no symlinks, no dotfiles, regular
//     files only) and load every file into one arena together with its
//     pre-rendered response headers and an ETag; index it in a seeded hash table
//   * mprotect the arena read-only
//
// Serving (one pinned thread per CPU, nothing shared but the read-only arena):
//   * every thread restricts its io_uring to six opcodes, then installs a
//     seccomp filter that allows only io_uring_enter, clock_gettime and exit;
//     the filesystem is unreachable at request time, so traversal is
//     impossible by construction: only paths in the table exist
//   * multishot accept into a fixed-file table, recv into a per-connection
//     buffer, sendmsg of [headers | Date line | body] straight from the arena
//   * a NEON pass finds the end of each header block and rejects control
//     bytes, bare CR and bare LF in the same sweep
//   * the Date header is double-buffered and refreshed by a 1 s multishot timer,
//     which also enforces header/idle/send timeouts

// ---------------------------------------------------------------- syscalls
        .equ SYS_getcwd,             17
        .equ SYS_close,              57
        .equ SYS_openat,             56
        .equ SYS_getdents64,         61
        .equ SYS_read,               63
        .equ SYS_write,              64
        .equ SYS_newfstatat,         79
        .equ SYS_fstat,              80
        .equ SYS_exit,               93
        .equ SYS_exit_group,         94
        .equ SYS_clock_gettime,      113
        .equ SYS_sched_setaffinity,  122
        .equ SYS_sched_getaffinity,  123
        .equ SYS_rt_sigreturn,       139
        .equ SYS_setgid,             144
        .equ SYS_setuid,             146
        .equ SYS_setgroups,          159
        .equ SYS_prctl,              167
        .equ SYS_getuid,             174
        .equ SYS_socket,             198
        .equ SYS_bind,               200
        .equ SYS_listen,             201
        .equ SYS_setsockopt,         208
        .equ SYS_clone,              220
        .equ SYS_mmap,               222
        .equ SYS_mprotect,           226
        .equ SYS_prlimit64,          261
        .equ SYS_seccomp,            277
        .equ SYS_getrandom,          278
        .equ SYS_io_uring_setup,     425
        .equ SYS_io_uring_enter,     426
        .equ SYS_io_uring_register,  427

        .equ AT_FDCWD,               -100
        .equ O_DIR_FLAGS,            0x8c000  // O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC
        .equ O_ROOT_FLAGS,           0x84000  // O_RDONLY|O_DIRECTORY|O_CLOEXEC
        .equ O_FILE_FLAGS,           0x88800  // O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK
        .equ AT_SYMLINK_NOFOLLOW,    0x100
        .equ DT_UNKNOWN,             0
        .equ DT_DIR,                 4
        .equ DT_REG,                 8
        .equ ST_MODE,                16
        .equ ST_SIZE,                48
        .equ ST_INO,                 8
        .equ ST_MTIME,               88
        .equ ST_MTIME_NSEC,          96

        .equ NOBODY,                 65534

// ---------------------------------------------------------------- io_uring ABI
        .equ SETUP_CQSIZE,           1 << 3
        .equ SETUP_CLAMP,            1 << 4
        .equ SETUP_R_DISABLED,       1 << 6
        .equ SETUP_SUBMIT_ALL,       1 << 7
        .equ SETUP_COOP_TASKRUN,     1 << 8
        .equ SETUP_SINGLE_ISSUER,    1 << 12
        .equ SETUP_DEFER_TASKRUN,    1 << 13
        .equ SETUP_NO_SQARRAY,       1 << 16
        .equ SETUP_FLAGS, SETUP_CQSIZE | SETUP_CLAMP | SETUP_R_DISABLED | SETUP_SUBMIT_ALL | SETUP_COOP_TASKRUN | SETUP_SINGLE_ISSUER | SETUP_DEFER_TASKRUN | SETUP_NO_SQARRAY

        .equ ENTER_GETEVENTS,        1
        .equ ENTER_REGISTERED_RING,  1 << 4

        .equ REG_RESTRICTIONS,       11
        .equ REG_ENABLE_RINGS,       12
        .equ REG_FILES2,             13
        .equ REG_RING_FDS,           20

        .equ OP_SENDMSG,             9
        .equ OP_TIMEOUT,             11
        .equ OP_ACCEPT,              13
        .equ OP_CLOSE,               19
        .equ OP_RECV,                27
        .equ OP_ASYNC_CANCEL,        14
        .equ OP_SHUTDOWN,            34

        .equ OFF_SQES,               0x10000000

        .equ P_SQ_ENTRIES,           0
        .equ P_CQ_ENTRIES,           4
        .equ P_FLAGS,                8
        .equ P_SQ_TAIL,              44
        .equ P_SQ_MASK,              48
        .equ P_CQ_HEAD,              80
        .equ P_CQ_TAIL,              84
        .equ P_CQ_MASK,              88
        .equ P_CQ_CQES,              100

        .equ CQE_F_MORE_BIT,         1

        // First 8 bytes of an SQE: opcode | flags<<8 | ioprio<<16 | fd<<32
        .equ SQE_ACCEPT_LO,          0x000d   // ACCEPT, ioprio = ACCEPT_MULTISHOT
        .equ SQE_ACCEPT_HI,          0x0001
        .equ SQE_RECV,               0x011b   // RECV, FIXED_FILE
        .equ SQE_SENDMSG,            0x0109   // SENDMSG, FIXED_FILE
        .equ SQE_CLOSE,              0x4013   // CLOSE, CQE_SKIP_SUCCESS
        .equ SQE_CANCEL,             0x400e   // ASYNC_CANCEL, CQE_SKIP_SUCCESS
        .equ CANCEL_ALL_FIXED_FD,    0xb      // CANCEL_ALL | CANCEL_FD | CANCEL_FD_FIXED
        .equ SQE_SHUTDOWN_LINK,      0x4922   // SHUTDOWN, FIXED_FILE|IO_HARDLINK|CQE_SKIP_SUCCESS
        .equ SQE_TIMEOUT,            0x000b
        .equ RECV_POLL_FIRST,        1
        .equ MSG_WAITALL_NOSIGNAL,   0x4100
        .equ TIMEOUT_MULTISHOT,      1 << 6

// ---------------------------------------------------------------- user_data tags
        .equ T_ACCEPT,               1
        .equ T_RECV,                 2
        .equ T_TIMER,                3
        .equ T_SEND,                 4
        .equ T_CLOSE,                5
        .equ T_SHUT,                 6

// ---------------------------------------------------------------- tuning
        .equ PORT_DEFAULT,           8080
        .equ MAX_THREADS,            256
        .equ BACKLOG,                65535
        .equ STACK_SIZE,             65536
        .equ SQ_ENTRIES,             4096
        .equ CQ_ENTRIES,             16384
        .equ CQ_BATCH,               1024
        .equ MAXCONN,                8192     // fixed-file slots per thread
        .equ CONN_SHIFT,             14       // 16 KiB of buffers per connection
        .equ MAXIOV,                 48       // 16 responses per sendmsg
        .equ S_MSGA,                 0        // struct msghdr x2
        .equ S_MSGB,                 64
        .equ S_IOVA,                 128      // struct iovec[MAXIOV] x2
        .equ S_IOVB,                 S_IOVA + MAXIOV * 16
        .equ S_IN,                   S_IOVB + MAXIOV * 16
        .equ BUFCAP,                 (1 << CONN_SHIFT) - S_IN - 64   // request bytes held at once
        .equ CHUNK,                  1 << 20  // bodies go out 1 MiB per sendmsg
        .equ PATHMAX,                2048
        .equ TO_HEADER,              15       // seconds to deliver a full header block
        .equ TO_IDLE,                30       // idle keep-alive
        .equ TO_SEND,                60       // a single send may take this long

        .equ TABLE_SLOTS,            1 << 17
        .equ MAX_ENTRIES,            TABLE_SLOTS / 2
        .equ TABLE_BYTES,            TABLE_SLOTS * 64
        .equ SNAP_MAX,               1 << 30  // file bytes kept in memory
        .equ ARENA_RESERVE,          TABLE_BYTES + SNAP_MAX + (MAX_ENTRIES * 1024)
        .equ URLMAX,                 3800
        .equ MAXDEPTH,               24
        .equ DENTBUF,                16384

// ---------------------------------------------------------------- table entry (64 B)
        .equ E_HASH,                 0
        .equ E_KEY,                  8
        .equ E_KEYLEN,               16
        .equ E_FLAGS,                20
        .equ E_HDR,                  24
        .equ E_HDRLEN,               32
        .equ E_H304LEN,              36
        .equ E_H304,                 40
        .equ E_BODY,                 48
        .equ E_BODYLEN,              56
        .equ EF_ETAG_BIT,            0
        .equ EF_CLOSE_BIT,           1

// ---------------------------------------------------------------- parse result flags
        .equ R_NOBODY,               1
        .equ R_304,                  2
        .equ R_CLOSE,                4
        .equ R_KA,                   8
        .equ R_V11,                  16
        .equ R_HOST,                 32
        .equ R_CCLOSE,               64
        .equ R_CKA,                  128
        .equ R_NOBODY_BIT,           0
        .equ R_304_BIT,              1
        .equ R_CLOSE_BIT,            2
        .equ R_KA_BIT,               3
        .equ R_V11_BIT,              4
        .equ R_HOST_BIT,             5
        .equ R_CCLOSE_BIT,           6
        .equ R_CKA_BIT,              7

// ---------------------------------------------------------------- per-connection meta (64 B)
        .equ M_FILL,                 0
        .equ M_POS,                  4
        .equ M_FLAGS,                8
        .equ M_IOVCNT,               12
        .equ M_ACC,                  16       // which iovec array is accumulating
        .equ M_LAST,                 20       // last progress (s)
        .equ M_RSTART,               24       // first byte of the current partial request (s)
        .equ M_CONTLEN,              32       // body bytes still to send
        .equ M_CONTPTR,              40
        .equ F_ACTIVE,               1
        .equ F_RECV,                 2        // recv in flight
        .equ F_SEND,                 4        // sendmsg in flight
        .equ F_CLOSING,              8        // tear down as soon as nothing is in flight
        .equ F_DRAIN,                16       // no more input; close once output is flushed
        .equ F_SHUT,                 32       // in-flight ops already cancelled
        .equ F_PARTIAL,              64
        .equ F_RECV_BIT,             1
        .equ F_SEND_BIT,             2
        .equ F_CLOSING_BIT,          3
        .equ F_DRAIN_BIT,            4
        .equ F_SHUT_BIT,             5
        .equ F_PARTIAL_BIT,          6

// ---------------------------------------------------------------- per-thread context
        .equ C_ENTERFD,              0
        .equ C_ENTERFL,              4
        .equ C_LISTEN,               8
        .equ C_SUBMITTED,            12
        .equ C_SQTAILP,              16
        .equ C_CQHEADP,              24
        .equ C_CQTAILP,              32
        .equ C_DATE,                 40
        .equ C_DATEA,                48
        .equ C_DATEB,                56
        .equ C_RINGFD,               64
        .equ C_NOWSEC,               68
        .equ C_TS,                   72
        .equ C_NOW,                  88
        .equ C_ACCPAUSE,             104
        .equ C_PARAMS,               128
        .equ C_REG,                  256
        .equ C_BLOBS,                512      // 2 x 192 B of Date lines
        .equ C_PATH,                 1024     // decoded request path
        .equ O_META,                 4096
        .equ CTX_SIZE,               O_META + MAXCONN * 64

        // Date line variants inside each 192 B blob
        .equ D0_LEN,                 39       // Date: ...\r\n\r\n
        .equ D1_LEN,                 58       // Date: ...\r\nConnection: close\r\n\r\n
        .equ D2_LEN,                 63       // Date: ...\r\nConnection: keep-alive\r\n\r\n

// Hot-loop register map (worker):
//   x28 ctx     x19 sqes     w20 sq tail   w21 sq mask
//   x22 cqes    w23 cq head  w24 cq mask   x25 connection buffers
//   x26 connection meta      w18 cq batch end
//   v28 '\n' x16  v29 '\r' x16  v31 zero

        .macro SYSCALL nr
        mov     x8, #\nr
        svc     #0
        .endm

        .macro ADDR reg, sym
        adrp    \reg, \sym
        add     \reg, \reg, :lo12:\sym
        .endm

        .macro CHECK msg
        ADDR    x1, \msg
        tbnz    x0, #63, die
        .endm

        .macro GET_SQE reg
        ldr     w9, [x28, #C_SUBMITTED]
        sub     w9, w20, w9
        cmp     w9, #SQ_ENTRIES
        b.lo    .Lsq\@
        str     x30, [sp, #-16]!
        bl      sqe_flush
        ldr     x30, [sp], #16
.Lsq\@:
        and     w9, w20, w21
        add     \reg, x19, x9, lsl #6
        add     w20, w20, #1
        stp     q31, q31, [\reg]
        stp     q31, q31, [\reg, #32]
        .endm

        // seeded multiply-xorshift over 8-byte words -> x2 (clobbers x0,x1,x3-x5)
        .macro HASH ptr, len
        ADDR    x0, g_seed
        ldr     x2, [x0]
        ldr     x3, =0x9e3779b97f4a7c15
        mul     x0, \len, x3
        eor     x2, x2, x0
        mov     x1, \ptr
        mov     x4, \len
.Lh1\@: cmp     x4, #8
        b.lo    .Lh2\@
        ldr     x0, [x1], #8
        eor     x2, x2, x0
        mul     x2, x2, x3
        eor     x2, x2, x2, lsr #29
        sub     x4, x4, #8
        b       .Lh1\@
.Lh2\@: cbz     x4, .Lh3\@
        ldr     x0, [x1]
        lsl     x5, x4, #3
        mov     x4, #1
        lsl     x4, x4, x5
        sub     x4, x4, #1
        and     x0, x0, x4
        eor     x2, x2, x0
        mul     x2, x2, x3
        eor     x2, x2, x2, lsr #29
.Lh3\@: eor     x2, x2, x2, lsr #32
        mul     x2, x2, x3
        eor     x2, x2, x2, lsr #29
        .endm

        .macro HEXV r
        sub     w7, \r, #'0'
        cmp     w7, #9
        b.ls    .Lx\@
        orr     w7, \r, #0x20
        sub     w7, w7, #'a'
        cmp     w7, #5
        b.hi    err400
        add     w7, w7, #10
.Lx\@:  mov     \r, w7
        .endm

        .macro SBLIT s
        ADDR    x0, \s
        mov     x1, #(\s\()_end - \s)
        bl      sb_str
        .endm

        // banner helper: copy a literal to x1 (x1 advances)
        .macro SBLIT_LINE s
        ADDR    x2, \s
        mov     x3, #(\s\()_end - \s)
        bl      append
        .endm

// ======================================================================== main
        .text
        .global _start
_start:
        ldr     x19, [sp]                   // argc
        add     x20, sp, #8                 // argv
        mov     w21, #PORT_DEFAULT
        mov     w22, #0                     // threads: auto
        ADDR    x23, s_dot                  // document root
        mov     x24, #1
a_loop: cmp     x24, x19
        b.hs    a_done
        ldr     x0, [x20, x24, lsl #3]
        ldrh    w1, [x0]
        ldrb    w2, [x0, #2]
        cbnz    w2, a_root
        mov     w3, #0x702d                 // "-p"
        cmp     w1, w3
        b.eq    a_port
        mov     w3, #0x742d                 // "-t"
        cmp     w1, w3
        b.eq    a_thr
        mov     w3, #0x682d                 // "-h"
        cmp     w1, w3
        b.eq    usage
a_root: mov     x23, x0
        add     x24, x24, #1
        b       a_loop
a_port: add     x24, x24, #1
        cmp     x24, x19
        b.hs    usage
        ldr     x0, [x20, x24, lsl #3]
        bl      parse_uint
        cbz     w0, usage
        mov     w1, #0xffff
        cmp     w0, w1
        b.hi    usage
        mov     w21, w0
        add     x24, x24, #1
        b       a_loop
a_thr:  add     x24, x24, #1
        cmp     x24, x19
        b.hs    usage
        ldr     x0, [x20, x24, lsl #3]
        bl      parse_uint
        cbz     w0, usage
        mov     w22, w0
        cmp     w22, #MAX_THREADS
        b.ls    1f
        mov     w22, #MAX_THREADS
1:      add     x24, x24, #1
        b       a_loop
a_done:
        ADDR    x0, g_root
        str     x23, [x0]

        // hash seed
        ADDR    x0, g_seed
        mov     x1, #8
        mov     x2, #0
        SYSCALL SYS_getrandom

        // CPUs we may run on
        mov     x0, #0
        mov     x1, #128
        ADDR    x2, g_affbuf
        SYSCALL SYS_sched_getaffinity
        ADDR    x3, g_cpus
        mov     w4, #0
        cmp     x0, #0
        b.le    3f
        lsl     x5, x0, #3
        mov     x6, #0
        ADDR    x2, g_affbuf
2:      lsr     x7, x6, #3
        ldrb    w7, [x2, x7]
        and     x9, x6, #7
        lsr     w7, w7, w9
        tbz     w7, #0, 4f
        cmp     w4, #MAX_THREADS
        b.hs    4f
        str     w6, [x3, x4, lsl #2]
        add     w4, w4, #1
4:      add     x6, x6, #1
        cmp     x6, x5
        b.lo    2b
3:      cbnz    w4, 5f
        str     wzr, [x3]
        mov     w4, #1
5:      ADDR    x3, g_ncpus
        str     w4, [x3]
        cbnz    w22, 6f
        mov     w22, w4
6:      ADDR    x3, g_nthreads
        str     w22, [x3]

        // RLIMIT_NOFILE soft := hard (fixed-file tables are checked against it)
        mov     x0, #0
        mov     x1, #7
        mov     x2, #0
        ADDR    x3, g_rlim
        SYSCALL SYS_prlimit64
        ADDR    x3, g_rlim
        ldr     x4, [x3, #8]
        str     x4, [x3]
        mov     x0, #0
        mov     x1, #7
        mov     x2, x3
        mov     x3, #0
        SYSCALL SYS_prlimit64

        // one SO_REUSEPORT listener per thread, in thread order
        ADDR    x0, g_one
        mov     w1, #1
        str     w1, [x0]
        ADDR    x0, g_sockaddr
        mov     w1, #2                      // AF_INET
        strh    w1, [x0]
        rev16   w2, w21
        strh    w2, [x0, #2]
        str     xzr, [x0, #4]
        str     wzr, [x0, #12]
        mov     w23, #0
7:      mov     x0, #2
        mov     x1, #1
        mov     x2, #0
        SYSCALL SYS_socket
        CHECK   m_socket
        mov     w24, w0
        mov     x1, #1                      // SOL_SOCKET
        mov     x2, #2                      // SO_REUSEADDR
        bl      setopt_one
        mov     x1, #1
        mov     x2, #15                     // SO_REUSEPORT
        bl      setopt_one
        mov     x1, #6                      // IPPROTO_TCP
        mov     x2, #1                      // TCP_NODELAY (inherited by accepted sockets)
        bl      setopt_one
        mov     w0, w24
        ADDR    x1, g_sockaddr
        mov     x2, #16
        SYSCALL SYS_bind
        CHECK   m_bind
        mov     w0, w24
        mov     x1, #BACKLOG
        SYSCALL SYS_listen
        CHECK   m_listen
        ADDR    x3, g_lfds
        str     w24, [x3, x23, lsl #2]
        add     w23, w23, #1
        cmp     w23, w22
        b.lo    7b

        // CPU steering: thread i on CPU i for all i -> "ld [SKF_AD_CPU]; ret A"
        ADDR    x3, g_ncpus
        ldr     w4, [x3]
        cmp     w4, w22
        b.ne    8f
        ADDR    x3, g_cpus
        sub     w5, w4, #1
        ldr     w6, [x3, x5, lsl #2]
        cmp     w6, w5
        b.ne    8f
        ADDR    x3, g_lfds
        ldr     w0, [x3]
        mov     x1, #1
        mov     x2, #51                     // SO_ATTACH_REUSEPORT_CBPF
        ADDR    x3, g_fprog
        ADDR    x4, g_bpf
        str     x4, [x3, #8]
        mov     x4, #16
        SYSCALL SYS_setsockopt
        ADDR    x0, g_steer
        mov     w1, #1
        str     w1, [x0]
8:
        // drop root before touching the document root
        SYSCALL SYS_getuid
        cbnz    x0, 9f
        mov     x0, #0
        mov     x1, #0
        SYSCALL SYS_setgroups
        CHECK   m_priv
        mov     x0, #NOBODY
        SYSCALL SYS_setgid
        CHECK   m_priv
        mov     x0, #NOBODY
        SYSCALL SYS_setuid
        CHECK   m_priv
        ADDR    x0, g_dropped
        mov     w1, #1
        str     w1, [x0]
9:
        bl      load_root

        // banner
        ADDR    x1, g_line
        SBLIT_LINE s_b1
        ADDR    x0, g_nfiles
        ldr     x0, [x0]
        bl      utoa
        SBLIT_LINE s_b2
        ADDR    x0, g_bytes
        ldr     x0, [x0]
        bl      utoa
        SBLIT_LINE s_b3
        ADDR    x2, g_root
        ldr     x2, [x2]
10:     ldrb    w4, [x2], #1
        cbz     w4, 11f
        strb    w4, [x1], #1
        b       10b
11:     SBLIT_LINE s_b4
        mov     w0, w21
        bl      utoa
        SBLIT_LINE s_b5
        mov     w0, w22
        bl      utoa
        SBLIT_LINE s_b6
        ADDR    x0, g_steer
        ldr     w0, [x0]
        cbz     w0, 12f
        SBLIT_LINE s_b7
12:     ADDR    x0, g_dropped
        ldr     w0, [x0]
        cbz     w0, 13f
        SBLIT_LINE s_b8
13:     ADDR    x0, g_skipped
        ldr     x0, [x0]
        cbz     x0, 14f
        mov     x9, x0
        SBLIT_LINE s_b9
        mov     x0, x9
        bl      utoa
        SBLIT_LINE s_b10
14:     mov     w0, #'\n'
        strb    w0, [x1], #1
        ADDR    x0, g_line
        sub     x2, x1, x0
        mov     x1, x0
        mov     x0, #1
        SYSCALL SYS_write

        // no privilege regain, no core dumps / ptrace by other uids
        mov     x0, #38                     // PR_SET_NO_NEW_PRIVS
        mov     x1, #1
        mov     x2, #0
        mov     x3, #0
        mov     x4, #0
        SYSCALL SYS_prctl
        CHECK   m_seccomp
        mov     x0, #4                      // PR_SET_DUMPABLE
        mov     x1, #0
        SYSCALL SYS_prctl

        // spawn threads 1..n-1; the main thread becomes worker 0
        mov     w23, #1
15:     cmp     w23, w22
        b.hs    16f
        mov     x0, #0
        mov     x1, #STACK_SIZE
        mov     x2, #3
        mov     x3, #0x22
        movk    x3, #0x2, lsl #16           // MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK
        mov     x4, #-1
        mov     x5, #0
        SYSCALL SYS_mmap
        CHECK   m_mmap
        add     x1, x0, #STACK_SIZE
        ldr     x0, =0x50f00                // VM|FS|FILES|SIGHAND|THREAD|SYSVSEM
        mov     x2, #0
        mov     x3, #0
        mov     x4, #0
        SYSCALL SYS_clone
        cbz     x0, 17f
        CHECK   m_clone
        add     w23, w23, #1
        b       15b
16:     mov     w0, #0
        b       worker
17:     mov     w0, w23
        b       worker

usage:
        ADDR    x1, s_usage
        mov     x2, #(s_usage_end - s_usage)
        mov     x0, #2
        SYSCALL SYS_write
        mov     x0, #2
        SYSCALL SYS_exit_group

setopt_one:
        mov     w0, w24
        ADDR    x3, g_one
        mov     x4, #4
        SYSCALL SYS_setsockopt
        ret

// ======================================================================== worker
worker:
        mov     w27, w0

        // pin to cpus[id % ncpus]
        ADDR    x3, g_ncpus
        ldr     w4, [x3]
        udiv    w5, w27, w4
        msub    w5, w5, w4, w27
        ADDR    x3, g_cpus
        ldr     w5, [x3, x5, lsl #2]
        sub     sp, sp, #128
        mov     x6, sp
        movi    v31.16b, #0
        stp     q31, q31, [x6]
        stp     q31, q31, [x6, #32]
        stp     q31, q31, [x6, #64]
        stp     q31, q31, [x6, #96]
        lsr     w7, w5, #3
        and     w8, w5, #7
        mov     w9, #1
        lsl     w9, w9, w8
        strb    w9, [x6, x7]
        mov     x0, #0
        mov     x1, #128
        mov     x2, x6
        SYSCALL SYS_sched_setaffinity
        add     sp, sp, #128

        // context + connection meta (populated), connection buffers (on demand)
        mov     x0, #0
        ldr     x1, =CTX_SIZE
        mov     x2, #3
        mov     x3, #0x8022                 // MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE
        mov     x4, #-1
        mov     x5, #0
        SYSCALL SYS_mmap
        ADDR    x1, m_mmap
        cmn     x0, #4095
        b.hs    die
        mov     x28, x0
        add     x26, x28, #O_META

        mov     x0, #0
        mov     x1, #(MAXCONN << CONN_SHIFT)
        mov     x2, #3
        mov     x3, #0x4022                 // MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE
        mov     x4, #-1
        mov     x5, #0
        SYSCALL SYS_mmap
        ADDR    x1, m_mmap
        cmn     x0, #4095
        b.hs    die
        mov     x25, x0

        ADDR    x3, g_lfds
        ldr     w0, [x3, x27, lsl #2]
        str     w0, [x28, #C_LISTEN]

        // io_uring, created disabled so it can be restricted before first use
        add     x1, x28, #C_PARAMS
        ldr     w2, =SETUP_FLAGS
        str     w2, [x1, #P_FLAGS]
        mov     w2, #CQ_ENTRIES
        str     w2, [x1, #P_CQ_ENTRIES]
        mov     x0, #SQ_ENTRIES
        SYSCALL SYS_io_uring_setup
        CHECK   m_setup
        str     w0, [x28, #C_RINGFD]
        str     w0, [x28, #C_ENTERFD]
        mov     w1, #ENTER_GETEVENTS
        str     w1, [x28, #C_ENTERFL]

        add     x10, x28, #C_PARAMS
        ldr     w1, [x10, #P_CQ_CQES]
        ldr     w2, [x10, #P_CQ_ENTRIES]
        add     x1, x1, x2, lsl #4
        mov     x4, x0
        mov     x0, #0
        mov     x2, #3
        mov     x3, #0x8001                 // MAP_SHARED|MAP_POPULATE
        mov     x5, #0
        SYSCALL SYS_mmap
        ADDR    x1, m_mmap
        cmn     x0, #4095
        b.hs    die
        mov     x11, x0

        ldr     w1, [x10, #P_SQ_ENTRIES]
        lsl     x1, x1, #6
        mov     x0, #0
        mov     x2, #3
        mov     x3, #0x8001
        ldr     w4, [x28, #C_RINGFD]
        mov     x5, #OFF_SQES
        SYSCALL SYS_mmap
        ADDR    x1, m_mmap
        cmn     x0, #4095
        b.hs    die
        mov     x19, x0

        ldr     w1, [x10, #P_SQ_TAIL]
        add     x1, x11, x1
        str     x1, [x28, #C_SQTAILP]
        ldr     w20, [x1]
        str     w20, [x28, #C_SUBMITTED]
        ldr     w1, [x10, #P_SQ_MASK]
        ldr     w21, [x11, x1]
        ldr     w1, [x10, #P_CQ_HEAD]
        add     x1, x11, x1
        str     x1, [x28, #C_CQHEADP]
        ldr     w23, [x1]
        ldr     w1, [x10, #P_CQ_TAIL]
        add     x1, x11, x1
        str     x1, [x28, #C_CQTAILP]
        ldr     w1, [x10, #P_CQ_MASK]
        ldr     w24, [x11, x1]
        ldr     w1, [x10, #P_CQ_CQES]
        add     x22, x11, x1

        // sparse fixed-file table: accepted sockets never enter the fd table
        add     x2, x28, #C_REG
        mov     w0, #MAXCONN
        str     w0, [x2]
        mov     w0, #1                      // IORING_RSRC_REGISTER_SPARSE
        str     w0, [x2, #4]
        ldr     w0, [x28, #C_RINGFD]
        mov     x1, #REG_FILES2
        mov     x3, #32
        SYSCALL SYS_io_uring_register
        CHECK   m_files

        // register the ring fd itself, so io_uring_enter skips fdget()
        add     x2, x28, #C_REG
        mov     w0, #-1
        str     w0, [x2]
        str     wzr, [x2, #4]
        ldr     w0, [x28, #C_RINGFD]
        str     x0, [x2, #8]
        mov     x1, #REG_RING_FDS
        mov     x3, #1
        SYSCALL SYS_io_uring_register
        cmp     x0, #1
        b.ne    1f
        add     x2, x28, #C_REG
        ldr     w0, [x2]
        str     w0, [x28, #C_ENTERFD]
        mov     w0, #(ENTER_GETEVENTS | ENTER_REGISTERED_RING)
        str     w0, [x28, #C_ENTERFL]
1:
        // only these opcodes and SQE flags, and no further io_uring_register
        add     x2, x28, #C_REG
        mov     x3, x2
        ADDR    x4, g_restrict
        mov     x5, #8
2:      ldrh    w6, [x4]
        ldrb    w7, [x4, #2]
        add     x4, x4, #4
        stp     xzr, xzr, [x3]
        strh    w6, [x3]                    // restriction kind
        strb    w7, [x3, #2]                // opcode / flags
        add     x3, x3, #16
        subs    x5, x5, #1
        b.ne    2b
        ldr     w0, [x28, #C_RINGFD]
        mov     x1, #REG_RESTRICTIONS
        mov     x3, #8
        SYSCALL SYS_io_uring_register
        CHECK   m_restrict
        ldr     w0, [x28, #C_RINGFD]
        mov     x1, #REG_ENABLE_RINGS
        mov     x2, #0
        mov     x3, #0
        SYSCALL SYS_io_uring_register
        CHECK   m_restrict

        // Date lines: both blobs from the templates, then render twice
        add     x0, x28, #C_BLOBS
        str     x0, [x28, #C_DATEA]
        str     x0, [x28, #C_DATE]
        bl      fill_dates
        add     x0, x28, #(C_BLOBS + 192)
        str     x0, [x28, #C_DATEB]
        bl      fill_dates
        mov     x0, #1
        str     x0, [x28, #C_TS]
        str     xzr, [x28, #C_TS + 8]
        bl      update_date
        bl      update_date

        // seccomp: from here on only io_uring_enter, clock_gettime and exit
        mov     x0, #1                      // SECCOMP_SET_MODE_FILTER
        mov     x1, #0
        ADDR    x2, g_scprog
        ADDR    x3, g_scfilter
        str     x3, [x2, #8]
        SYSCALL SYS_seccomp
        CHECK   m_seccomp

        movi    v31.16b, #0
        movi    v28.16b, #0x0a
        movi    v29.16b, #0x0d
        bl      queue_accept
        bl      queue_timer

// ------------------------------------------------------------------------ loop
        .p2align 6
loop:
        ldr     x0, [x28, #C_SQTAILP]
        stlr    w20, [x0]
        ldr     w1, [x28, #C_SUBMITTED]
        sub     w1, w20, w1
        str     w20, [x28, #C_SUBMITTED]
        ldr     w0, [x28, #C_ENTERFD]
        mov     w2, #1
        ldr     w3, [x28, #C_ENTERFL]
        mov     x4, #0
        mov     x5, #0
        SYSCALL SYS_io_uring_enter
        ldr     x0, [x28, #C_CQTAILP]
        ldar    w18, [x0]
        sub     w1, w18, w23
        cmp     w1, #CQ_BATCH
        b.ls    cq_next
        add     w18, w23, #CQ_BATCH
cq_next:
        cmp     w23, w18
        b.eq    cq_done
        and     w9, w23, w24
        add     x9, x22, x9, lsl #4
        ldr     x0, [x9]                    // user_data
        ldp     w1, w2, [x9, #8]            // res, flags
        add     w23, w23, #1
        and     w3, w0, #0xff
        cmp     w3, #T_RECV
        b.eq    on_recv
        cmp     w3, #T_SEND
        b.eq    on_send
        cmp     w3, #T_ACCEPT
        b.eq    on_accept
        cmp     w3, #T_TIMER
        b.eq    on_timer
        b       cq_next
cq_done:
        ldr     x0, [x28, #C_CQHEADP]
        stlr    w23, [x0]
        b       loop

// ------------------------------------------------------------------------ handlers
on_recv:
        ubfx    x4, x0, #8, #24
        add     x3, x26, x4, lsl #6
        ldr     w5, [x3, #M_FLAGS]
        bic     w5, w5, #F_RECV
        cmp     w1, #0
        b.gt    1f
        orr     w6, w5, #F_DRAIN            // EOF: flush what we owe, then close
        orr     w7, w5, #F_CLOSING          // error: just close
        csel    w5, w6, w7, eq
        str     w5, [x3, #M_FLAGS]
        b       2f
1:      str     w5, [x3, #M_FLAGS]
        ldr     w6, [x3, #M_FILL]
        add     w6, w6, w1
        str     w6, [x3, #M_FILL]
        ldr     w6, [x28, #C_NOWSEC]
        str     w6, [x3, #M_LAST]
2:      mov     w0, w4
        bl      process
        b       cq_next

on_send:
        ubfx    x4, x0, #8, #24
        add     x3, x26, x4, lsl #6
        ldr     w5, [x3, #M_FLAGS]
        bic     w5, w5, #F_SEND
        orr     w6, w5, #F_CLOSING
        cmp     w1, #0
        csel    w5, w6, w5, lt
        str     w5, [x3, #M_FLAGS]
        ldr     w6, [x28, #C_NOWSEC]
        str     w6, [x3, #M_LAST]
        mov     w0, w4
        bl      process
        b       cq_next

on_accept:
        tbnz    w1, #31, 2f
        mov     w4, w1
        add     x3, x26, x4, lsl #6
        stp     q31, q31, [x3]
        stp     q31, q31, [x3, #32]
        mov     w5, #F_ACTIVE
        str     w5, [x3, #M_FLAGS]
        ldr     w5, [x28, #C_NOWSEC]
        str     w5, [x3, #M_LAST]
        add     x5, x25, x4, lsl #CONN_SHIFT
        stp     q31, q31, [x5, #S_MSGA]
        stp     q31, q31, [x5, #S_MSGA + 32]
        stp     q31, q31, [x5, #S_MSGB]
        stp     q31, q31, [x5, #S_MSGB + 32]
        mov     w0, w4
        mov     w1, #0
        bl      arm_recv
        tbnz    w2, #CQE_F_MORE_BIT, cq_next
        bl      queue_accept
        b       cq_next
2:      tbnz    w2, #CQE_F_MORE_BIT, cq_next
        mov     w0, #1                      // table full or error: retry on the next tick
        str     w0, [x28, #C_ACCPAUSE]
        b       cq_next

on_timer:
        mov     w17, w2
        bl      update_date
        bl      sweep
        ldr     w0, [x28, #C_ACCPAUSE]
        cbz     w0, 1f
        str     wzr, [x28, #C_ACCPAUSE]
        bl      queue_accept
1:      tbnz    w17, #CQE_F_MORE_BIT, cq_next
        bl      queue_timer
        b       cq_next

// ------------------------------------------------------------------------ connection logic
// process(w0 = conn): parse buffered requests, queue responses, keep one
// sendmsg in flight, re-arm recv when there is room, tear down when done.
process:
        stp     x29, x30, [sp, #-64]!
        mov     w1, w0
        str     x1, [sp, #16]
        add     x2, x26, x1, lsl #6
        str     x2, [sp, #24]
        add     x3, x25, x1, lsl #CONN_SHIFT
        str     x3, [sp, #32]
        add     x4, x3, #S_IN
        str     x4, [sp, #40]
        str     xzr, [sp, #48]              // 0: input exhausted, 1: blocked on output
p_top:
        ldr     x2, [sp, #24]
        ldr     w5, [x2, #M_FLAGS]
        tbnz    w5, #F_CLOSING_BIT, p_tail
        ldr     x6, [x2, #M_CONTLEN]
        cbz     x6, p_parse
        // a large body is still going out
        tbnz    w5, #F_SEND_BIT, p_blocked
        ldr     w7, [x2, #M_IOVCNT]
        cbnz    w7, p_blocked
        ldr     w8, [x2, #M_ACC]
        ldr     x3, [sp, #32]
        mov     x9, #S_IOVA
        mov     x10, #S_IOVB
        cmp     w8, #0
        csel    x9, x9, x10, eq
        add     x9, x3, x9
        ldr     x10, [x2, #M_CONTPTR]
        mov     x11, #CHUNK
        cmp     x6, x11
        csel    x11, x6, x11, lo
        stp     x10, x11, [x9]
        mov     w7, #1
        str     w7, [x2, #M_IOVCNT]
        add     x10, x10, x11
        sub     x6, x6, x11
        str     x10, [x2, #M_CONTPTR]
        str     x6, [x2, #M_CONTLEN]
        cbnz    x6, p_blocked
p_parse:
        ldr     x2, [sp, #24]
        ldr     w5, [x2, #M_FLAGS]
        tbnz    w5, #F_DRAIN_BIT, p_blocked
        ldr     x6, [x2, #M_CONTLEN]
        cbnz    x6, p_blocked
        ldr     w7, [x2, #M_IOVCNT]
        cmp     w7, #(MAXIOV - 3)
        b.hi    p_blocked
        ldr     w8, [x2, #M_POS]
        ldr     w9, [x2, #M_FILL]
        cmp     w8, w9
        b.eq    p_flush
        ldr     x4, [sp, #40]
        add     x0, x4, x8
        add     x1, x4, x9
        bl      parse_one
        ldr     x3, [sp, #24]
        cbz     x0, p_incomplete
        ldr     x4, [sp, #40]
        sub     x5, x0, x4
        str     w5, [x3, #M_POS]
        ldr     w6, [x3, #M_FLAGS]
        bic     w6, w6, #F_PARTIAL
        str     w6, [x3, #M_FLAGS]
        mov     x0, x3
        ldr     x3, [sp, #32]
        bl      emit
        b       p_parse
p_incomplete:
        ldr     w8, [x3, #M_POS]
        ldr     w9, [x3, #M_FILL]
        cbnz    w8, 1f
        mov     w10, #BUFCAP
        cmp     w9, w10
        b.lo    1f
        str     w9, [x3, #M_POS]            // a header block larger than the buffer
        mov     x0, x3
        ADDR    x1, e_431
        mov     w2, #R_CLOSE
        ldr     x3, [sp, #32]
        bl      emit
        b       p_blocked
1:      ldr     w6, [x3, #M_FLAGS]
        tbnz    w6, #F_PARTIAL_BIT, p_flush
        orr     w6, w6, #F_PARTIAL
        str     w6, [x3, #M_FLAGS]
        ldr     w7, [x28, #C_NOWSEC]
        str     w7, [x3, #M_RSTART]
        b       p_flush
p_blocked:
        mov     x0, #1
        str     x0, [sp, #48]
p_flush:
        ldr     x2, [sp, #24]
        ldr     w5, [x2, #M_FLAGS]
        ldr     w7, [x2, #M_IOVCNT]
        cbz     w7, p_tail
        tbnz    w5, #F_SEND_BIT, p_tail
        ldr     x0, [sp, #16]
        bl      submit_send
        ldr     x0, [sp, #48]
        cbz     x0, p_tail
        str     xzr, [sp, #48]              // output slot freed: keep going
        b       p_top
p_tail:
        ldr     x2, [sp, #24]
        ldr     w5, [x2, #M_FLAGS]
        tbnz    w5, #F_RECV_BIT, 4f
        // compact: drop consumed bytes so the partial request starts at 0
        ldr     w8, [x2, #M_POS]
        cbz     w8, 4f
        ldr     w9, [x2, #M_FILL]
        sub     w10, w9, w8
        str     w10, [x2, #M_FILL]
        str     wzr, [x2, #M_POS]
        cbz     w10, 4f
        ldr     x4, [sp, #40]
        add     x11, x4, x8
3:      ldrb    w12, [x11], #1
        strb    w12, [x4], #1
        subs    w10, w10, #1
        b.ne    3b
4:      // input finished and all output flushed -> close
        tbz     w5, #F_DRAIN_BIT, 5f
        tbnz    w5, #F_SEND_BIT, 5f
        ldr     w7, [x2, #M_IOVCNT]
        cbnz    w7, 5f
        ldr     x6, [x2, #M_CONTLEN]
        cbnz    x6, 5f
        orr     w5, w5, #F_CLOSING
        str     w5, [x2, #M_FLAGS]
5:      ldr     x0, [sp, #48]
        cbnz    x0, 6f
        mov     w6, #(F_RECV | F_DRAIN | F_CLOSING)
        tst     w5, w6
        b.ne    6f
        ldr     w9, [x2, #M_FILL]
        mov     w10, #BUFCAP
        cmp     w9, w10
        b.hs    6f
        ldr     x0, [sp, #16]
        mov     w1, #RECV_POLL_FIRST
        bl      arm_recv
6:      ldr     x0, [sp, #16]
        bl      maybe_close
        ldp     x29, x30, [sp], #64
        ret

// emit(x0 = meta, x1 = entry, w2 = R_* flags, x3 = conn buffers)
emit:
        ldr     w4, [x1, #E_FLAGS]
        tbz     w4, #EF_CLOSE_BIT, 1f
        orr     w2, w2, #R_CLOSE
1:      ldr     w5, [x0, #M_ACC]
        ldr     w6, [x0, #M_IOVCNT]
        mov     x7, #S_IOVA
        mov     x8, #S_IOVB
        cmp     w5, #0
        csel    x7, x7, x8, eq
        add     x7, x3, x7
        add     x7, x7, x6, lsl #4
        tbnz    w2, #R_304_BIT, 2f
        ldr     x8, [x1, #E_HDR]
        ldr     w9, [x1, #E_HDRLEN]
        b       3f
2:      ldr     x8, [x1, #E_H304]
        ldr     w9, [x1, #E_H304LEN]
3:      stp     x8, x9, [x7], #16
        ldr     x8, [x28, #C_DATE]
        tbnz    w2, #R_CLOSE_BIT, 4f
        tbnz    w2, #R_KA_BIT, 5f
        mov     x9, #D0_LEN
        b       6f
4:      add     x8, x8, #64
        mov     x9, #D1_LEN
        b       6f
5:      add     x8, x8, #128
        mov     x9, #D2_LEN
6:      stp     x8, x9, [x7], #16
        add     w6, w6, #2
        tbnz    w2, #R_NOBODY_BIT, 8f
        ldr     x8, [x1, #E_BODY]
        ldr     x9, [x1, #E_BODYLEN]
        cbz     x9, 8f
        mov     x10, #CHUNK
        cmp     x9, x10
        b.ls    7f
        sub     x11, x9, x10
        add     x12, x8, x10
        str     x11, [x0, #M_CONTLEN]
        str     x12, [x0, #M_CONTPTR]
        mov     x9, x10
7:      stp     x8, x9, [x7], #16
        add     w6, w6, #1
8:      str     w6, [x0, #M_IOVCNT]
        tbz     w2, #R_CLOSE_BIT, 9f
        ldr     w4, [x0, #M_FLAGS]
        orr     w4, w4, #F_DRAIN
        str     w4, [x0, #M_FLAGS]
9:      ret

// submit_send(w0 = conn): send the accumulating iovec array, flip arrays
submit_send:
        add     x1, x26, x0, lsl #6
        add     x2, x25, x0, lsl #CONN_SHIFT
        ldr     w3, [x1, #M_ACC]
        ldr     w4, [x1, #M_IOVCNT]
        cmp     w3, #0
        add     x6, x2, #S_MSGA
        add     x7, x2, #S_MSGB
        csel    x6, x6, x7, eq
        add     x7, x2, #S_IOVA
        add     x8, x2, #S_IOVB
        csel    x7, x7, x8, eq
        str     x7, [x6, #16]               // msg_iov
        str     x4, [x6, #24]               // msg_iovlen
        eor     w3, w3, #1
        str     w3, [x1, #M_ACC]
        str     wzr, [x1, #M_IOVCNT]
        ldr     w3, [x1, #M_FLAGS]
        orr     w3, w3, #F_SEND
        str     w3, [x1, #M_FLAGS]
        mov     x4, x0
        GET_SQE x5
        mov     x7, #SQE_SENDMSG
        orr     x7, x7, x4, lsl #32
        str     x7, [x5]
        str     x6, [x5, #16]
        mov     x7, #1
        movk    x7, #MSG_WAITALL_NOSIGNAL, lsl #32
        str     x7, [x5, #24]
        lsl     x7, x4, #8
        orr     x7, x7, #T_SEND
        str     x7, [x5, #32]
        ret

// arm_recv(w0 = conn, w1 = ioprio)
arm_recv:
        add     x3, x26, x0, lsl #6
        ldr     w6, [x3, #M_FLAGS]
        orr     w6, w6, #F_RECV
        str     w6, [x3, #M_FLAGS]
        ldr     w6, [x3, #M_FILL]
        add     x7, x25, x0, lsl #CONN_SHIFT
        add     x7, x7, #S_IN
        add     x7, x7, x6
        mov     w8, #BUFCAP
        sub     w8, w8, w6
        mov     x4, x0
        GET_SQE x5
        mov     x6, #SQE_RECV
        orr     x6, x6, x1, lsl #16
        orr     x6, x6, x4, lsl #32
        str     x6, [x5]
        str     x7, [x5, #16]
        str     w8, [x5, #24]
        lsl     x6, x4, #8
        orr     x6, x6, #T_RECV
        str     x6, [x5, #32]
        ret

// maybe_close(w0 = conn): close once nothing is in flight; cancel what is.
// The cancel runs inline at submit time and matches requests by the file in
// the slot, so it can never hit a connection that reuses the slot later.
// The close itself is SHUTDOWN hard-linked to CLOSE: on 6.x kernels a removed
// fixed file is only released once older fixed-file requests retire, so the
// FIN must come from shutdown(); the link keeps the slot occupied until that
// shutdown (which io_uring may run on a worker) has actually happened.
maybe_close:
        add     x3, x26, x0, lsl #6
        ldr     w6, [x3, #M_FLAGS]
        tbz     w6, #F_CLOSING_BIT, 9f
        mov     x4, x0
        tst     w6, #(F_RECV | F_SEND)
        b.eq    1f
        tbnz    w6, #F_SHUT_BIT, 9f
        orr     w6, w6, #F_SHUT
        str     w6, [x3, #M_FLAGS]
        GET_SQE x5
        mov     x6, #SQE_CANCEL
        orr     x6, x6, x4, lsl #32
        str     x6, [x5]
        mov     w6, #CANCEL_ALL_FIXED_FD
        str     w6, [x5, #28]
        mov     x6, #T_SHUT
        str     x6, [x5, #32]
        ret
1:      str     wzr, [x3, #M_FLAGS]
        ldr     w9, [x28, #C_SUBMITTED]     // both SQEs of the link in one submission
        sub     w9, w20, w9
        cmp     w9, #(SQ_ENTRIES - 2)
        b.lo    2f
        str     x30, [sp, #-16]!
        bl      sqe_flush
        ldr     x30, [sp], #16
2:      GET_SQE x5
        mov     x6, #SQE_SHUTDOWN_LINK
        orr     x6, x6, x4, lsl #32
        str     x6, [x5]
        mov     w6, #2                      // SHUT_RDWR
        str     w6, [x5, #24]
        mov     x6, #T_SHUT
        str     x6, [x5, #32]
        GET_SQE x5
        mov     x6, #SQE_CLOSE
        str     x6, [x5]
        add     w6, w4, #1                  // CLOSE takes a 1-based fixed-file index
        str     w6, [x5, #44]
        mov     x6, #T_CLOSE
        str     x6, [x5, #32]
9:      ret

// sweep: header, idle and send timeouts (runs once per second)
sweep:
        str     x30, [sp, #-16]!
        ldr     w14, [x28, #C_NOWSEC]
        mov     x13, #0
1:      add     x3, x26, x13, lsl #6
        ldr     w6, [x3, #M_FLAGS]
        tbz     w6, #0, 5f                  // F_ACTIVE
        tbnz    w6, #F_CLOSING_BIT, 5f
        ldr     w7, [x3, #M_LAST]
        sub     w7, w14, w7
        tbnz    w6, #F_SEND_BIT, 2f
        cmp     w7, #TO_IDLE
        b.hi    4f
        tbz     w6, #F_PARTIAL_BIT, 5f
        ldr     w7, [x3, #M_RSTART]
        sub     w7, w14, w7
        cmp     w7, #TO_HEADER
        b.hi    4f
        b       5f
2:      cmp     w7, #TO_SEND
        b.ls    5f
4:      orr     w6, w6, #F_CLOSING
        str     w6, [x3, #M_FLAGS]
        mov     x0, x13
        bl      maybe_close
5:      add     x13, x13, #1
        cmp     x13, #MAXCONN
        b.lo    1b
        ldr     x30, [sp], #16
        ret

queue_accept:
        GET_SQE x5
        ldr     w6, [x28, #C_LISTEN]
        mov     x7, #SQE_ACCEPT_LO
        movk    x7, #SQE_ACCEPT_HI, lsl #16
        orr     x7, x7, x6, lsl #32
        str     x7, [x5]
        mov     w7, #-1                     // IORING_FILE_INDEX_ALLOC
        str     w7, [x5, #44]
        mov     x7, #T_ACCEPT
        str     x7, [x5, #32]
        ret

queue_timer:
        GET_SQE x5
        mov     x6, #SQE_TIMEOUT
        str     x6, [x5]
        add     x6, x28, #C_TS
        str     x6, [x5, #16]
        mov     x6, #1
        movk    x6, #TIMEOUT_MULTISHOT, lsl #32
        str     x6, [x5, #24]
        mov     x6, #T_TIMER
        str     x6, [x5, #32]
        ret

// Submit everything queued so far without waiting. Preserves all but x9.
sqe_flush:
        stp     x0, x1, [sp, #-80]!
        stp     x2, x3, [sp, #16]
        stp     x4, x5, [sp, #32]
        stp     x6, x7, [sp, #48]
        str     x8, [sp, #64]
        ldr     x0, [x28, #C_SQTAILP]
        stlr    w20, [x0]
        ldr     w1, [x28, #C_SUBMITTED]
        sub     w1, w20, w1
        str     w20, [x28, #C_SUBMITTED]
        ldr     w0, [x28, #C_ENTERFD]
        mov     w2, #0
        ldr     w3, [x28, #C_ENTERFL]
        and     w3, w3, #ENTER_REGISTERED_RING
        mov     x4, #0
        mov     x5, #0
        SYSCALL SYS_io_uring_enter
        ldr     x8, [sp, #64]
        ldp     x6, x7, [sp, #48]
        ldp     x4, x5, [sp, #32]
        ldp     x2, x3, [sp, #16]
        ldp     x0, x1, [sp], #80
        ret

// ======================================================================== HTTP parsing
// parse_one(x0 = p, x1 = end) -> x0 = end of request (0: need more bytes),
//                                x1 = table entry, w2 = R_* flags
parse_one:
        stp     x29, x30, [sp, #-16]!
        mov     x10, x0
        mov     x11, x1
        mov     x12, #0
        mov     w4, #0x0a0d
0:      sub     x2, x11, x10                // ignore empty lines before a request
        cmp     x2, #2
        b.lt    1f
        ldrh    w3, [x10]
        cmp     w3, w4
        b.ne    1f
        add     x10, x10, #2
        b       0b
1:      mov     x0, x10
        mov     x1, x11
        bl      scan_block
        cbz     x0, p1_incomplete
        cmp     x0, #1
        b.eq    err400
        mov     x11, x0

        // request line: METHOD SP target SP HTTP/1.x
        mov     x0, x10
        bl      find_lf
        mov     x16, x0
        sub     x17, x0, #1
        sub     x2, x17, x10
        cmp     x2, #14
        b.lt    err400
        ldr     w3, [x10]
        ldr     w4, =0x20544547             // "GET "
        cmp     w3, w4
        b.eq    2f
        ldr     w4, =0x44414548             // "HEAD"
        cmp     w3, w4
        b.ne    err405
        ldrb    w3, [x10, #4]
        cmp     w3, #' '
        b.ne    err405
        mov     x12, #R_NOBODY
        add     x13, x10, #5
        b       3f
2:      add     x13, x10, #4
3:      sub     x14, x17, #8
        ldrb    w3, [x14, #-1]
        cmp     w3, #' '
        b.ne    err400
        ldr     x3, [x14]
        ldr     x4, =0x312e312f50545448     // "HTTP/1.1"
        cmp     x3, x4
        b.eq    4f
        ldr     x4, =0x302e312f50545448     // "HTTP/1.0"
        cmp     x3, x4
        b.eq    5f
        and     x3, x3, #0xffffffffff
        ldr     x4, =0x2f50545448           // "HTTP/"
        cmp     x3, x4
        b.eq    err505
        b       err400
4:      orr     x12, x12, #R_V11
5:      sub     x15, x14, #1                // target = [x13, x15)
        cmp     x13, x15
        b.hs    err400
        ldrb    w3, [x13]
        cmp     w3, #'/'
        b.ne    err400
        sub     x2, x15, x13
        cmp     x2, #PATHMAX
        b.hi    err414

        // percent-decode the path, stop at query/fragment
        add     x5, x28, #C_PATH
        mov     x6, x5
6:      cmp     x13, x15
        b.hs    8f
        ldrb    w3, [x13], #1
        cmp     w3, #'?'
        b.eq    8f
        cmp     w3, #'#'
        b.eq    8f
        cmp     w3, #'%'
        b.eq    7f
        sub     w4, w3, #0x21
        cmp     w4, #(0x7e - 0x21)
        b.hi    err400
        strb    w3, [x6], #1
        b       6b
7:      add     x4, x13, #2
        cmp     x4, x15
        b.hi    err400
        ldrb    w3, [x13]
        HEXV    w3
        ldrb    w4, [x13, #1]
        HEXV    w4
        orr     w3, w4, w3, lsl #4
        cbz     w3, err400
        strb    w3, [x6], #1
        add     x13, x13, #2
        b       6b
8:      mov     x0, x5
        sub     x1, x6, x5
        bl      lookup
        mov     x13, x0

        // header fields
        add     x16, x16, #1
        mov     x14, #0                     // If-None-Match value
        mov     x15, #0
h_loop: ldrh    w3, [x16]
        mov     w4, #0x0a0d
        cmp     w3, w4
        b.eq    h_done
        mov     x0, x16
        bl      find_lf
        mov     x17, x0
        ldrb    w3, [x16]
        cmp     w3, #' '                    // obs-fold
        b.eq    err400
        cmp     w3, #'\t'
        b.eq    err400
        mov     x2, x16
1:      cmp     x2, x17
        b.hs    err400
        ldrb    w3, [x2]
        cmp     w3, #':'
        b.eq    2f
        cmp     w3, #' '
        b.eq    err400
        cmp     w3, #'\t'
        b.eq    err400
        add     x2, x2, #1
        b       1b
2:      sub     x8, x2, x16
        cbz     x8, err400
        add     x6, x2, #1                  // value = [x6, x7), OWS trimmed
        sub     x7, x17, #1
3:      cmp     x6, x7
        b.hs    5f
        ldrb    w4, [x6]
        cmp     w4, #' '
        b.eq    4f
        cmp     w4, #'\t'
        b.ne    5f
4:      add     x6, x6, #1
        b       3b
5:      cmp     x7, x6
        b.ls    7f
        ldrb    w4, [x7, #-1]
        cmp     w4, #' '
        b.eq    6f
        cmp     w4, #'\t'
        b.ne    7f
6:      sub     x7, x7, #1
        b       5b
7:      cmp     x8, #4
        b.eq    h_host
        cmp     x8, #10
        b.eq    h_conn
        cmp     x8, #13
        b.eq    h_inm
        cmp     x8, #14
        b.eq    h_cl
        cmp     x8, #17
        b.eq    h_te
h_next: add     x16, x17, #1
        b       h_loop

h_host: mov     x0, x16
        ADDR    x1, s_host
        mov     x2, #4
        bl      ieq
        cbz     w0, h_next
        tbnz    x12, #R_HOST_BIT, err400
        orr     x12, x12, #R_HOST
        b       h_next
h_conn: mov     x0, x16
        ADDR    x1, s_connection
        mov     x2, #10
        bl      ieq
        cbz     w0, h_next
        mov     x0, x6
        mov     x1, x7
        ADDR    x2, s_close
        mov     x3, #5
        bl      icontains
        cbz     w0, 1f
        orr     x12, x12, #R_CCLOSE
1:      mov     x0, x6
        mov     x1, x7
        ADDR    x2, s_keepalive
        mov     x3, #10
        bl      icontains
        cbz     w0, h_next
        orr     x12, x12, #R_CKA
        b       h_next
h_inm:  mov     x0, x16
        ADDR    x1, s_inm
        mov     x2, #13
        bl      ieq
        cbz     w0, h_next
        mov     x14, x6
        sub     x15, x7, x6
        b       h_next
h_cl:   mov     x0, x16                     // no request bodies: only "0" is allowed
        ADDR    x1, s_cl
        mov     x2, #14
        bl      ieq
        cbz     w0, h_next
        cmp     x6, x7
        b.hs    err400
1:      ldrb    w3, [x6], #1
        cmp     w3, #'0'
        b.ne    err413
        cmp     x6, x7
        b.lo    1b
        b       h_next
h_te:   mov     x0, x16
        ADDR    x1, s_te
        mov     x2, #17
        bl      ieq
        cbz     w0, h_next
        b       err501

h_done: tbz     x12, #R_V11_BIT, 1f
        tbz     x12, #R_HOST_BIT, err400    // HTTP/1.1 requires Host
        tbz     x12, #R_CCLOSE_BIT, 2f
        orr     x12, x12, #R_CLOSE
        b       2f
1:      tbnz    x12, #R_CCLOSE_BIT, 3f      // HTTP/1.0: close unless keep-alive asked
        tbz     x12, #R_CKA_BIT, 3f
        orr     x12, x12, #R_KA
        b       2f
3:      orr     x12, x12, #R_CLOSE
2:      cbnz    x13, 4f
        ADDR    x13, e_404
        b       6f
4:      cbz     x15, 6f
        ldr     w3, [x13, #E_FLAGS]
        tbz     w3, #EF_ETAG_BIT, 6f
        cmp     x15, #1
        b.ne    5f
        ldrb    w3, [x14]
        cmp     w3, #'*'
        b.eq    7f
5:      mov     x0, x14
        add     x1, x14, x15
        ldr     x2, [x13, #E_H304]
        ldr     w3, [x13, #E_H304LEN]
        add     x2, x2, x3
        sub     x2, x2, #20                 // "<16 hex>" + CRLF at the end of the 304 head
        mov     x3, #18
        bl      icontains
        cbz     w0, 6f
7:      orr     x12, x12, #(R_304 | R_NOBODY)
6:      mov     x0, x11
        mov     x1, x13
        mov     x2, x12
        ldp     x29, x30, [sp], #16
        ret

p1_incomplete:
        mov     x0, #0
        ldp     x29, x30, [sp], #16
        ret

err400: ADDR    x13, e_400
        b       err_out
err405: ADDR    x13, e_405
        b       err_out
err413: ADDR    x13, e_413
        b       err_out
err414: ADDR    x13, e_414
        b       err_out
err501: ADDR    x13, e_501
        b       err_out
err505: ADDR    x13, e_505
err_out:
        orr     x12, x12, #R_CLOSE
        mov     x0, x11
        mov     x1, x13
        mov     x2, x12
        ldp     x29, x30, [sp], #16
        ret

// scan_block(x0 = p, x1 = end) -> x0 = byte after the "\r\n\r\n" that ends the
// header block, 0 if it is not complete yet, 1 if the bytes are not valid
// HTTP: control characters other than HT, DEL, CR without LF, LF without CR.
scan_block:
        movi    v16.16b, #0                 // previous block: LF
        movi    v17.16b, #0                 // previous block: CR
        movi    v18.16b, #0x20
        movi    v19.16b, #0x09
        movi    v20.16b, #0x7f
1:      sub     x2, x1, x0
        cmp     x2, #0
        b.le    9f
        ldr     q0, [x0]
        cmeq    v1.16b, v0.16b, v28.16b     // LF
        cmeq    v2.16b, v0.16b, v29.16b     // CR
        cmhi    v3.16b, v18.16b, v0.16b     // < 0x20
        cmeq    v4.16b, v0.16b, v19.16b
        orr     v4.16b, v4.16b, v1.16b
        orr     v4.16b, v4.16b, v2.16b
        bic     v3.16b, v3.16b, v4.16b      // CTL except HT, CR, LF
        cmeq    v4.16b, v0.16b, v20.16b
        orr     v3.16b, v3.16b, v4.16b      // | DEL
        ext     v5.16b, v17.16b, v2.16b, #15    // CR at j-1
        bic     v6.16b, v5.16b, v1.16b
        orr     v3.16b, v3.16b, v6.16b      // CR not followed by LF
        bic     v6.16b, v1.16b, v5.16b
        orr     v3.16b, v3.16b, v6.16b      // LF not preceded by CR
        ext     v6.16b, v16.16b, v1.16b, #14    // LF at j-2
        ext     v7.16b, v17.16b, v2.16b, #13    // CR at j-3
        and     v6.16b, v6.16b, v7.16b
        and     v5.16b, v5.16b, v1.16b
        and     v5.16b, v5.16b, v6.16b      // "\r\n\r\n" ends at j
        shrn    v5.8b, v5.8h, #4
        fmov    x3, d5
        shrn    v3.8b, v3.8h, #4
        fmov    x4, d3
        cmp     x2, #16
        b.hs    2f
        lsl     x5, x2, #2
        mov     x6, #1
        lsl     x6, x6, x5
        sub     x6, x6, #1
        and     x3, x3, x6
        and     x4, x4, x6
2:      cbnz    x3, 3f
        cbnz    x4, 8f
        mov     v16.16b, v1.16b
        mov     v17.16b, v2.16b
        add     x0, x0, #16
        b       1b
3:      rbit    x5, x3
        clz     x5, x5                      // 4 * lane
        add     x6, x5, #4
        mov     x7, #64
        sub     x6, x7, x6
        mov     x7, #-1
        lsr     x7, x7, x6                  // lanes up to and including the terminator
        tst     x4, x7
        b.ne    8f
        add     x0, x0, x5, lsr #2
        add     x0, x0, #1
        ret
8:      mov     x0, #1
        ret
9:      mov     x0, #0
        ret

// find_lf(x0) -> x0 = address of the next '\n' (caller guarantees one exists)
find_lf:
1:      ldr     q0, [x0]
        cmeq    v0.16b, v0.16b, v28.16b
        shrn    v0.8b, v0.8h, #4
        fmov    x2, d0
        cbnz    x2, 2f
        add     x0, x0, #16
        b       1b
2:      rbit    x2, x2
        clz     x2, x2
        add     x0, x0, x2, lsr #2
        ret

// lookup(x0 = key, x1 = len) -> x0 = entry or 0. Clobbers x0-x9.
lookup:
        mov     x8, x0
        mov     x9, x1
        HASH    x8, x9
        ADDR    x3, g_table
        ldr     x3, [x3]
        ADDR    x4, g_tmask
        ldr     x4, [x4]
        and     x5, x2, x4
1:      add     x6, x3, x5, lsl #6
        ldr     x7, [x6, #E_KEY]
        cbz     x7, 9f
        ldr     x0, [x6, #E_HASH]
        cmp     x0, x2
        b.ne    2f
        ldr     w0, [x6, #E_KEYLEN]
        cmp     x0, x9
        b.ne    2f
        mov     x0, #0
3:      cmp     x0, x9
        b.hs    8f
        ldrb    w1, [x7, x0]
        ldrb    w4, [x8, x0]
        cmp     w1, w4
        b.ne    2f
        add     x0, x0, #1
        b       3b
8:      mov     x0, x6
        ret
2:      ADDR    x4, g_tmask
        ldr     x4, [x4]
        add     x5, x5, #1
        and     x5, x5, x4
        b       1b
9:      mov     x0, #0
        ret

// ieq(x0 = s, x1 = lowercase literal, x2 = len) -> w0. Clobbers x0-x4.
ieq:
1:      cbz     x2, 2f
        ldrb    w3, [x0], #1
        orr     w3, w3, #0x20
        ldrb    w4, [x1], #1
        cmp     w3, w4
        b.ne    3f
        sub     x2, x2, #1
        b       1b
2:      mov     w0, #1
        ret
3:      mov     w0, #0
        ret

// icontains(x0 = s, x1 = end, x2 = lowercase needle, x3 = len) -> w0.
// Clobbers x0-x5, x8, x9.
icontains:
        sub     x4, x1, x3
1:      cmp     x0, x4
        b.hi    9f
        mov     x5, #0
2:      cmp     x5, x3
        b.hs    8f
        ldrb    w8, [x0, x5]
        orr     w8, w8, #0x20
        ldrb    w9, [x2, x5]
        cmp     w8, w9
        b.ne    3f
        add     x5, x5, #1
        b       2b
3:      add     x0, x0, #1
        b       1b
8:      mov     w0, #1
        ret
9:      mov     w0, #0
        ret

// ======================================================================== date
// Render "Www, DD Mmm YYYY hh:mm:ss" into the idle blob's three Date lines,
// then flip. Clobbers x0-x16.
update_date:
        str     x30, [sp, #-16]!
        ldr     x0, [x28, #C_DATE]
        ldr     x1, [x28, #C_DATEA]
        ldr     x2, [x28, #C_DATEB]
        cmp     x0, x1
        csel    x10, x2, x1, eq
        add     x0, x10, #6
        bl      fmt_date
        ldur    q0, [x10, #6]
        ldur    q1, [x10, #19]
        stur    q0, [x10, #70]
        stur    q1, [x10, #83]
        stur    q0, [x10, #134]
        stur    q1, [x10, #147]
        str     x10, [x28, #C_DATE]
        ldr     x30, [sp], #16
        ret

// x0 = blob: copy the three Date line templates in
fill_dates:
        str     x30, [sp, #-16]!
        ADDR    x1, s_d0
        mov     x2, #D0_LEN
        mov     x3, x0
        bl      copy_n
        ADDR    x1, s_d1
        mov     x2, #D1_LEN
        add     x3, x0, #64
        bl      copy_n
        ADDR    x1, s_d2
        mov     x2, #D2_LEN
        add     x3, x0, #128
        bl      copy_n
        ldr     x30, [sp], #16
        ret

        .macro TWO val, off
        udiv    w13, \val, w14
        msub    w15, w13, w14, \val
        add     w13, w13, #'0'
        add     w15, w15, #'0'
        strb    w13, [x9, #\off]
        strb    w15, [x9, #(\off + 1)]
        .endm

// x0 = destination (29 bytes, separators already present). Preserves x10.
fmt_date:
        mov     x9, x0
        mov     x0, #0                      // CLOCK_REALTIME
        add     x1, x28, #C_NOW
        SYSCALL SYS_clock_gettime
        ldr     x0, [x28, #C_NOW]
        str     w0, [x28, #C_NOWSEC]
        ldr     x1, =86400
        udiv    x2, x0, x1
        msub    x3, x2, x1, x0
        mov     w14, #10

        add     x4, x2, #4                  // 1970-01-01 was a Thursday
        mov     x5, #7
        udiv    x6, x4, x5
        msub    x4, x6, x5, x4
        add     x4, x4, x4, lsl #1
        ADDR    x5, s_days
        add     x5, x5, x4
        ldrh    w6, [x5]
        strh    w6, [x9]
        ldrb    w6, [x5, #2]
        strb    w6, [x9, #2]

        // civil_from_days (H. Hinnant)
        ldr     x4, =719468
        add     x4, x2, x4
        ldr     x5, =146097
        udiv    x6, x4, x5
        msub    x7, x6, x5, x4
        mov     x11, #1460
        udiv    x8, x7, x11
        sub     x8, x7, x8
        ldr     x11, =36524
        udiv    x12, x7, x11
        add     x8, x8, x12
        ldr     x11, =146096
        udiv    x12, x7, x11
        sub     x8, x8, x12
        mov     x11, #365
        udiv    x8, x8, x11
        mov     x12, #400
        madd    x6, x6, x12, x8
        mul     x12, x8, x11
        add     x12, x12, x8, lsr #2
        mov     x11, #100
        udiv    x13, x8, x11
        sub     x12, x12, x13
        sub     x7, x7, x12
        mov     x11, #5
        mov     x12, #2
        madd    x8, x7, x11, x12
        mov     x11, #153
        udiv    x8, x8, x11
        mul     x12, x8, x11
        add     x12, x12, #2
        mov     x11, #5
        udiv    x12, x12, x11
        sub     x7, x7, x12
        add     x7, x7, #1
        cmp     x8, #10
        add     x12, x8, #3
        sub     x13, x8, #9
        csel    x8, x12, x13, lo
        cmp     x8, #2
        cinc    x6, x6, ls

        TWO     w7, 5
        sub     x8, x8, #1
        add     x8, x8, x8, lsl #1
        ADDR    x5, s_months
        add     x5, x5, x8
        ldrh    w11, [x5]
        strh    w11, [x9, #8]
        ldrb    w11, [x5, #2]
        strb    w11, [x9, #10]
        mov     w11, #100
        udiv    w12, w6, w11
        msub    w16, w12, w11, w6
        TWO     w12, 12
        TWO     w16, 14
        mov     x11, #3600
        udiv    x12, x3, x11
        msub    x3, x12, x11, x3
        TWO     w12, 17
        mov     x11, #60
        udiv    x12, x3, x11
        msub    x3, x12, x11, x3
        TWO     w12, 20
        TWO     w3, 23
        ret

// ======================================================================== snapshot
load_root:
        stp     x29, x30, [sp, #-32]!
        str     x19, [sp, #16]
        mov     x0, #0
        ldr     x1, =ARENA_RESERVE
        mov     x2, #3
        mov     x3, #0x4022                 // MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE
        mov     x4, #-1
        mov     x5, #0
        SYSCALL SYS_mmap
        ADDR    x1, m_mmap
        cmn     x0, #4095
        b.hs    die
        ADDR    x1, g_table
        str     x0, [x1]
        ADDR    x1, g_tmask
        ldr     x2, =(TABLE_SLOTS - 1)
        str     x2, [x1]
        add     x2, x0, #TABLE_BYTES
        ADDR    x1, g_cur
        str     x2, [x1]
        ldr     x2, =ARENA_RESERVE
        add     x2, x0, x2
        ADDR    x1, g_end
        str     x2, [x1]

        mov     x0, #AT_FDCWD
        ADDR    x1, g_root
        ldr     x1, [x1]
        ldr     x2, =O_ROOT_FLAGS
        mov     x3, #0
        SYSCALL SYS_openat
        CHECK   m_root
        mov     x19, x0
        ADDR    x1, g_urlpath
        mov     w2, #'/'
        strb    w2, [x1]
        ADDR    x1, g_urllen
        mov     x2, #1
        str     x2, [x1]
        mov     w1, #0
        bl      walk
        mov     x0, #1
        bl      add_alias                   // "/" -> "/index.html"
        mov     x0, x19
        SYSCALL SYS_close

        ADDR    x0, g_table
        ldr     x0, [x0]
        ldr     x1, =ARENA_RESERVE
        mov     x2, #1                      // PROT_READ
        SYSCALL SYS_mprotect
        CHECK   m_mprotect
        ldr     x19, [sp, #16]
        ldp     x29, x30, [sp], #32
        ret

// walk(x0 = dirfd, w1 = depth); g_urlpath[0..g_urllen) is the URL of this
// directory and ends with '/'
walk:
        stp     x29, x30, [sp, #-80]!
        stp     x19, x20, [sp, #16]
        stp     x21, x22, [sp, #32]
        stp     x23, x24, [sp, #48]
        stp     x25, x26, [sp, #64]
        sub     sp, sp, #DENTBUF
        mov     x19, x0
        mov     w20, w1
        ADDR    x0, g_urllen
        ldr     x21, [x0]
w_read: mov     x0, x19
        mov     x1, sp
        mov     x2, #DENTBUF
        SYSCALL SYS_getdents64
        cmp     x0, #0
        b.le    w_done
        mov     x22, x0
        mov     x23, #0
w_ent:  cmp     x23, x22
        b.hs    w_read
        add     x24, sp, x23
        ldrh    w0, [x24, #16]              // d_reclen
        add     x23, x23, x0
        ldrb    w25, [x24, #18]             // d_type
        add     x24, x24, #19               // d_name
        ldrb    w0, [x24]
        cmp     w0, #'.'                    // ".", "..", and every hidden file
        b.eq    w_ent
        mov     x26, #0
1:      ldrb    w0, [x24, x26]
        cbz     w0, 2f
        add     x26, x26, #1
        b       1b
2:      add     x0, x21, x26
        cmp     x0, #URLMAX
        b.hs    w_ent
        cmp     w25, #DT_UNKNOWN
        b.ne    3f
        mov     x0, x19
        mov     x1, x24
        ADDR    x2, g_stat
        mov     x3, #AT_SYMLINK_NOFOLLOW
        SYSCALL SYS_newfstatat
        tbnz    x0, #63, w_ent
        ADDR    x2, g_stat
        ldr     w0, [x2, #ST_MODE]
        and     w0, w0, #0xf000
        mov     w25, #DT_DIR
        cmp     w0, #0x4000
        b.eq    3f
        mov     w25, #DT_REG
        cmp     w0, #0x8000
        b.ne    w_ent
3:      cmp     w25, #DT_REG
        b.eq    w_file
        cmp     w25, #DT_DIR
        b.ne    w_ent                       // symlinks, sockets, devices: never served
        cmp     w20, #MAXDEPTH
        b.hs    w_ent
        mov     x0, x19
        mov     x1, x24
        ldr     x2, =O_DIR_FLAGS
        mov     x3, #0
        SYSCALL SYS_openat
        tbnz    x0, #63, w_ent
        mov     x25, x0
        // url := dir URL + name
        ADDR    x1, g_urlpath
        add     x1, x1, x21
        mov     x2, x24
        mov     x3, x26
4:      ldrb    w4, [x2], #1
        strb    w4, [x1], #1
        subs    x3, x3, #1
        b.ne    4b
        add     x0, x21, x26
        bl      add_redirect                // "/dir" -> 301 "/dir/"
        ADDR    x1, g_urlpath
        add     x0, x21, x26
        mov     w2, #'/'
        strb    w2, [x1, x0]
        add     x0, x0, #1
        ADDR    x1, g_urllen
        str     x0, [x1]
        mov     x0, x25
        add     w1, w20, #1
        bl      walk
        add     x0, x21, x26
        add     x0, x0, #1
        bl      add_alias                   // "/dir/" -> "/dir/index.html"
        ADDR    x1, g_urllen
        str     x21, [x1]
        mov     x0, x25
        SYSCALL SYS_close
        b       w_ent
w_file: mov     x0, x19
        mov     x1, x24
        mov     x2, x26
        bl      add_file
        b       w_ent
w_done: add     sp, sp, #DENTBUF
        ldp     x25, x26, [sp, #64]
        ldp     x23, x24, [sp, #48]
        ldp     x21, x22, [sp, #32]
        ldp     x19, x20, [sp, #16]
        ldp     x29, x30, [sp], #80
        ret

// add_file(x0 = dirfd, x1 = name, x2 = name length)
add_file:
        stp     x29, x30, [sp, #-96]!
        stp     x19, x20, [sp, #16]
        stp     x21, x22, [sp, #32]
        stp     x23, x24, [sp, #48]
        stp     x25, x26, [sp, #64]
        stp     x27, x28, [sp, #80]
        mov     x19, x0
        mov     x20, x1
        mov     x21, x2
        ADDR    x0, g_nent
        ldr     x0, [x0]
        ldr     x1, =(MAX_ENTRIES - 4)
        cmp     x0, x1
        b.hs    f_skip
        mov     x0, x19
        mov     x1, x20
        ldr     x2, =O_FILE_FLAGS
        mov     x3, #0
        SYSCALL SYS_openat
        tbnz    x0, #63, f_out
        mov     x22, x0
        ADDR    x1, g_stat
        SYSCALL SYS_fstat
        tbnz    x0, #63, f_close
        ADDR    x2, g_stat
        ldr     w0, [x2, #ST_MODE]
        and     w0, w0, #0xf000
        cmp     w0, #0x8000
        b.ne    f_close
        ldr     x23, [x2, #ST_SIZE]
        ADDR    x0, g_bytes
        ldr     x0, [x0]
        add     x0, x0, x23
        mov     x1, #SNAP_MAX
        cmp     x0, x1
        b.hi    f_skipc
        ADDR    x0, g_cur
        ldr     x0, [x0]
        add     x0, x0, x23
        add     x0, x0, #8192
        ADDR    x1, g_end
        ldr     x1, [x1]
        cmp     x0, x1
        b.hs    f_skipc
        // ETag inputs, before g_stat is reused
        ldr     x27, [x2, #ST_MTIME]
        ldr     x0, [x2, #ST_MTIME_NSEC]
        ldr     x1, [x2, #ST_INO]
        ldr     x3, =0x9e3779b97f4a7c15
        eor     x27, x27, x0, lsl #20
        mul     x27, x27, x3
        eor     x27, x27, x1
        eor     x27, x27, x23, ror #17
        mul     x27, x27, x3
        eor     x27, x27, x27, lsr #31
        // body
        add     x0, x23, #16
        bl      alloc
        mov     x24, x0
        mov     x25, #0
1:      cmp     x25, x23
        b.hs    2f
        mov     x0, x22
        add     x1, x24, x25
        sub     x2, x23, x25
        SYSCALL SYS_read
        cmp     x0, #0
        b.le    2f
        add     x25, x25, x0
        b       1b
2:      mov     x23, x25                    // what we actually read
        mov     x0, x22
        SYSCALL SYS_close
        ADDR    x0, g_bytes
        ldr     x1, [x0]
        add     x1, x1, x23
        str     x1, [x0]
        ADDR    x0, g_nfiles
        ldr     x1, [x0]
        add     x1, x1, #1
        str     x1, [x0]
        // key = directory URL + name
        ADDR    x0, g_urllen
        ldr     x26, [x0]
        add     x26, x26, x21
        add     x0, x26, #16
        bl      alloc
        mov     x25, x0
        ADDR    x1, g_urlpath
        ADDR    x2, g_urllen
        ldr     x2, [x2]
        mov     x3, x0
        bl      copy_n
        mov     x1, x20
        mov     x2, x21
        bl      copy_n
        ADDR    x0, g_tmpent
        stp     xzr, x25, [x0, #E_HASH]
        str     w26, [x0, #E_KEYLEN]
        mov     w1, #1                      // EF_ETAG
        str     w1, [x0, #E_FLAGS]
        stp     x24, x23, [x0, #E_BODY]
        // 200 head
        bl      sb_mark
        mov     x28, x0
        SBLIT   s_h200
        mov     x0, x20
        mov     x1, x21
        bl      ctype
        bl      sb_str
        SBLIT   s_hcl
        mov     x0, x23
        bl      sb_dec
        SBLIT   s_etag1
        mov     x0, x27
        bl      sb_hex16
        SBLIT   s_etag2
        SBLIT   s_hnosniff
        bl      sb_mark
        sub     x1, x0, x28
        ADDR    x0, g_tmpent
        str     x28, [x0, #E_HDR]
        str     w1, [x0, #E_HDRLEN]
        // 304 head
        bl      sb_mark
        mov     x28, x0
        SBLIT   s_h304
        SBLIT   s_etag1
        mov     x0, x27
        bl      sb_hex16
        SBLIT   s_etag2
        bl      sb_mark
        sub     x1, x0, x28
        ADDR    x0, g_tmpent
        str     x28, [x0, #E_H304]
        str     w1, [x0, #E_H304LEN]
        bl      sb_align
        bl      insert_tmp
        b       f_out
f_skipc:
        mov     x0, x22
        SYSCALL SYS_close
f_skip: ADDR    x0, g_skipped
        ldr     x1, [x0]
        add     x1, x1, #1
        str     x1, [x0]
        b       f_out
f_close:
        mov     x0, x22
        SYSCALL SYS_close
f_out:  ldp     x27, x28, [sp, #80]
        ldp     x25, x26, [sp, #64]
        ldp     x23, x24, [sp, #48]
        ldp     x21, x22, [sp, #32]
        ldp     x19, x20, [sp, #16]
        ldp     x29, x30, [sp], #96
        ret

// add_redirect(x0 = length of g_urlpath, no trailing slash): "/d" -> 301 "/d/"
add_redirect:
        stp     x29, x30, [sp, #-48]!
        stp     x19, x20, [sp, #16]
        str     x21, [sp, #32]
        mov     x19, x0
        add     x0, x19, #16
        bl      alloc
        mov     x20, x0
        ADDR    x1, g_urlpath
        mov     x2, x19
        mov     x3, x0
        bl      copy_n
        ADDR    x0, g_tmpent
        stp     xzr, x20, [x0, #E_HASH]
        str     w19, [x0, #E_KEYLEN]
        str     wzr, [x0, #E_FLAGS]
        stp     xzr, xzr, [x0, #E_BODY]
        str     xzr, [x0, #E_H304]
        str     wzr, [x0, #E_H304LEN]
        bl      sb_mark
        mov     x21, x0
        SBLIT   s_loc1
        // Location: percent-encoded, so no byte of a file name can reach the header raw
        ADDR    x0, g_urlpath
        mov     x1, x19
        bl      sb_pct
        SBLIT   s_loc2
        SBLIT   s_hnosniff
        bl      sb_mark
        sub     x1, x0, x21
        ADDR    x0, g_tmpent
        str     x21, [x0, #E_HDR]
        str     w1, [x0, #E_HDRLEN]
        bl      sb_align
        bl      insert_tmp
        ldr     x21, [sp, #32]
        ldp     x19, x20, [sp, #16]
        ldp     x29, x30, [sp], #48
        ret

// add_alias(x0 = length of g_urlpath, ends with '/'): "/d/" -> "/d/index.html"
add_alias:
        stp     x29, x30, [sp, #-32]!
        stp     x19, x20, [sp, #16]
        mov     x19, x0
        ADDR    x1, g_urlpath
        add     x3, x1, x19
        ADDR    x1, s_index
        mov     x2, #10
        bl      copy_n
        ADDR    x0, g_urlpath
        add     x1, x19, #10
        bl      lookup
        cbz     x0, 9f
        ADDR    x1, g_tmpent
        ldp     q0, q1, [x0]
        stp     q0, q1, [x1]
        ldp     q0, q1, [x0, #32]
        stp     q0, q1, [x1, #32]
        add     x0, x19, #16
        bl      alloc
        mov     x20, x0
        ADDR    x1, g_urlpath
        mov     x2, x19
        mov     x3, x0
        bl      copy_n
        ADDR    x0, g_tmpent
        str     x20, [x0, #E_KEY]
        str     w19, [x0, #E_KEYLEN]
        bl      insert_tmp
9:      ldp     x19, x20, [sp, #16]
        ldp     x29, x30, [sp], #32
        ret

// insert g_tmpent (key/keylen set) into the table unless the key exists
insert_tmp:
        stp     x29, x30, [sp, #-16]!
        ADDR    x0, g_nent
        ldr     x0, [x0]
        ldr     x1, =(TABLE_SLOTS - 1024)
        cmp     x0, x1
        b.hs    9f
        ADDR    x10, g_tmpent
        ldr     x8, [x10, #E_KEY]
        ldr     w9, [x10, #E_KEYLEN]
        mov     x0, x8
        mov     x1, x9
        bl      lookup
        cbnz    x0, 9f
        ADDR    x10, g_tmpent
        ldr     x8, [x10, #E_KEY]
        ldr     w9, [x10, #E_KEYLEN]
        HASH    x8, x9
        str     x2, [x10, #E_HASH]
        ADDR    x3, g_table
        ldr     x3, [x3]
        ADDR    x4, g_tmask
        ldr     x4, [x4]
        and     x5, x2, x4
1:      add     x6, x3, x5, lsl #6
        ldr     x7, [x6, #E_KEY]
        cbz     x7, 2f
        add     x5, x5, #1
        and     x5, x5, x4
        b       1b
2:      ldp     q0, q1, [x10]
        stp     q0, q1, [x6]
        ldp     q0, q1, [x10, #32]
        stp     q0, q1, [x6, #32]
        ADDR    x0, g_nent
        ldr     x1, [x0]
        add     x1, x1, #1
        str     x1, [x0]
9:      ldp     x29, x30, [sp], #16
        ret

// ctype(x0 = name, x1 = len) -> x0 = MIME type, x1 = length
ctype:
        add     x2, x0, x1                  // end
        mov     x3, x2
1:      cmp     x3, x0
        b.ls    8f
        ldrb    w4, [x3, #-1]
        cmp     w4, #'.'
        b.eq    2f
        sub     x3, x3, #1
        b       1b
2:      sub     x4, x2, x3                  // extension = [x3, x2)
        ADDR    x5, t_mime
3:      ldrb    w6, [x5]
        cbz     w6, 8f
        add     x7, x5, #1                  // ext
        add     x8, x7, x6                  // type length byte
        ldrb    w9, [x8]
        cmp     x6, x4
        b.ne    5f
        mov     x10, #0
4:      cmp     x10, x4
        b.hs    6f
        ldrb    w11, [x3, x10]
        orr     w11, w11, #0x20
        ldrb    w12, [x7, x10]
        cmp     w11, w12
        b.ne    5f
        add     x10, x10, #1
        b       4b
5:      add     x5, x8, #1
        add     x5, x5, x9
        b       3b
6:      add     x0, x8, #1
        mov     x1, x9
        ret
8:      ADDR    x0, s_octet
        mov     x1, #(s_octet_end - s_octet)
        ret

// arena bump allocator: x0 = size -> x0 = 16-aligned pointer
alloc:
        ADDR    x1, g_cur
        ldr     x2, [x1]
        add     x2, x2, #15
        and     x2, x2, #~15
        add     x3, x2, x0
        str     x3, [x1]
        mov     x0, x2
        ret

// copy_n(x1 = src, x2 = len, x3 = dst) -> x3 advanced
copy_n:
        cbz     x2, 2f
1:      ldrb    w4, [x1], #1
        strb    w4, [x3], #1
        subs    x2, x2, #1
        b.ne    1b
2:      ret

// string builder on g_cur
sb_mark:
        ADDR    x0, g_cur
        ldr     x0, [x0]
        ret
sb_align:
        ADDR    x0, g_cur
        ldr     x1, [x0]
        add     x1, x1, #15
        and     x1, x1, #~15
        str     x1, [x0]
        ret
sb_str:                                     // x0 = src, x1 = len
        ADDR    x2, g_cur
        ldr     x3, [x2]
        cbz     x1, 2f
1:      ldrb    w4, [x0], #1
        strb    w4, [x3], #1
        subs    x1, x1, #1
        b.ne    1b
2:      str     x3, [x2]
        ret
sb_dec:                                     // x0 = value
        str     x30, [sp, #-16]!
        ADDR    x2, g_cur
        ldr     x1, [x2]
        bl      utoa
        ADDR    x2, g_cur
        str     x1, [x2]
        ldr     x30, [sp], #16
        ret
sb_hex16:                                   // x0 = value
        ADDR    x2, g_cur
        ldr     x3, [x2]
        ADDR    x5, s_hex
        mov     x4, #60
1:      lsr     x6, x0, x4
        and     x6, x6, #15
        ldrb    w6, [x5, x6]
        strb    w6, [x3], #1
        subs    x4, x4, #4
        b.pl    1b
        str     x3, [x2]
        ret
sb_pct:                                     // x0 = src, x1 = len
        ADDR    x2, g_cur
        ldr     x3, [x2]
        ADDR    x5, s_hex
        cbz     x1, 9f
1:      ldrb    w4, [x0], #1
        sub     w6, w4, #'a'
        cmp     w6, #25
        b.ls    3f
        sub     w6, w4, #'A'
        cmp     w6, #25
        b.ls    3f
        sub     w6, w4, #'0'
        cmp     w6, #9
        b.ls    3f
        cmp     w4, #'/'
        b.eq    3f
        cmp     w4, #'-'
        b.eq    3f
        cmp     w4, #'.'
        b.eq    3f
        cmp     w4, #'_'
        b.eq    3f
        cmp     w4, #'~'
        b.eq    3f
        mov     w6, #'%'
        strb    w6, [x3], #1
        lsr     w6, w4, #4
        ldrb    w6, [x5, x6]
        strb    w6, [x3], #1
        and     w6, w4, #15
        ldrb    w6, [x5, x6]
        strb    w6, [x3], #1
        b       4f
3:      strb    w4, [x3], #1
4:      subs    x1, x1, #1
        b.ne    1b
9:      str     x3, [x2]
        ret

// ======================================================================== helpers
parse_uint:
        mov     w1, #0
        mov     w3, #10
1:      ldrb    w2, [x0], #1
        sub     w2, w2, #'0'
        cmp     w2, #9
        b.hi    2f
        madd    w1, w1, w3, w2
        b       1b
2:      mov     w0, w1
        ret

// x0 -> decimal at x1 (x1 advances). Clobbers x2-x6.
utoa:
        sub     sp, sp, #32
        mov     x2, sp
        mov     x6, sp
        mov     x3, #10
1:      udiv    x4, x0, x3
        msub    x5, x4, x3, x0
        add     w5, w5, #'0'
        strb    w5, [x2], #1
        mov     x0, x4
        cbnz    x0, 1b
2:      ldrb    w5, [x2, #-1]!
        strb    w5, [x1], #1
        cmp     x2, x6
        b.ne    2b
        add     sp, sp, #32
        ret

append:
        cbz     x3, 2f
1:      ldrb    w4, [x2], #1
        strb    w4, [x1], #1
        subs    x3, x3, #1
        b.ne    1b
2:      ret

// x0 = -errno, x1 = NUL-terminated message
die:
        neg     x19, x0
        mov     x20, x1
        ADDR    x1, g_line
        ADDR    x2, s_fatal
        mov     x3, #(s_fatal_end - s_fatal)
        bl      append
1:      ldrb    w4, [x20], #1
        cbz     w4, 2f
        strb    w4, [x1], #1
        b       1b
2:      ADDR    x2, s_errno
        mov     x3, #(s_errno_end - s_errno)
        bl      append
        mov     x0, x19
        bl      utoa
        mov     w0, #')'
        strb    w0, [x1], #1
        mov     w0, #'\n'
        strb    w0, [x1], #1
        ADDR    x0, g_line
        sub     x2, x1, x0
        mov     x1, x0
        mov     x0, #2
        SYSCALL SYS_write
        mov     x0, #1
        SYSCALL SYS_exit_group

        .ltorg

// ======================================================================== data
        .section .rodata
        .p2align 4
s_d0:   .ascii  "Date: Thu, 01 Jan 1970 00:00:00 GMT\r\n\r\n"
s_d0_end:
s_d1:   .ascii  "Date: Thu, 01 Jan 1970 00:00:00 GMT\r\nConnection: close\r\n\r\n"
s_d1_end:
s_d2:   .ascii  "Date: Thu, 01 Jan 1970 00:00:00 GMT\r\nConnection: keep-alive\r\n\r\n"
s_d2_end:
        .if (s_d0_end - s_d0) != D0_LEN || (s_d1_end - s_d1) != D1_LEN || (s_d2_end - s_d2) != D2_LEN
        .error "Date line length mismatch"
        .endif

s_h200:     .ascii "HTTP/1.1 200 OK\r\nServer: absurd\r\nContent-Type: "
s_h200_end:
s_hcl:      .ascii "\r\nContent-Length: "
s_hcl_end:
s_etag1:    .ascii "\r\nETag: \""
s_etag1_end:
s_etag2:    .ascii "\"\r\n"
s_etag2_end:
s_hnosniff: .ascii "X-Content-Type-Options: nosniff\r\n"
s_hnosniff_end:
s_h304:     .ascii "HTTP/1.1 304 Not Modified\r\nServer: absurd"
s_h304_end:
s_loc1:     .ascii "HTTP/1.1 301 Moved Permanently\r\nServer: absurd\r\nContent-Length: 0\r\nLocation: "
s_loc1_end:
s_loc2:     .ascii "/\r\n"
s_loc2_end:
s_octet:    .ascii "application/octet-stream"
s_octet_end:
s_index:    .ascii "index.html"
s_hex:      .ascii "0123456789abcdef"
s_host:     .ascii "host"
s_connection: .ascii "connection"
s_close:    .ascii "close"
s_keepalive: .ascii "keep-alive"
s_inm:      .ascii "if-none-match"
s_cl:       .ascii "content-length"
s_te:       .ascii "transfer-encoding"
s_dot:      .asciz "."
s_days:     .ascii "SunMonTueWedThuFriSat"
s_months:   .ascii "JanFebMarAprMayJunJulAugSepOctNovDec"

        .macro MIME ext, type
        .byte   9f - 8f
8:      .ascii  "\ext"
9:      .byte   7f - 6f
6:      .ascii  "\type"
7:
        .endm
t_mime:
        MIME    "html",  "text/html; charset=utf-8"
        MIME    "htm",   "text/html; charset=utf-8"
        MIME    "css",   "text/css; charset=utf-8"
        MIME    "js",    "text/javascript; charset=utf-8"
        MIME    "mjs",   "text/javascript; charset=utf-8"
        MIME    "json",  "application/json"
        MIME    "map",   "application/json"
        MIME    "webmanifest", "application/manifest+json"
        MIME    "txt",   "text/plain; charset=utf-8"
        MIME    "md",    "text/markdown; charset=utf-8"
        MIME    "csv",   "text/csv; charset=utf-8"
        MIME    "xml",   "application/xml"
        MIME    "svg",   "image/svg+xml"
        MIME    "png",   "image/png"
        MIME    "jpg",   "image/jpeg"
        MIME    "jpeg",  "image/jpeg"
        MIME    "gif",   "image/gif"
        MIME    "webp",  "image/webp"
        MIME    "avif",  "image/avif"
        MIME    "ico",   "image/x-icon"
        MIME    "bmp",   "image/bmp"
        MIME    "wasm",  "application/wasm"
        MIME    "pdf",   "application/pdf"
        MIME    "woff",  "font/woff"
        MIME    "woff2", "font/woff2"
        MIME    "ttf",   "font/ttf"
        MIME    "otf",   "font/otf"
        MIME    "mp4",   "video/mp4"
        MIME    "webm",  "video/webm"
        MIME    "mp3",   "audio/mpeg"
        MIME    "ogg",   "audio/ogg"
        MIME    "wav",   "audio/wav"
        MIME    "zip",   "application/zip"
        MIME    "gz",    "application/gzip"
        .byte   0

// Static error responses, laid out as table entries.
        .macro ERRRESP name, status, body, flags, extra=""
        .section .rodata
h_\name:
        .ascii  "HTTP/1.1 \status\r\nServer: absurd\r\nContent-Type: text/plain; charset=utf-8\r\n"
        .ascii  "\extra"
        .ascii  "Content-Length: "
        .ascii  "\body"
h_\name\()_end:
b_\name:
        .ascii  "\status\n"
b_\name\()_end:
        .endm

        // \body here is the decimal length of "<status>\n", followed by CRLF + nosniff
        ERRRESP 400, "400 Bad Request", "16\r\nX-Content-Type-Options: nosniff\r\n", 2
        ERRRESP 404, "404 Not Found", "14\r\nX-Content-Type-Options: nosniff\r\n", 0
        ERRRESP 405, "405 Method Not Allowed", "23\r\nX-Content-Type-Options: nosniff\r\n", 2, "Allow: GET, HEAD\r\n"
        ERRRESP 413, "413 Content Too Large", "22\r\nX-Content-Type-Options: nosniff\r\n", 2
        ERRRESP 414, "414 URI Too Long", "17\r\nX-Content-Type-Options: nosniff\r\n", 2
        ERRRESP 431, "431 Request Header Fields Too Large", "36\r\nX-Content-Type-Options: nosniff\r\n", 2
        ERRRESP 501, "501 Not Implemented", "20\r\nX-Content-Type-Options: nosniff\r\n", 2
        ERRRESP 505, "505 HTTP Version Not Supported", "31\r\nX-Content-Type-Options: nosniff\r\n", 2

        .if (b_400_end - b_400) != 16 || (b_404_end - b_404) != 14 || (b_405_end - b_405) != 23 || (b_413_end - b_413) != 22
        .error "error body length mismatch"
        .endif
        .if (b_414_end - b_414) != 17 || (b_431_end - b_431) != 36 || (b_501_end - b_501) != 20 || (b_505_end - b_505) != 31
        .error "error body length mismatch"
        .endif

        .macro ERRENT name, flags
e_\name:
        .quad   0, 0
        .word   0, \flags
        .quad   h_\name
        .word   h_\name\()_end - h_\name, 0
        .quad   0
        .quad   b_\name
        .quad   b_\name\()_end - b_\name
        .endm

        .p2align 4
        ERRENT  400, 2
        ERRENT  404, 0
        ERRENT  405, 2
        ERRENT  413, 2
        ERRENT  414, 2
        ERRENT  431, 2
        ERRENT  501, 2
        ERRENT  505, 2

s_b1:   .ascii "absurd: serving "
s_b1_end:
s_b2:   .ascii " files ("
s_b2_end:
s_b3:   .ascii " bytes) from "
s_b3_end:
s_b4:   .ascii " on 0.0.0.0:"
s_b4_end:
s_b5:   .ascii ", "
s_b5_end:
s_b6:   .ascii " threads, io_uring + seccomp sandbox"
s_b6_end:
s_b7:   .ascii ", cpu-steered"
s_b7_end:
s_b8:   .ascii ", running as nobody"
s_b8_end:
s_b9:   .ascii "\nabsurd: warning: skipped "
s_b9_end:
s_b10:  .ascii " files (1 GiB snapshot cap or table full)"
s_b10_end:
s_usage: .ascii "usage: absurd [-p port] [-t threads] [document-root]\n"
s_usage_end:
s_fatal: .ascii "absurd: fatal: "
s_fatal_end:
s_errno: .ascii " failed (errno "
s_errno_end:
m_socket:   .asciz "socket"
m_bind:     .asciz "bind"
m_listen:   .asciz "listen"
m_mmap:     .asciz "mmap"
m_mprotect: .asciz "mprotect"
m_clone:    .asciz "clone"
m_priv:     .asciz "dropping privileges"
m_root:     .asciz "opening the document root"
m_setup:    .asciz "io_uring_setup (need Linux >= 6.6 and io_uring allowed by seccomp)"
m_files:    .asciz "register fixed files"
m_restrict: .asciz "restricting io_uring"
m_seccomp:  .asciz "installing seccomp filter"

        .p2align 2
// io_uring restrictions: (opcode, value) pairs. 1 = SQE_OP, 2 = SQE_FLAGS_ALLOWED
g_restrict:
        .hword  1
        .byte   OP_ACCEPT
        .byte   0
        .hword  1
        .byte   OP_RECV
        .byte   0
        .hword  1
        .byte   OP_SENDMSG
        .byte   0
        .hword  1
        .byte   OP_CLOSE
        .byte   0
        .hword  1
        .byte   OP_TIMEOUT
        .byte   0
        .hword  1
        .byte   OP_ASYNC_CANCEL
        .byte   0
        .hword  1
        .byte   OP_SHUTDOWN
        .byte   0
        .hword  2
        .byte   0x49                        // FIXED_FILE | IO_HARDLINK | CQE_SKIP_SUCCESS
        .byte   0

        .p2align 3
g_bpf:                                      // reuseport: ld [SKF_AD_CPU]; ret A
        .hword  0x20
        .byte   0, 0
        .word   0xfffff024
        .hword  0x16
        .byte   0, 0
        .word   0

g_scfilter:                                 // seccomp allow-list
        .hword  0x20                        // ld [arch]
        .byte   0, 0
        .word   4
        .hword  0x15                        // jeq AUDIT_ARCH_AARCH64
        .byte   0, 6
        .word   0xc00000b7
        .hword  0x20                        // ld [nr]
        .byte   0, 0
        .word   0
        .hword  0x15
        .byte   5, 0
        .word   SYS_io_uring_enter
        .hword  0x15
        .byte   4, 0
        .word   SYS_clock_gettime
        .hword  0x15
        .byte   3, 0
        .word   SYS_exit
        .hword  0x15
        .byte   2, 0
        .word   SYS_exit_group
        .hword  0x15
        .byte   1, 0
        .word   SYS_rt_sigreturn
        .hword  0x06                        // ret KILL_PROCESS
        .byte   0, 0
        .word   0x80000000
        .hword  0x06                        // ret ALLOW
        .byte   0, 0
        .word   0x7fff0000
g_scfilter_end:

        .data
        .p2align 3
g_fprog:    .hword 2, 0, 0, 0
            .quad  0
g_scprog:   .hword (g_scfilter_end - g_scfilter) / 8, 0, 0, 0
            .quad  0

        .bss
        .p2align 4
g_tmpent:   .space 64
g_stat:     .space 128
g_affbuf:   .space 128
g_cpus:     .space 4 * MAX_THREADS
g_lfds:     .space 4 * MAX_THREADS
g_seed:     .space 8
g_table:    .space 8
g_tmask:    .space 8
g_cur:      .space 8
g_end:      .space 8
g_nent:     .space 8
g_nfiles:   .space 8
g_bytes:    .space 8
g_skipped:  .space 8
g_urllen:   .space 8
g_root:     .space 8
g_ncpus:    .space 4
g_nthreads: .space 4
g_one:      .space 4
g_steer:    .space 4
g_dropped:  .space 4
g_sockaddr: .space 16
g_rlim:     .space 16
g_line:     .space 4096
g_urlpath:  .space URLMAX + 64
