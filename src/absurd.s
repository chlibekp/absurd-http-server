// absurd — an HTTP/1.1 server in AArch64 assembly for Linux, built on io_uring.
//
// No libc, no allocator, no syscalls per request. One pinned thread per CPU,
// each with its own SO_REUSEPORT listener and its own io_uring:
//
//   * multishot accept straight into the ring's fixed-file table
//   * multishot recv into a kernel-managed provided-buffer ring
//   * NEON scan that counts complete requests 16 bytes at a time
//   * responses are pre-rendered NCOPIES times back to back, so any number of
//     pipelined requests is answered by one send() pointing at static memory
//   * the Date header is double-buffered and refreshed by a multishot timer
//   * a classic-BPF reuseport program steers each connection to the listener
//     owned by the CPU that took the SYN
//
// Every request gets the same 200 response (TechEmpower "plaintext" style).

// ---------------------------------------------------------------- syscalls
        .equ SYS_write,              64
        .equ SYS_exit_group,         94
        .equ SYS_clock_gettime,      113
        .equ SYS_sched_setaffinity,  122
        .equ SYS_sched_getaffinity,  123
        .equ SYS_socket,             198
        .equ SYS_bind,               200
        .equ SYS_listen,             201
        .equ SYS_setsockopt,         208
        .equ SYS_clone,              220
        .equ SYS_mmap,               222
        .equ SYS_prlimit64,          261
        .equ SYS_io_uring_setup,     425
        .equ SYS_io_uring_enter,     426
        .equ SYS_io_uring_register,  427

// ---------------------------------------------------------------- io_uring ABI
        .equ SETUP_CQSIZE,           1 << 3
        .equ SETUP_CLAMP,            1 << 4
        .equ SETUP_SUBMIT_ALL,       1 << 7
        .equ SETUP_COOP_TASKRUN,     1 << 8
        .equ SETUP_SINGLE_ISSUER,    1 << 12
        .equ SETUP_DEFER_TASKRUN,    1 << 13
        .equ SETUP_NO_SQARRAY,       1 << 16
        .equ SETUP_FLAGS, SETUP_CQSIZE | SETUP_CLAMP | SETUP_SUBMIT_ALL | SETUP_COOP_TASKRUN | SETUP_SINGLE_ISSUER | SETUP_DEFER_TASKRUN | SETUP_NO_SQARRAY

        .equ ENTER_GETEVENTS,        1
        .equ ENTER_REGISTERED_RING,  1 << 4

        .equ REG_FILES2,             13
        .equ REG_RING_FDS,           20
        .equ REG_PBUF_RING,          22

        .equ OFF_SQES,               0x10000000

        // struct io_uring_params
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
        //   ACCEPT(13), ioprio = IORING_ACCEPT_MULTISHOT
        //   RECV(27), flags = FIXED_FILE|BUFFER_SELECT, ioprio = IORING_RECV_MULTISHOT
        //   SEND(26), flags = FIXED_FILE
        //   CLOSE(19), flags = CQE_SKIP_SUCCESS
        //   TIMEOUT(11)
        .equ SQE_ACCEPT_LO,          0x000d
        .equ SQE_ACCEPT_HI,          0x0001
        .equ SQE_RECV_LO,            0x211b
        .equ SQE_RECV_HI,            0x0002
        .equ SQE_SEND,               0x011a
        .equ SQE_CLOSE,              0x4013
        .equ SQE_TIMEOUT,            0x000b
        .equ MSG_WAITALL_NOSIGNAL,   0x4100
        .equ TIMEOUT_MULTISHOT,      1 << 6

        .equ ENOBUFS,                105

// ---------------------------------------------------------------- user_data tags
        .equ T_ACCEPT,               1
        .equ T_RECV,                 2
        .equ T_TIMER,                3
        .equ T_SEND,                 4
        .equ T_CLOSE,                5

// ---------------------------------------------------------------- tuning
        .equ MAX_THREADS,            256
        .equ SQ_ENTRIES,             4096
        .equ CQ_ENTRIES,             16384
        .equ CQ_BATCH,               1024     // <= 2 SQEs per CQE keeps SQ from overflowing
        .equ NBUF,                   4096     // provided buffers per thread (power of 2)
        .equ BUFSZ,                  2048
        .equ SLOT,                   BUFSZ + 32  // 16B carry prefix + data + 16B zero pad
        .equ MAXCONN,                16384    // fixed-file slots per thread
        .equ NCOPIES,                128      // pipelined responses per send
        .equ RESP_LEN,               131
        .equ DATE_OFF,               85
        .equ PORT_DEFAULT,           8080
        .equ BACKLOG,                65535
        .equ STACK_SIZE,             65536

// ---------------------------------------------------------------- per-thread arena
        .equ C_ENTERFD,              0
        .equ C_ENTERFL,              4
        .equ C_LISTEN,               8
        .equ C_SUBMITTED,            12
        .equ C_SQTAILP,              16
        .equ C_CQHEADP,              24
        .equ C_CQTAILP,              32
        .equ C_PBUF,                 40
        .equ C_BLOB,                 48
        .equ C_BLOBA,                56
        .equ C_BLOBB,                64
        .equ C_RINGFD,               72
        .equ C_TS,                   80       // __kernel_timespec {1, 0}
        .equ C_NOW,                  96
        .equ C_PARAMS,               128      // io_uring_params (120 bytes)
        .equ C_REG,                  256      // scratch for register structs

        .equ BLOBSZ,                 ((NCOPIES * RESP_LEN + 4095) / 4096) * 4096
        .equ O_PBUF,                 4096
        .equ O_BLOBA,                O_PBUF + NBUF * 16
        .equ O_BLOBB,                O_BLOBA + BLOBSZ
        .equ O_CONN,                 O_BLOBB + BLOBSZ
        .equ O_BUFS,                 O_CONN + MAXCONN * 16
        .equ ARENA_SIZE,             O_BUFS + NBUF * SLOT

        // per-connection record (16 bytes)
        .equ K_CARRY,                0        // last 4 bytes seen (cross-buffer matching)
        .equ K_PENDING,              4        // responses owed but not yet sent
        .equ K_INFLIGHT,             8        // a send is outstanding
        .equ K_GEN,                  12       // bumps on every accept into this slot

// Hot-loop register map (worker):
//   x28 arena   x19 sqes   w20 sq tail   w21 sq mask
//   x22 cqes    w23 cq head w24 cq mask  x25 buffers
//   w26 pbuf tail  x27 conns  w18 cq batch end
//   v28 '\n' x16  v29 '\r' x16  v31 zero

        .macro GET_SQE reg
        and     w9, w20, w21
        add     \reg, x19, x9, lsl #6
        add     w20, w20, #1
        stp     q31, q31, [\reg]
        stp     q31, q31, [\reg, #32]
        .endm

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

// ======================================================================== main
        .text
        .global _start
_start:
        ldr     x19, [sp]                   // argc
        add     x20, sp, #8                 // argv

        mov     w21, #PORT_DEFAULT
        cmp     x19, #2
        b.lt    1f
        ldr     x0, [x20, #8]
        bl      parse_uint
        cbz     w0, 1f
        mov     w21, w0
1:
        // Which CPUs may we run on?
        mov     x0, #0
        mov     x1, #128
        ADDR    x2, g_affbuf
        SYSCALL SYS_sched_getaffinity
        ADDR    x3, g_cpus
        mov     w4, #0                      // ncpus
        cmp     x0, #0
        b.le    3f
        lsl     x5, x0, #3                  // bits to scan
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

        mov     w22, w4                     // threads default = ncpus
        cmp     x19, #3
        b.lt    6f
        ldr     x0, [x20, #16]
        bl      parse_uint
        cbz     w0, 6f
        mov     w22, w0
        cmp     w22, #MAX_THREADS
        b.ls    6f
        mov     w22, #MAX_THREADS
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

        // One SO_REUSEPORT listener per thread, created in order so that
        // listener i sits at index i of the reuseport group.
        ADDR    x0, g_one
        mov     w1, #1
        str     w1, [x0]
        ADDR    x0, g_sockaddr
        mov     w1, #2                      // AF_INET
        strh    w1, [x0]
        rev16   w2, w21
        strh    w2, [x0, #2]
        str     xzr, [x0, #4]               // INADDR_ANY + zero pad
        str     wzr, [x0, #12]

        mov     w23, #0
7:      mov     x0, #2                      // AF_INET
        mov     x1, #1                      // SOCK_STREAM
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
        mov     x1, #6
        mov     x2, #9                      // TCP_DEFER_ACCEPT: wake us only once data arrived
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

        // CPU steering: if thread i runs on CPU i for all i, attach
        //   ld [SKF_AD_CPU] ; ret A
        // so the kernel hands a connection to the listener of the CPU that
        // processed its SYN. Otherwise fall back to the default 4-tuple hash.
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
        mov     x1, #1                      // SOL_SOCKET
        mov     x2, #51                     // SO_ATTACH_REUSEPORT_CBPF
        ADDR    x3, g_fprog
        ADDR    x4, g_bpf
        str     x4, [x3, #8]
        mov     x4, #16
        SYSCALL SYS_setsockopt              // best effort
        ADDR    x0, g_steer
        mov     w1, #1
        str     w1, [x0]
8:
        // banner
        ADDR    x1, g_line
        ADDR    x2, s_banner1
        mov     x3, #(s_banner1_end - s_banner1)
        bl      append
        mov     w0, w21
        bl      utoa
        ADDR    x2, s_banner2
        mov     x3, #(s_banner2_end - s_banner2)
        bl      append
        mov     w0, w22
        bl      utoa
        ADDR    x2, s_banner3
        mov     x3, #(s_banner3_end - s_banner3)
        bl      append
        ADDR    x0, g_steer
        ldr     w0, [x0]
        cbz     w0, 9f
        ADDR    x2, s_banner4
        mov     x3, #(s_banner4_end - s_banner4)
        bl      append
9:      mov     w0, #'\n'
        strb    w0, [x1], #1
        ADDR    x0, g_line
        sub     x2, x1, x0
        mov     x1, x0
        mov     x0, #1
        SYSCALL SYS_write

        // spawn threads 1..n-1; the main thread becomes worker 0
        mov     w23, #1
10:     cmp     w23, w22
        b.hs    11f
        mov     x0, #0
        mov     x1, #STACK_SIZE
        mov     x2, #3                      // PROT_READ|PROT_WRITE
        mov     x3, #0x22                   // MAP_PRIVATE|MAP_ANONYMOUS
        movk    x3, #0x2, lsl #16           // |MAP_STACK
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
        cbz     x0, 12f
        CHECK   m_clone
        add     w23, w23, #1
        b       10b
11:     mov     w0, #0
        b       worker
12:     mov     w0, w23                     // child: own stack, same registers
        b       worker

// setsockopt(w24, x1, x2, &1, 4)
setopt_one:
        mov     w0, w24
        ADDR    x3, g_one
        mov     x4, #4
        SYSCALL SYS_setsockopt
        ret

// ======================================================================== worker
worker:
        mov     w27, w0                     // thread id

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
        SYSCALL SYS_sched_setaffinity       // best effort
        add     sp, sp, #128

        // arena
        mov     x0, #0
        ldr     x1, =ARENA_SIZE
        mov     x2, #3
        mov     x3, #0x8022                 // MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE
        mov     x4, #-1
        mov     x5, #0
        SYSCALL SYS_mmap
        ADDR    x1, m_mmap
        cmn     x0, #4095
        b.hs    die
        mov     x28, x0

        ADDR    x3, g_lfds
        ldr     w0, [x3, x27, lsl #2]
        str     w0, [x28, #C_LISTEN]

        // io_uring_setup
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

        // map rings (SQ+CQ share one mapping; no SQ index array)
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
        mov     x11, x0                     // rings

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
        mov     x19, x0                     // sqes

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

        add     x25, x28, #O_BUFS
        ldr     x0, =O_CONN
        add     x27, x28, x0

        // sparse fixed-file table: accepted sockets never touch the fd table
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

        // provided-buffer ring, group 0
        add     x0, x28, #O_PBUF
        str     x0, [x28, #C_PBUF]
        mov     x1, #0                      // bid
        add     x2, x25, #16                // first buffer's data
        mov     w3, #BUFSZ
13:     add     x4, x0, x1, lsl #4
        str     x2, [x4]
        str     w3, [x4, #8]
        strh    w1, [x4, #12]
        add     x2, x2, #SLOT
        add     x1, x1, #1
        cmp     x1, #NBUF
        b.lo    13b
        mov     w26, #NBUF
        strh    w26, [x0, #14]              // ring tail
        add     x2, x28, #C_REG
        stp     xzr, xzr, [x2]
        stp     xzr, xzr, [x2, #16]
        str     xzr, [x2, #32]
        str     x0, [x2]                    // ring_addr
        mov     w0, #NBUF
        str     w0, [x2, #8]                // ring_entries, bgid 0
        ldr     w0, [x28, #C_RINGFD]
        mov     x1, #REG_PBUF_RING
        mov     x3, #1
        SYSCALL SYS_io_uring_register
        CHECK   m_pbuf

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
        b.ne    14f
        add     x2, x28, #C_REG
        ldr     w0, [x2]
        str     w0, [x28, #C_ENTERFD]
        mov     w0, #(ENTER_GETEVENTS | ENTER_REGISTERED_RING)
        str     w0, [x28, #C_ENTERFL]
14:
        // response blobs: NCOPIES back-to-back copies, two of them
        add     x0, x28, #O_BLOBA
        str     x0, [x28, #C_BLOBA]
        str     x0, [x28, #C_BLOB]
        bl      fill_blob
        add     x0, x28, #O_BLOBB
        str     x0, [x28, #C_BLOBB]
        bl      fill_blob
        mov     x0, #1
        str     x0, [x28, #C_TS]
        str     xzr, [x28, #C_TS + 8]
        movi    v31.16b, #0
        bl      update_date                 // writes B, makes it current
        bl      update_date                 // writes A, makes it current

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
        ldr     x0, [x28, #C_PBUF]
        add     x0, x0, #14
        stlrh   w26, [x0]                   // hand recycled buffers back
        b       loop

// ------------------------------------------------------------------------ recv
        .p2align 4
on_recv:
        ubfx    x4, x0, #8, #24             // conn index == fixed-file slot
        add     x3, x27, x4, lsl #4
        cmp     w1, #0
        b.le    recv_end
        lsr     w5, w2, #16                 // buffer id
        mov     w6, #SLOT
        umaddl  x10, w5, w6, x25
        add     x10, x10, #16               // data start
        ldr     w6, [x3, #K_CARRY]
        str     w6, [x10, #-4]              // previous buffer's tail in front
        add     x11, x10, x1                // data end
        ldur    w6, [x11, #-4]
        str     w6, [x3, #K_CARRY]
        str     q31, [x11]                  // zero pad: no stale matches past end

        // count "\r\n\r\n": lane j of block i is a hit iff
        //   b[i+j-3]=='\r' && b[i+j-2]=='\n' && b[i+j-1]=='\r' && b[i+j]=='\n'
        ldur    q0, [x10, #-16]
        cmeq    v1.16b, v0.16b, v28.16b     // prev LF
        cmeq    v2.16b, v0.16b, v29.16b     // prev CR
        movi    v30.16b, #0
        mov     x12, x10
1:      ldr     q0, [x12], #16
        cmeq    v3.16b, v0.16b, v28.16b
        cmeq    v4.16b, v0.16b, v29.16b
        ext     v5.16b, v2.16b, v4.16b, #15
        ext     v6.16b, v1.16b, v3.16b, #14
        ext     v7.16b, v2.16b, v4.16b, #13
        and     v5.16b, v5.16b, v6.16b
        and     v7.16b, v7.16b, v3.16b
        and     v5.16b, v5.16b, v7.16b
        sub     v30.16b, v30.16b, v5.16b    // lanes count up (<=128 blocks)
        mov     v1.16b, v3.16b
        mov     v2.16b, v4.16b
        cmp     x12, x11
        b.lo    1b
        uaddlv  h30, v30.16b
        umov    w6, v30.h[0]

        // recycle the buffer immediately; tail is published once per batch
        and     w7, w26, #(NBUF - 1)
        ldr     x8, [x28, #C_PBUF]
        add     x8, x8, x7, lsl #4
        str     x10, [x8]
        mov     w7, #BUFSZ
        str     w7, [x8, #8]
        strh    w5, [x8, #12]
        add     w26, w26, #1

        cbz     w6, 3f
        ldr     w7, [x3, #K_INFLIGHT]
        cbnz    w7, 2f
        bl      do_send
        b       3f
2:      ldr     w7, [x3, #K_PENDING]        // keep byte order: queue behind the send
        add     w7, w7, w6
        str     w7, [x3, #K_PENDING]
3:      tbnz    w2, #CQE_F_MORE_BIT, cq_next
        bl      queue_recv
        b       cq_next

recv_end:
        tbnz    w2, #CQE_F_MORE_BIT, cq_next
        cmn     w1, #ENOBUFS
        b.ne    4f
        bl      queue_recv                  // ran dry on buffers; re-arm
        b       cq_next
4:      GET_SQE x5                          // EOF or error: close the slot
        mov     x6, #SQE_CLOSE
        str     x6, [x5]
        add     w6, w4, #1                  // file_index is 1-based for CLOSE
        str     w6, [x5, #44]
        mov     x6, #T_CLOSE
        str     x6, [x5, #32]
        b       cq_next

// ------------------------------------------------------------------------ send
on_send:
        ubfx    x4, x0, #8, #24
        add     x3, x27, x4, lsl #4
        ldr     w5, [x3, #K_GEN]
        lsr     x6, x0, #32
        cmp     w5, w6
        b.ne    cq_next                     // slot was recycled; stale completion
        tbnz    w1, #31, cq_next            // peer is gone; recv side will close
        str     wzr, [x3, #K_INFLIGHT]
        ldr     w6, [x3, #K_PENDING]
        cbz     w6, cq_next
        bl      do_send
        b       cq_next

// ------------------------------------------------------------------------ accept
on_accept:
        tbnz    w1, #31, 1f
        add     x3, x27, x1, lsl #4
        ldr     w4, [x3, #K_GEN]
        add     w4, w4, #1
        str     xzr, [x3, #K_CARRY]         // carry + pending
        stp     wzr, w4, [x3, #K_INFLIGHT]
        mov     w4, w1
        bl      queue_recv
1:      tbnz    w2, #CQE_F_MORE_BIT, cq_next
        bl      queue_accept
        b       cq_next

// ------------------------------------------------------------------------ timer
on_timer:
        mov     w17, w2
        bl      update_date
        tbnz    w17, #CQE_F_MORE_BIT, cq_next
        bl      queue_timer
        b       cq_next

// ======================================================================== SQE builders
// w4 = conn, w6 = responses owed, x3 = conn record
do_send:
        mov     w7, #NCOPIES
        cmp     w6, w7
        csel    w7, w6, w7, lo
        sub     w8, w6, w7
        str     w8, [x3, #K_PENDING]
        mov     w8, #1
        str     w8, [x3, #K_INFLIGHT]
        GET_SQE x5
        mov     x8, #SQE_SEND
        orr     x8, x8, x4, lsl #32
        str     x8, [x5]
        ldr     x8, [x28, #C_BLOB]
        str     x8, [x5, #16]
        mov     w8, #RESP_LEN
        mul     w8, w8, w7
        mov     x9, #MSG_WAITALL_NOSIGNAL
        orr     x8, x8, x9, lsl #32
        str     x8, [x5, #24]               // len | msg_flags
        ldr     w8, [x3, #K_GEN]
        lsl     x8, x8, #32
        orr     x8, x8, x4, lsl #8
        orr     x8, x8, #T_SEND
        str     x8, [x5, #32]
        ret

// w4 = conn
queue_recv:
        GET_SQE x5
        mov     x6, #SQE_RECV_LO
        movk    x6, #SQE_RECV_HI, lsl #16
        orr     x6, x6, x4, lsl #32
        str     x6, [x5]
        lsl     x6, x4, #8
        orr     x6, x6, #T_RECV
        str     x6, [x5, #32]
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
        str     x6, [x5, #24]               // len=1 | timeout_flags
        mov     x6, #T_TIMER
        str     x6, [x5, #32]
        ret

// ======================================================================== date
// Render "Www, DD Mmm YYYY hh:mm:ss" into the idle blob, replicate it to all
// copies, then flip. In-flight sends keep reading the other blob, which is
// not rewritten for another second. Clobbers x0-x16.
update_date:
        str     x30, [sp, #-16]!
        ldr     x0, [x28, #C_BLOB]
        ldr     x1, [x28, #C_BLOBA]
        ldr     x2, [x28, #C_BLOBB]
        cmp     x0, x1
        csel    x10, x2, x1, eq
        add     x0, x10, #DATE_OFF
        bl      fmt_date
        add     x0, x10, #DATE_OFF
        ldr     q0, [x0]
        ldur    q1, [x0, #13]
        mov     w1, #(NCOPIES - 1)
        add     x2, x0, #RESP_LEN
1:      str     q0, [x2]
        stur    q1, [x2, #13]
        add     x2, x2, #RESP_LEN
        subs    w1, w1, #1
        b.ne    1b
        str     x10, [x28, #C_BLOB]
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
        ldr     x1, =86400
        udiv    x2, x0, x1                  // days since epoch
        msub    x3, x2, x1, x0              // seconds into day
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
        add     x4, x2, x4                  // z
        ldr     x5, =146097
        udiv    x6, x4, x5                  // era
        msub    x7, x6, x5, x4              // doe
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
        udiv    x8, x8, x11                 // yoe
        mov     x12, #400
        madd    x6, x6, x12, x8             // y = yoe + era*400
        mul     x12, x8, x11
        add     x12, x12, x8, lsr #2
        mov     x11, #100
        udiv    x13, x8, x11
        sub     x12, x12, x13
        sub     x7, x7, x12                 // doy
        mov     x11, #5
        mov     x12, #2
        madd    x8, x7, x11, x12
        mov     x11, #153
        udiv    x8, x8, x11                 // mp
        mul     x12, x8, x11
        add     x12, x12, #2
        mov     x11, #5
        udiv    x12, x12, x11
        sub     x7, x7, x12
        add     x7, x7, #1                  // day
        cmp     x8, #10
        add     x12, x8, #3
        sub     x13, x8, #9
        csel    x8, x12, x13, lo            // month 1..12
        cmp     x8, #2
        cinc    x6, x6, ls                  // year

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

// x0 = blob: NCOPIES copies of the template
fill_blob:
        mov     w1, #NCOPIES
1:      ADDR    x2, resp
        mov     w3, #RESP_LEN
2:      ldrb    w4, [x2], #1
        strb    w4, [x0], #1
        subs    w3, w3, #1
        b.ne    2b
        subs    w1, w1, #1
        b.ne    1b
        ret

// ======================================================================== helpers
// x0 = NUL-terminated decimal -> w0
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

// copy x3 bytes from x2 to x1 (x1 advances)
append:
        cbz     x3, 2f
1:      ldrb    w4, [x2], #1
        strb    w4, [x1], #1
        subs    x3, x3, #1
        b.ne    1b
2:      ret

// w0 -> decimal at x1 (x1 advances)
utoa:
        sub     sp, sp, #32
        mov     x2, sp
        mov     x6, sp
        mov     w3, #10
1:      udiv    w4, w0, w3
        msub    w5, w4, w3, w0
        add     w5, w5, #'0'
        strb    w5, [x2], #1
        mov     w0, w4
        cbnz    w0, 1b
2:      ldrb    w5, [x2, #-1]!
        strb    w5, [x1], #1
        cmp     x2, x6
        b.ne    2b
        add     sp, sp, #32
        ret

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
        mov     w0, w19
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
resp:
        .ascii  "HTTP/1.1 200 OK\r\n"
        .ascii  "Server: absurd\r\n"
        .ascii  "Content-Type: text/plain\r\n"
        .ascii  "Content-Length: 13\r\n"
        .ascii  "Date: "
resp_date:
        .ascii  "Thu, 01 Jan 1970 00:00:00 GMT\r\n"
        .ascii  "\r\n"
        .ascii  "Hello, World!"
resp_end:
        .if (resp_end - resp) != RESP_LEN
        .error "RESP_LEN mismatch"
        .endif
        .if (resp_date - resp) != DATE_OFF
        .error "DATE_OFF mismatch"
        .endif

s_days:     .ascii "SunMonTueWedThuFriSat"
s_months:   .ascii "JanFebMarAprMayJunJulAugSepOctNovDec"
s_banner1:  .ascii "absurd: listening on 0.0.0.0:"
s_banner1_end:
s_banner2:  .ascii ", "
s_banner2_end:
s_banner3:  .ascii " threads, io_uring"
s_banner3_end:
s_banner4:  .ascii ", cpu-steered reuseport"
s_banner4_end:
s_fatal:    .ascii "absurd: fatal: "
s_fatal_end:
s_errno:    .ascii " failed (errno "
s_errno_end:
m_socket:   .asciz "socket"
m_bind:     .asciz "bind"
m_listen:   .asciz "listen"
m_mmap:     .asciz "mmap"
m_clone:    .asciz "clone"
m_setup:    .asciz "io_uring_setup (need Linux >= 6.6 and io_uring allowed by seccomp)"
m_files:    .asciz "register fixed files"
m_pbuf:     .asciz "register buffer ring"

        .p2align 3
g_bpf:                                      // struct sock_filter[2]
        .hword  0x20                        // BPF_LD|BPF_W|BPF_ABS
        .byte   0, 0
        .word   0xfffff024                  // SKF_AD_OFF + SKF_AD_CPU
        .hword  0x16                        // BPF_RET|BPF_A
        .byte   0, 0
        .word   0

        .data
        .p2align 3
g_fprog:    .hword 2, 0, 0, 0               // struct sock_fprog {len; *filter}
            .quad  0

        .bss
        .p2align 4
g_affbuf:   .space 128
g_cpus:     .space 4 * MAX_THREADS
g_lfds:     .space 4 * MAX_THREADS
g_ncpus:    .space 4
g_nthreads: .space 4
g_one:      .space 4
g_steer:    .space 4
g_sockaddr: .space 16
g_rlim:     .space 16
g_line:     .space 256
