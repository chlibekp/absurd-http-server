// Shared constants: io_uring ABI, data layouts and tunables. Architecture
// independent; included first by src/<arch>/absurd.s.

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
        .equ REG_FILE_ALLOC_RANGE,   25

        .equ OP_SENDMSG,             9
        .equ OP_TIMEOUT,             11
        .equ OP_ACCEPT,              13
        .equ OP_ASYNC_CANCEL,        14
        .equ OP_CONNECT,             16
        .equ OP_CLOSE,               19
        .equ OP_RECV,                27
        .equ OP_SHUTDOWN,            34
        .equ OP_SOCKET,              45

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

        // SQE flags
        .equ SQF_FIXED,              0x01
        .equ SQF_LINK,               0x04
        .equ SQF_HARDLINK,           0x08
        .equ SQF_SKIP,               0x40
        .equ SQF_ALLOWED,            SQF_FIXED | SQF_LINK | SQF_HARDLINK | SQF_SKIP

        // First 8 bytes of an SQE: opcode | flags<<8 | ioprio<<16 | fd<<32
        .equ SQE_ACCEPT,             0x000d
        .equ SQE_RECV,               0x011b   // RECV, FIXED_FILE
        .equ SQE_SENDMSG,            0x0109   // SENDMSG, FIXED_FILE
        .equ SQE_CLOSE,              0x4013   // CLOSE, CQE_SKIP_SUCCESS
        .equ SQE_CLOSE_CQE,          0x0013   // CLOSE, completion wanted
        .equ SQE_CANCEL,             0x400e   // ASYNC_CANCEL, CQE_SKIP_SUCCESS
        .equ CANCEL_ALL_FIXED_FD,    0xb      // CANCEL_ALL | CANCEL_FD | CANCEL_FD_FIXED
        .equ SQE_SHUTDOWN_LINK,      0x4922   // SHUTDOWN, FIXED_FILE|IO_HARDLINK|CQE_SKIP_SUCCESS
        .equ SQE_TIMEOUT,            0x000b
        .equ SQE_SOCKET_LINK,        0x442d   // SOCKET, IO_LINK|CQE_SKIP_SUCCESS
        .equ SQE_CONNECT,            0x0110   // CONNECT, FIXED_FILE
        .equ RECV_POLL_FIRST,        1
        .equ MSG_WAITALL_NOSIGNAL,   0x4100
        .equ MSG_NOSIGNAL,           0x4000
        .equ TIMEOUT_MULTISHOT,      1 << 6
        .equ FILE_INDEX_ALLOC,       0xffffffff

// ---------------------------------------------------------------- user_data tags
        .equ T_ACCEPT,               1
        .equ T_RECV,                 2
        .equ T_TIMER,                3
        .equ T_SEND,                 4
        .equ T_CLOSE,                5
        .equ T_SHUT,                 6
        .equ T_UCONN,                7        // upstream connect finished
        .equ T_USEND,                8
        .equ T_URECV,                9
        .equ T_UCLOSE,               10       // upstream socket closed: slot reusable
        .equ T_IGN,                  11

// ---------------------------------------------------------------- tuning
        .equ PORT_DEFAULT,           8080
        .equ MAX_THREADS,            256
        .equ BACKLOG,                65535
        .equ STACK_SIZE,             65536
        .equ SQ_ENTRIES,             4096
        .equ CQ_ENTRIES,             16384
        .equ CQ_BATCH,               1024
        .equ NACCEPT,                16       // single-shot accepts kept in flight (each has its own peer address)
        .equ MAXCONN,                8192     // client fixed-file slots per thread
        .equ MAXPROXY,               256      // upstream connections per thread
        .equ NFILES,                 MAXCONN + MAXPROXY
        .equ CONN_SHIFT,             15       // 32 KiB per connection
        .equ MAXIOV,                 48       // per iovec array
        .equ IOV_ROOM,               MAXIOV - 6
        .equ S_MSGA,                 0        // struct msghdr x2
        .equ S_MSGB,                 64
        .equ S_IOVA,                 128      // struct iovec[MAXIOV] x2
        .equ S_IOVB,                 S_IOVA + MAXIOV * 16
        .equ S_SCRA,                 S_IOVB + MAXIOV * 16   // per-array scratch for dynamic headers
        .equ SCRCAP,                 4096
        .equ SCR_ROOM,               SCRCAP - 2800
        .equ S_SCRB,                 S_SCRA + SCRCAP
        .equ S_IN,                   S_SCRB + SCRCAP
        .equ INCAP,                  (1 << CONN_SHIFT) - S_IN - 64   // request bytes held at once
        .equ HEADMAX,                14656    // largest request head (431 above)
        .equ CHUNK,                  1 << 20  // bodies go out 1 MiB per sendmsg
        .equ PATHMAX,                2048
        .equ STATIC_BODY_MAX,        1 << 20  // request bodies discarded for static targets
        .equ TO_HEADER,              15
        .equ TO_IDLE,                30
        .equ TO_SEND,                60
        .equ TO_UPSTREAM,            60

        .equ TABLE_SLOTS,            1 << 17
        .equ MAX_ENTRIES,            TABLE_SLOTS / 2
        .equ ESIZE_SHIFT,            7
        .equ TABLE_BYTES,            TABLE_SLOTS << ESIZE_SHIFT
        .equ SNAP_MAX,               1 << 30
        .equ ARENA_RESERVE,          TABLE_BYTES + SNAP_MAX + (MAX_ENTRIES * 1024) + (1 << 20)
        .equ URLMAX,                 3800
        .equ MAXDEPTH,               24
        .equ DENTBUF,                16384

        .equ CFGMAX,                 65536
        .equ MAXROUTES,              32
        .equ MAXCHAL,                32

// ---------------------------------------------------------------- table entry (128 B)
        .equ E_HASH,                 0
        .equ E_KEY,                  8
        .equ E_KEYLEN,               16
        .equ E_FLAGS,                20
        .equ E_HDR,                  24       // full head, without Date and the final CRLF
        .equ E_HDRLEN,               32
        .equ E_H304LEN,              36
        .equ E_H304,                 40
        .equ E_BODY,                 48
        .equ E_BODYLEN,              56
        .equ E_MTIME,                64       // Last-Modified, seconds
        .equ E_ETAG,                 72       // the 16 hex digits of the ETag
        .equ E_TAIL,                 80       // headers after Content-Length (reused for 206)
        .equ E_TAILLEN,              88
        .equ EF_FILE_BIT,            0        // a file: validators, ranges
        .equ EF_CLOSE_BIT,           1        // close the connection after this response
        .equ EF_RAW_BIT,             2        // complete as is: no Date line, no body (100 Continue)
        .equ EF_FILE,                1
        .equ EF_CLOSE,               2
        .equ EF_RAW,                 4

// ---------------------------------------------------------------- request info (per thread)
        .equ RQ_KIND,                0
        .equ RQ_FLAGS,               4
        .equ RQ_ENTRY,               8
        .equ RQ_ROUTE,               16
        .equ RQ_RFIRST,              24
        .equ RQ_RLAST,               32
        .equ RQ_MPTR,                40
        .equ RQ_MLEN,                48
        .equ RQ_TPTR,                56       // origin-form target (path + query)
        .equ RQ_TLEN,                64
        .equ RQ_HPTR,                72       // first header line
        .equ RQ_HEND,                80       // byte after the head
        .equ RQ_AUTH,                88       // authority of an absolute-form target
        .equ RQ_AUTHLEN,             96
        .equ RQ_BMODE,               104
        .equ RQ_METHOD,              108
        .equ RQ_BREM,                112
        .equ RQ_INM,                 120      // (ptr, end) pairs of header values
        .equ RQ_IM,                  136
        .equ RQ_IMS,                 152
        .equ RQ_IUS,                 168
        .equ RQ_IR,                  184
        .equ RQ_RANGE,               200
        .equ RQ_CLR,                 216      // absurd_clearance cookie value
        .equ RQ_POW,                 232      // absurd_pow cookie value
        .equ RQ_TE,                  248      // transfer-coding state bits
        .equ RQ_CLSEEN,              252
        .equ RQ_SIZE,                256

        .equ TE_SEEN,                1
        .equ TE_LASTCH,              2
        .equ TE_OTHER,               4
        .equ TE_CHUNKED,             8

        .equ K_ENTRY,                0        // static entry (maybe as 304)
        .equ K_RANGE,                1        // 206 for RQ_RFIRST..RQ_RLAST of the entry
        .equ K_416,                  2
        .equ K_CHPAGE,               3        // JS challenge page
        .equ K_CHPASS,               4        // solved challenge: 307 + clearance cookie
        .equ K_PROXY,                5

        .equ MT_UNKNOWN,             0
        .equ MT_GET,                 1
        .equ MT_HEAD,                2
        .equ MT_OPTIONS,             3
        .equ MT_POST,                4
        .equ MT_PUT,                 5
        .equ MT_DELETE,              6
        .equ MT_PATCH,               7
        .equ MT_TRACE,               8
        .equ MT_CONNECT,             9

// ---------------------------------------------------------------- parse result flags
        .equ R_NOBODY,               1
        .equ R_304,                  2
        .equ R_CLOSE,                4
        .equ R_KA,                   8
        .equ R_V11,                  16
        .equ R_HOST,                 32
        .equ R_CCLOSE,               64
        .equ R_CKA,                  128
        .equ R_EXPECT,               256
        .equ R_EXPECTBAD,            512
        .equ R_ABS,                  1024
        .equ R_NOBODY_BIT,           0
        .equ R_304_BIT,              1
        .equ R_CLOSE_BIT,            2
        .equ R_KA_BIT,               3
        .equ R_V11_BIT,              4
        .equ R_HOST_BIT,             5
        .equ R_CCLOSE_BIT,           6
        .equ R_CKA_BIT,              7
        .equ R_EXPECT_BIT,           8
        .equ R_EXPECTBAD_BIT,        9
        .equ R_ABS_BIT,              10

// ---------------------------------------------------------------- body framer (16 B)
        .equ FR_MODE,                0        // byte
        .equ FR_STATE,               1        // byte
        .equ FR_LINE,                2        // u16: length of the current ext/trailer line
        .equ FR_REM,                 8
        .equ BM_NONE,                0
        .equ BM_LEN,                 1
        .equ BM_CHUNKED,             2
        .equ BM_CLOSE,               3        // until EOF (responses only)
        .equ CS_SIZE0,               0
        .equ CS_SIZE,                1
        .equ CS_EXT,                 2
        .equ CS_SIZELF,              3
        .equ CS_DATA,                4
        .equ CS_DATACR,              5
        .equ CS_DATALF,              6
        .equ CS_TRL0,                7
        .equ CS_TRL,                 8
        .equ CS_TRLLF,               9
        .equ CS_ENDLF,               10
        .equ CS_DONE,                11
        .equ FS_MORE,                0        // framer status
        .equ FS_DONE,                1
        .equ FS_ERR,                 2
        .equ LINE_MAX,               4096

// ---------------------------------------------------------------- per-connection meta (128 B)
        .equ M_FILL,                 0
        .equ M_POS,                  4
        .equ M_FLAGS,                8
        .equ M_IOVCNT,               12
        .equ M_ACC,                  16       // which iovec array is accumulating
        .equ M_LAST,                 20       // last progress (s)
        .equ M_RSTART,               24       // first byte of the current partial request (s)
        .equ M_PEER,                 28       // IPv4 address, network order
        .equ M_CONTLEN,              32       // body bytes still to send
        .equ M_CONTPTR,              40
        .equ M_SCR,                  48       // bytes used in the accumulating scratch
        .equ M_PSLOT,                52       // proxy slot of the exchange in progress
        .equ M_BODY,                 64       // framer for a discarded request body
        .equ META_SHIFT,             7
        .equ F_ACTIVE,               1
        .equ F_RECV,                 2        // recv in flight
        .equ F_SEND,                 4        // sendmsg in flight
        .equ F_CLOSING,              8        // tear down as soon as nothing is in flight
        .equ F_DRAIN,                16       // no more input; close once output is flushed
        .equ F_SHUT,                 32       // in-flight ops already cancelled
        .equ F_PARTIAL,              64
        .equ F_BODY,                 128      // discarding a request body
        .equ F_PROXY,                256      // a proxied exchange owns the connection
        .equ F_ACTIVE_BIT,           0
        .equ F_RECV_BIT,             1
        .equ F_SEND_BIT,             2
        .equ F_CLOSING_BIT,          3
        .equ F_DRAIN_BIT,            4
        .equ F_SHUT_BIT,             5
        .equ F_PARTIAL_BIT,          6
        .equ F_BODY_BIT,             7
        .equ F_PROXY_BIT,            8

// ---------------------------------------------------------------- proxy slot (64 KiB)
        .equ PX_STATE,               0        // 0 free, 1 in use
        .equ PX_CONN,                4        // client connection, -1 once detached
        .equ PX_FLAGS,               8
        .equ PX_LAST,                12
        .equ PX_REQ,                 16       // framer: request body
        .equ PX_RES,                 32       // framer: response body
        .equ PX_WLEN,                48       // request head bytes
        .equ PX_OOFF,                52       // bytes used in PX_OBUF
        .equ PX_RFILL,               56
        .equ PX_RPOS,                60
        .equ PX_BSENT,               64       // request body bytes in the send in flight
        .equ PX_NEXT,                68       // free list
        .equ PX_ROUTE,               72
        .equ PX_MSG,                 128      // struct msghdr
        .equ PX_IOV,                 192      // struct iovec
        .equ PX_HEAD,                1024
        .equ PX_HEADCAP,             16896
        .equ PX_RBUF,                PX_HEAD + PX_HEADCAP
        .equ PX_RCAP,                32768
        .equ PX_OBUF,                PX_RBUF + PX_RCAP
        .equ PX_OCAP,                65536 - PX_OBUF - 64
        .equ PX_SHIFT,               16
        .equ PF_CONN,                1        // socket+connect in flight
        .equ PF_SEND,                2
        .equ PF_RECV,                4
        .equ PF_HEADSENT,            8
        .equ PF_REQDONE,             16
        .equ PF_RESHEAD,             32       // final response head forwarded
        .equ PF_RESDONE,             64
        .equ PF_OUTPEND,             128      // client iovecs point into this slot
        .equ PF_CLOSE,               256      // client connection must close afterwards
        .equ PF_CLOSING,             512
        .equ PF_SHUT,                1024
        .equ PF_HEAD,                2048     // HEAD request: no response body
        .equ PF_DECHUNK,             4096     // HTTP/1.0 client: strip chunked framing
        .equ PF_V11,                 8192
        .equ PF_KA,                  16384
        .equ PF_ESTAB,               32768
        .equ PF_SENT,                65536    // response bytes already queued to the client
        .equ PF_FAIL,                131072   // upstream failed
        .equ PF_EOF,                 262144
        .equ PF_CONN_BIT,            0
        .equ PF_SEND_BIT,            1
        .equ PF_RECV_BIT,            2
        .equ PF_HEADSENT_BIT,        3
        .equ PF_REQDONE_BIT,         4
        .equ PF_RESHEAD_BIT,         5
        .equ PF_RESDONE_BIT,         6
        .equ PF_OUTPEND_BIT,         7
        .equ PF_CLOSE_BIT,           8
        .equ PF_CLOSING_BIT,         9
        .equ PF_SHUT_BIT,            10
        .equ PF_HEAD_BIT,            11
        .equ PF_DECHUNK_BIT,         12
        .equ PF_V11_BIT,             13
        .equ PF_KA_BIT,              14
        .equ PF_ESTAB_BIT,           15
        .equ PF_SENT_BIT,            16
        .equ PF_FAIL_BIT,            17
        .equ PF_EOF_BIT,             18

// ---------------------------------------------------------------- config records
        .equ RT_PREFIX,              0
        .equ RT_PLEN,                8
        .equ RT_ADDR,                16       // struct sockaddr_in
        .equ RT_HOST,                32       // "ip:port" text
        .equ RT_HOSTLEN,             40
        .equ RT_SIZE,                48

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
        .equ C_ACCPAUSE,             104      // bitmask of accepts to re-arm on the next tick
        .equ C_ID,                   108
        .equ C_SQTAIL,               112
        .equ C_SQMASK,               116
        .equ C_CQHEAD,               120
        .equ C_CQMASK,               124
        .equ C_PARAMS,               128
        .equ C_SQES,                 248
        .equ C_REG,                  256
        .equ C_BLOBS,                512      // 2 x 192 B of Date lines
        .equ C_PXFREE,               896
        .equ C_CQES,                 904
        .equ C_PXBASE,               912
        .equ C_CONNS,                920
        .equ C_META,                 928
        .equ C_ACCADDR,              1024     // NACCEPT x 32 B: sockaddr_in + socklen
        .equ C_REQ,                  1536
        .equ C_PATH,                 2048     // decoded request path
        .equ C_TGT,                  4160     // origin-form target built from absolute-form
        .equ C_SHA,                  6272     // SHA-256 work area (512 B)
        .equ C_TOKS,                 6784     // Connection tokens: 16 x (ptr, len)
        .equ NTOKS,                  16
        .equ O_META,                 8192
        .equ CTX_SIZE,               O_META + (MAXCONN << META_SHIFT)

        // Date line variants inside each 192 B blob
        .equ D0_LEN,                 39       // Date: ...\r\n\r\n
        .equ D1_LEN,                 58       // Date: ...\r\nConnection: close\r\n\r\n
        .equ D2_LEN,                 63       // Date: ...\r\nConnection: keep-alive\r\n\r\n

        // JS challenge
        .equ CH_NONCE_LEN,           26       // 8 hex ts + 16 hex MAC + 2 hex difficulty
        .equ CH_CLR_LEN,             24       // 8 hex expiry + 16 hex MAC
        .equ CH_POW_WINDOW,          300      // seconds a challenge stays solvable
        .equ TAG_POW,                0x706f77
        .equ TAG_CLR,                0x636c72
