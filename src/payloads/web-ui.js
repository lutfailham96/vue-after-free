//simple server

include('userland.js')

jsmaf.remotePlay = true

// register socket stuff
try { fn.register(97, 'socket', 'bigint') } catch(e) {}
try { fn.register(98, 'connect', 'bigint') } catch(e) {}
try { fn.register(104, 'bind', 'bigint') } catch(e) {}
try { fn.register(105, 'setsockopt', 'bigint') } catch(e) {}
try { fn.register(106, 'listen', 'bigint') } catch(e) {}
try { fn.register(30, 'accept', 'bigint') } catch(e) {}
try { fn.register(32, 'getsockname', 'bigint') } catch(e) {}
try { fn.register(3, 'read', 'bigint') } catch(e) {}
try { fn.register(4, 'write', 'bigint') } catch(e) {}
try { fn.register(6, 'close', 'bigint') } catch(e) {}

var socket_sys = fn.socket
var connect_sys = fn.connect
var bind_sys = fn.bind
var setsockopt_sys = fn.setsockopt
var listen_sys = fn.listen
var accept_sys = fn.accept
var getsockname_sys = fn.getsockname
var read_sys = fn.read
var write_sys = fn.write
var close_sys = fn.close

var AF_INET = 2
var SOCK_STREAM = 1
var SOCK_DGRAM = 2
var SOL_SOCKET = 0xFFFF
var SO_REUSEADDR = 0x4

// just a simple page with one button lol
var html = '<!DOCTYPE html>\n' +
'<html>\n' +
'<head>\n' +
'<title>ps4 test</title>\n' +
'<style>\n' +
'body{background:#222;color:#0f0;font-family:monospace;padding:20px;}\n' +
'h1{color:#0f0;}\n' +
'button{background:#444;color:#0f0;border:2px solid #0f0;padding:10px 20px;font-size:16px;cursor:pointer;font-family:monospace;}\n' +
'button:hover{background:#0f0;color:#000;}\n' +
'.info{margin:20px 0;}\n' +
'</style>\n' +
'</head>\n' +
'<body>\n' +
'<h1>ps4 jailbreak test</h1>\n' +
'<div class="info">\n' +
'eboot base: ' + eboot_addr.toString() + '\n' +
'</div>\n' +
'<button onclick="location.href=\'/run-lapse\'">load lapse_test.js</button>\n' +
'</body>\n' +
'</html>\n';

// detect local ip by connecting to 8.8.8.8 (doesnt actually send anything)
log('detecting local ip...')
var detect_fd = socket_sys(new BigInt(0, AF_INET), new BigInt(0, SOCK_DGRAM), new BigInt(0, 0))
if (detect_fd.lo < 0) throw new Error('socket failed')

var detect_addr = mem.malloc(16)
mem.view(detect_addr).setUint8(0, 16)
mem.view(detect_addr).setUint8(1, AF_INET)
mem.view(detect_addr).setUint16(2, 0x3500, false) // port 53
mem.view(detect_addr).setUint32(4, 0x08080808, false) // 8.8.8.8

var local_ip = '127.0.0.1' // fallback

if (connect_sys(detect_fd, detect_addr, new BigInt(0, 16)).lo >= 0) {
    var local_addr = mem.malloc(16)
    var local_len = mem.malloc(4)
    mem.view(local_len).setUint32(0, 16, true)

    if (getsockname_sys(detect_fd, local_addr, local_len).lo >= 0) {
        var ip_int = mem.view(local_addr).getUint32(4, false)
        var ip1 = (ip_int >> 24) & 0xFF
        var ip2 = (ip_int >> 16) & 0xFF
        var ip3 = (ip_int >> 8) & 0xFF
        var ip4 = ip_int & 0xFF
        local_ip = ip1 + '.' + ip2 + '.' + ip3 + '.' + ip4
        log('detected ip: ' + local_ip)
    }
}

close_sys(detect_fd)

// create server socket
log('creating server...')
var srv = socket_sys(new BigInt(0, AF_INET), new BigInt(0, SOCK_STREAM), new BigInt(0, 0))
if (srv.lo < 0) throw new Error('cant create socket')

// set SO_REUSEADDR
var optval = mem.malloc(4)
mem.view(optval).setUint32(0, 1, true)
setsockopt_sys(srv, new BigInt(0, SOL_SOCKET), new BigInt(0, SO_REUSEADDR), optval, new BigInt(0, 4))

// bind to 0.0.0.0:0 (let os pick port)
var addr = mem.malloc(16)
mem.view(addr).setUint8(0, 16)
mem.view(addr).setUint8(1, AF_INET)
mem.view(addr).setUint16(2, 0, false) // port 0
mem.view(addr).setUint32(4, 0, false) // 0.0.0.0

if (bind_sys(srv, addr, new BigInt(0, 16)).lo < 0) {
    close_sys(srv)
    throw new Error('bind failed')
}

// get actual port
var actual_addr = mem.malloc(16)
var actual_len = mem.malloc(4)
mem.view(actual_len).setUint32(0, 16, true)
getsockname_sys(srv, actual_addr, actual_len)
var port = mem.view(actual_addr).getUint16(2, false)

log('got port: ' + port)

// listen
if (listen_sys(srv, new BigInt(0, 5)).lo < 0) {
    close_sys(srv)
    throw new Error('listen failed')
}

log('server started on 0.0.0.0:' + port)
log('local url: http://127.0.0.1:' + port)
log('network url: http://' + local_ip + ':' + port)

// try to open browser
try {
    jsmaf.openWebBrowser('http://127.0.0.1:' + port)
    log('opened browser')
} catch(e) {
    log('couldnt open browser: ' + e.message)
}

// helper to send response
function send_response(fd, body) {
    var resp = 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ' + body.length + '\r\nConnection: close\r\n\r\n' + body
    var buf = mem.malloc(resp.length)
    for (var i = 0; i < resp.length; i++) {
        mem.view(buf).setUint8(i, resp.charCodeAt(i))
    }
    write_sys(fd, buf, new BigInt(0, resp.length))
}

// parse path from http request
function get_path(buf, len) {
    var req = ''
    for (var i = 0; i < len && i < 1024; i++) {
        var c = mem.view(buf).getUint8(i)
        if (c === 0) break
        req += String.fromCharCode(c)
    }

    // GET /path HTTP/1.1
    var lines = req.split('\n')
    if (lines.length > 0) {
        var parts = lines[0].trim().split(' ')
        if (parts.length >= 2) return parts[1]
    }
    return '/'
}

log('waiting for connections...')

var count = 0
var max = 50
var client_addr = mem.malloc(16)
var client_len = mem.malloc(4)
var req_buf = mem.malloc(4096)

while (count < max) {
    log('')
    log('[' + (count + 1) + '/' + max + '] waiting...')

    mem.view(client_len).setUint32(0, 16, true)
    var client_ret = accept_sys(srv, client_addr, client_len)
    var client = client_ret instanceof BigInt ? client_ret.lo : client_ret

    if (client < 0) {
        log('accept failed: ' + client)
        continue
    }

    log('client connected')

    // read request
    var read_ret = read_sys(client, req_buf, new BigInt(0, 4096))
    var bytes = read_ret instanceof BigInt ? read_ret.lo : read_ret
    log('read ' + bytes + ' bytes')

    var path = get_path(req_buf, bytes)
    log('path: ' + path)

    // handle /run-lapse
    if (path.indexOf('/run-lapse') === 0) {
        log('running lapse_test.js')

        send_response(client, 'running lapse_test.js... check console')
        close_sys(client)

        try {
            log('=== lapse_test start ===')

            // load binloader and lapse
            include('binloader.js')
            include('lapse.js')

            // wait for lapse to finish
            function check_lapse() {
                if (typeof libc_addr === 'undefined') return false
                if (typeof kernel === 'undefined' || !kernel.read_qword) return false
                if (typeof getuid !== 'undefined') {
                    try {
                        var uid = getuid()
                        if (!uid.eq(0)) return false
                    } catch(e) { return false }
                }
                return true
            }

            log('waiting for lapse...')
            var start = Date.now()
            var timeout = 60000

            while (!check_lapse()) {
                if (Date.now() - start > timeout) {
                    log('lapse timeout')
                    break
                }
                // wait a bit
                var t = Date.now()
                while (Date.now() - t < 500) {}
            }

            var elapsed = ((Date.now() - start) / 1000).toFixed(1)
            log('lapse done in ' + elapsed + 's')

            // init binloader
            log('init binloader...')
            binloader_init()
            log('binloader ready')

            log('=== lapse_test done ===')
        } catch(e) {
            log('error: ' + e.message)
            if (e.stack) log(e.stack)
        }
    } else {
        // just serve the main page
        send_response(client, html)
        close_sys(client)
    }

    log('closed connection')
    count++
}

log('')
log('reached max requests (' + max + ')')
close_sys(srv)
log('done')
