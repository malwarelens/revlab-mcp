/*
 * process_network.js -- revlab-mcp bundled Frida script.
 *
 * Hooks process creation, WinINet / WinHTTP requests and DNS lookups,
 * reporting structured events via send():
 *   { api: "WinHttpOpenRequest", args: { verb: "POST", object: "/gate" },
 *     tid: 1234, backtrace: [...] }
 *
 * This is the "who does it talk to and what does it spawn" companion
 * to api_monitor.js. Every hook is best-effort: missing exports are
 * skipped silently and argument decoding is defensive.
 */

'use strict';

function safeUtf16(ptr) {
  try {
    if (ptr.isNull()) return null;
    return ptr.readUtf16String();
  } catch (e) { return '<unreadable>'; }
}

function safeUtf8(ptr) {
  try {
    if (ptr.isNull()) return null;
    return ptr.readUtf8String();
  } catch (e) { return '<unreadable>'; }
}

function emit(api, args, context) {
  var bt = [];
  try {
    bt = Thread.backtrace(context, Backtracer.ACCURATE).slice(0, 6)
      .map(DebugSymbol.fromAddress).map(function (s) { return s.toString(); });
  } catch (e) { /* backtrace is decoration only */ }
  send({ api: api, args: args || {}, tid: Process.getCurrentThreadId(),
         backtrace: bt });
}

function hook(moduleName, exportName, onEnter) {
  try {
    var addr = Module.findExportByName(moduleName, exportName);
    if (addr === null) return;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        try { onEnter.call(this, args); } catch (e) { /* never break the target */ }
      }
    });
  } catch (e) { /* export not present -- skip */ }
}

/* ---- process creation ---- */
hook('kernel32.dll', 'CreateProcessW', function (args) {
  emit('CreateProcessW', { application: safeUtf16(args[0]),
                           cmdline: safeUtf16(args[1]) }, this.context);
});
hook('kernel32.dll', 'CreateProcessA', function (args) {
  emit('CreateProcessA', { application: safeUtf8(args[0]),
                           cmdline: safeUtf8(args[1]) }, this.context);
});
hook('ntdll.dll', 'NtCreateUserProcess', function () {
  emit('NtCreateUserProcess', {}, this.context);
});

/* ---- WinINet ---- */
hook('wininet.dll', 'InternetOpenW', function (args) {
  emit('InternetOpenW', { agent: safeUtf16(args[0]) }, this.context);
});
hook('wininet.dll', 'InternetConnectW', function (args) {
  emit('InternetConnectW', { host: safeUtf16(args[1]),
                             port: args[2].toInt32() }, this.context);
});
hook('wininet.dll', 'HttpOpenRequestW', function (args) {
  emit('HttpOpenRequestW', { verb: safeUtf16(args[1]),
                             object: safeUtf16(args[2]) }, this.context);
});
hook('wininet.dll', 'HttpSendRequestW', function (args) {
  emit('HttpSendRequestW', { headers_len: args[2].toInt32(),
                             body_len: args[4].toInt32() }, this.context);
});
hook('wininet.dll', 'InternetReadFile', function (args) {
  emit('InternetReadFile', { buffer_size: args[2].toInt32() }, this.context);
});

/* ---- WinHTTP ---- */
hook('winhttp.dll', 'WinHttpOpen', function (args) {
  emit('WinHttpOpen', { agent: safeUtf16(args[0]) }, this.context);
});
hook('winhttp.dll', 'WinHttpConnect', function (args) {
  emit('WinHttpConnect', { host: safeUtf16(args[1]),
                           port: args[2].toInt32() }, this.context);
});
hook('winhttp.dll', 'WinHttpOpenRequest', function (args) {
  emit('WinHttpOpenRequest', { verb: safeUtf16(args[1]),
                               object: safeUtf16(args[2]) }, this.context);
});
hook('winhttp.dll', 'WinHttpSendRequest', function (args) {
  emit('WinHttpSendRequest', { body_len: args[4].toInt32(),
                               total_len: args[5].toInt32() }, this.context);
});
hook('winhttp.dll', 'WinHttpReadData', function (args) {
  emit('WinHttpReadData', { buffer_size: args[2].toInt32() }, this.context);
});

/* ---- DNS ---- */
hook('ws2_32.dll', 'getaddrinfo', function (args) {
  emit('getaddrinfo', { node: safeUtf8(args[0]),
                        service: safeUtf8(args[1]) }, this.context);
});
hook('ws2_32.dll', 'GetAddrInfoW', function (args) {
  emit('GetAddrInfoW', { node: safeUtf16(args[0]),
                         service: safeUtf16(args[1]) }, this.context);
});
hook('dnsapi.dll', 'DnsQuery_W', function (args) {
  emit('DnsQuery_W', { name: safeUtf16(args[0]),
                       type: args[1].toInt32() }, this.context);
});
hook('dnsapi.dll', 'DnsQuery_A', function (args) {
  emit('DnsQuery_A', { name: safeUtf8(args[0]),
                       type: args[1].toInt32() }, this.context);
});

send({ api: '__script_loaded__', args: { script: 'process_network.js' } });
