/*
 * api_monitor.js -- revlab-mcp bundled Frida script.
 *
 * Hooks a starter set of WinAPI functions commonly seen in malware
 * behaviour monitoring and reports structured events via send():
 *   { api: "CreateFileW", args: { path: "..." }, tid: 1234, backtrace: [...] }
 *
 * Every hook is best-effort: if an export is missing on the target
 * (different Windows version / WOW64), that hook is skipped silently.
 * Argument decoding is defensive -- a bad read never kills the script.
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

function emit(api, args) {
  send({
    api: api,
    args: args || {},
    tid: Process.getCurrentThreadId(),
    backtrace: Thread.backtrace(this ? this.context : null, Backtracer.ACCURATE)
      .slice(0, 6).map(DebugSymbol.fromAddress).map(function (s) { return s.toString(); })
  });
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

/* ---- file system ---- */
hook('kernel32.dll', 'CreateFileW', function (args) {
  emit('CreateFileW', { path: safeUtf16(args[0]), access: args[1].toString() });
});
hook('kernel32.dll', 'DeleteFileW', function (args) {
  emit('DeleteFileW', { path: safeUtf16(args[0]) });
});
hook('kernel32.dll', 'WriteFile', function (args) {
  emit('WriteFile', { handle: args[0].toString(), length: args[2].toInt32() });
});
hook('ntdll.dll', 'NtCreateFile', function (args) {
  emit('NtCreateFile', {});
});

/* ---- registry ---- */
hook('advapi32.dll', 'RegCreateKeyExW', function (args) {
  emit('RegCreateKeyExW', { subkey: safeUtf16(args[1]) });
});
hook('advapi32.dll', 'RegSetValueExW', function (args) {
  emit('RegSetValueExW', { value_name: safeUtf16(args[1]), type: args[3].toInt32(),
                           size: args[5].toInt32() });
});
hook('advapi32.dll', 'RegDeleteValueW', function (args) {
  emit('RegDeleteValueW', { value_name: safeUtf16(args[1]) });
});

/* ---- process / injection ---- */
hook('kernel32.dll', 'VirtualAllocEx', function (args) {
  emit('VirtualAllocEx', { process: args[0].toString(), address: args[1].toString(),
                           size: args[2].toInt32(), protect: args[4].toString() });
});
hook('kernel32.dll', 'WriteProcessMemory', function (args) {
  emit('WriteProcessMemory', { process: args[0].toString(), address: args[1].toString(),
                               size: args[3].toInt32() });
});
hook('kernel32.dll', 'CreateRemoteThread', function (args) {
  emit('CreateRemoteThread', { process: args[0].toString(), start: args[3].toString(),
                               parameter: args[4].toString() });
});
hook('kernel32.dll', 'CreateProcessW', function (args) {
  emit('CreateProcessW', { application: safeUtf16(args[0]), cmdline: safeUtf16(args[1]) });
});
hook('kernel32.dll', 'OpenProcess', function (args) {
  emit('OpenProcess', { access: args[0].toString(), pid: args[2].toInt32() });
});

/* ---- memory ---- */
hook('kernel32.dll', 'VirtualProtect', function (args) {
  emit('VirtualProtect', { address: args[0].toString(), size: args[1].toInt32(),
                           protect: args[2].toString() });
});
hook('kernel32.dll', 'LoadLibraryW', function (args) {
  emit('LoadLibraryW', { name: safeUtf16(args[0]) });
});

/* ---- networking ---- */
hook('wininet.dll', 'InternetOpenW', function (args) {
  emit('InternetOpenW', { agent: safeUtf16(args[0]) });
});
hook('wininet.dll', 'InternetConnectW', function (args) {
  emit('InternetConnectW', { host: safeUtf16(args[1]), port: args[2].toInt32() });
});
hook('winhttp.dll', 'WinHttpConnect', function (args) {
  emit('WinHttpConnect', { host: safeUtf16(args[1]), port: args[2].toInt32() });
});
hook('winhttp.dll', 'WinHttpOpenRequest', function (args) {
  emit('WinHttpOpenRequest', { verb: safeUtf16(args[1]), object: safeUtf16(args[2]) });
});
hook('ws2_32.dll', 'connect', function (args) {
  emit('connect', { socket: args[0].toString() });
});
hook('ws2_32.dll', 'send', function (args) {
  emit('send', { socket: args[0].toString(), length: args[2].toInt32() });
});

/* ---- crypto ---- */
hook('advapi32.dll', 'CryptEncrypt', function (args) {
  emit('CryptEncrypt', { data_len: args[4].isNull() ? null : args[4].readU32() });
});
hook('bcrypt.dll', 'BCryptEncrypt', function (args) {
  emit('BCryptEncrypt', { input_len: args[2].toInt32() });
});

/* ---- anti-debug / timing ---- */
hook('kernel32.dll', 'IsDebuggerPresent', function () {
  emit('IsDebuggerPresent', {});
});
hook('kernel32.dll', 'GetTickCount', function () {
  emit('GetTickCount', {});
});

send({ api: '__script_loaded__', args: { script: 'api_monitor.js' } });
