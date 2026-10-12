/*
 * crypto_monitor.js -- revlab-mcp bundled Frida script.
 *
 * Hooks the classic CryptoAPI / CNG encryption entry points and
 * reports structured events via send():
 *   { api: "CryptEncrypt", args: { data_len: 128, preview: "ab12..." },
 *     tid: 1234, backtrace: [...] }
 *
 * For each call the event carries the data length and a hex preview
 * of the first 64 bytes of the *output* buffer (ciphertext for
 * encrypt, recovered plaintext for decrypt) -- enough for an analyst
 * to spot keys, headers and known plaintext without shipping whole
 * buffers through the event channel.
 *
 * Every hook is best-effort: missing exports are skipped silently and
 * argument decoding is defensive -- a bad read never kills the script.
 */

'use strict';

var PREVIEW_BYTES = 64;

function safeLen(ptr) {
  try {
    if (ptr.isNull()) return null;
    return ptr.readU32();
  } catch (e) { return null; }
}

function hexPreview(ptr, len) {
  try {
    if (ptr.isNull() || len === null || len <= 0) return null;
    var n = Math.min(len, PREVIEW_BYTES);
    var bytes = new Uint8Array(ptr.readByteArray(n));
    var out = '';
    for (var i = 0; i < bytes.length; i++) {
      var h = bytes[i].toString(16);
      out += (h.length === 1 ? '0' : '') + h;
    }
    return out;
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

function hook(moduleName, exportName, callbacks) {
  try {
    var addr = Module.findExportByName(moduleName, exportName);
    if (addr === null) return;
    Interceptor.attach(addr, callbacks);
  } catch (e) { /* export not present -- skip */ }
}

/* BOOL CryptEncrypt(HCRYPTKEY, HCRYPTHASH, BOOL Final, DWORD dwFlags,
 *                   BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen)
 * Enter: *pdwDataLen = plaintext length. Leave: pbData = ciphertext. */
hook('advapi32.dll', 'CryptEncrypt', {
  onEnter: function (args) {
    this.pbData = args[4];
    this.pdwDataLen = args[5];
    this.inputLen = safeLen(args[5]);
  },
  onLeave: function (retval) {
    if (retval.toInt32() === 0) return;  /* FALSE -- call failed */
    try {
      var outLen = safeLen(this.pdwDataLen);
      emit('CryptEncrypt', {
        input_len: this.inputLen,
        data_len: outLen,
        preview: hexPreview(this.pbData, outLen)
      }, this.context);
    } catch (e) { /* never break the target */ }
  }
});

/* BOOL CryptDecrypt(HCRYPTKEY, HCRYPTHASH, BOOL Final, DWORD dwFlags,
 *                   BYTE *pbData, DWORD *pdwDataLen)
 * Enter: pbData = ciphertext. Leave: pbData = recovered plaintext. */
hook('advapi32.dll', 'CryptDecrypt', {
  onEnter: function (args) {
    this.pbData = args[4];
    this.pdwDataLen = args[5];
    this.inputLen = safeLen(args[5]);
  },
  onLeave: function (retval) {
    if (retval.toInt32() === 0) return;
    try {
      var outLen = safeLen(this.pdwDataLen);
      emit('CryptDecrypt', {
        input_len: this.inputLen,
        data_len: outLen,
        preview: hexPreview(this.pbData, outLen)
      }, this.context);
    } catch (e) { /* never break the target */ }
  }
});

/* NTSTATUS BCryptEncrypt(BCRYPT_KEY_HANDLE, PUCHAR pbInput, ULONG cbInput,
 *   VOID *pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput,
 *   ULONG cbOutput, ULONG *pcbResult, ULONG dwFlags)
 * pbOutput may be NULL (size query) -- that case is reported without a
 * preview. The event carries both the plaintext input preview and the
 * ciphertext output preview. */
hook('bcrypt.dll', 'BCryptEncrypt', {
  onEnter: function (args) {
    this.pbInput = args[1];
    this.cbInput = args[2].toInt32();
    this.pbOutput = args[6];
    this.pcbResult = args[8];
  },
  onLeave: function (retval) {
    if (retval.toInt32() !== 0) return;  /* NTSTATUS != STATUS_SUCCESS */
    try {
      var outLen = safeLen(this.pcbResult);
      emit('BCryptEncrypt', {
        input_len: this.cbInput,
        data_len: outLen,
        input_preview: hexPreview(this.pbInput, this.cbInput),
        preview: this.pbOutput.isNull() ? null
                 : hexPreview(this.pbOutput, outLen)
      }, this.context);
    } catch (e) { /* never break the target */ }
  }
});

send({ api: '__script_loaded__', args: { script: 'crypto_monitor.js' } });
