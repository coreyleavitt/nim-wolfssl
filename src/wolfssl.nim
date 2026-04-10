## Nim wrapper for wolfSSL 5.x
##
## High-level TLS client API built on low-level bindings.
##
## **Linking modes** (compile-time choice):
##
## - **Dynamic** (default): uses ``softlink`` for runtime dlopen. The binary
##   starts even if the wolfSSL shared library is absent. Call
##   ``loadWolfssl()`` before use and ``wolfsslAvailable()`` to check.
## - **Static** (``-d:wolfsslStatic``): links ``.a`` archives at build time.
##   The binary always has wolfSSL baked in — no ``.so`` needed at runtime.
##
## .. code-block:: nim
##   var ctx = newTlsContext(caFile = "/etc/ssl/ca-bundle.pem")
##   ctx.connect("example.com", 443)
##   ctx.write("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
##   echo ctx.read()
##   ctx.close()
##
## Low-level access: ``import wolfssl/ssl`` for types/constants.
##
## **Thread safety:** ``TlsContext`` is not thread-safe. Each context must
## be used from a single thread. ``wolfSSL_Init()`` is called once via
## double-checked locking and is safe under concurrent ``newTlsContext`` calls.

import std/[nativesockets, locks, strutils]
import wolfssl/ssl
export ssl

when not defined(wolfsslStatic):
  import wolfssl/loader
  import softlink  # for SoftlinkError in {.raises.}
  export loader

type
  WolfSslError* = object of CatchableError
    code*: cint  ## wolfSSL error code

  TlsVersion* = enum
    tlsAuto  ## Negotiate highest available (wolfSSLv23_client_method)
    tls12    ## TLS 1.2 only (wolfTLSv1_2_client_method)
    tls13    ## TLS 1.3 only (wolfTLSv1_3_client_method)

  TlsState* = enum
    tsClosed = 0  ## Zero value — must remain first for wasMoved safety
    tsReady       ## Context initialized, ready to connect
    tsConnected   ## TLS session established, can read/write

  TlsContext* = object
    ## Owns all wolfSSL state for a single TLS client connection.
    ## Move-only: copying is a compile-time error. Not thread-safe.
    state: TlsState
    ctx: ptr WolfsslCtx
    ssl: ptr Wolfssl
    sockFd: SocketHandle

# -- Global init (thread-safe, called once) --------------------------------

var initLock: Lock
var initDone: bool
initLock.initLock()

proc ensureInit() =
  if not initDone:
    withLock initLock:
      if not initDone:
        if wolfSSL_Init() != SSL_SUCCESS:
          raise newException(WolfSslError, "wolfSSL_Init failed")
        initDone = true

# -- Lifecycle hooks --------------------------------------------------------

proc `=destroy`*(ctx: TlsContext) =
  ## Free all wolfSSL resources and close the socket.
  ## Safe on zero-initialized, partially-initialized, and moved-from objects.
  ##
  ## Does NOT send close_notify — no network I/O in destructors.
  ## Use close() for a clean TLS shutdown before teardown.
  # wolfSSL calls wrapped in try/except: in dynamic mode, softlink wrappers
  # can raise SoftlinkError if libraries were unloaded. Destructors must not
  # propagate exceptions.
  try:
    # Free in reverse dependency order: ssl references ctx.
    if ctx.ssl != nil:
      wolfSSL_free(ctx.ssl)
    if ctx.ctx != nil:
      wolfSSL_CTX_free(ctx.ctx)
  except CatchableError:
    discard  # best-effort cleanup; socket close below always runs
  if ctx.sockFd != osInvalidSocket:
    ctx.sockFd.close()
  # Zero critical fields so manual =destroy calls leave a safe state
  # rather than a zombie with dangling pointers. Uses addr to write
  # through the immutable TlsContext parameter (same pattern as Nim's
  # internal destructors).
  var p = addr ctx
  p.state = tsClosed
  p.ssl = nil
  p.ctx = nil
  p.sockFd = osInvalidSocket

proc `=copy`*(dst: var TlsContext, src: TlsContext) {.error:
  "TlsContext cannot be copied; use 'move' to transfer ownership".}

# -- Error translation ------------------------------------------------------

when not defined(wolfsslStatic):
  proc checkRet(ret: cint) {.inline, raises: [WolfSslError, SoftlinkError].} =
    ## Translate a non-success wolfSSL return code into an exception.
    ## For global/CTX-level calls where no ssl session exists.
    if ret != SSL_SUCCESS:
      var buf: array[256, char]
      discard wolfSSL_ERR_error_string(culong(cast[cuint](ret)), cast[cstring](addr buf[0]))
      buf[255] = '\0'
      let msg = $cast[cstring](addr buf[0])
      let err = newException(WolfSslError,
        if msg.len > 0 and msg != "unknown error number": msg
        else: "wolfSSL error: " & $ret)
      err.code = ret
      raise err

  proc checkRet(ssl: ptr Wolfssl, ret: cint) {.inline, raises: [WolfSslError, SoftlinkError].} =
    ## Translate a wolfSSL session-level error into an exception.
    ## Uses wolfSSL_get_error + wolfSSL_ERR_error_string for detail.
    if ret != SSL_SUCCESS and ret <= 0:
      let errCode = wolfSSL_get_error(ssl, ret)
      var buf: array[256, char]
      discard wolfSSL_ERR_error_string(culong(cast[cuint](errCode)), cast[cstring](addr buf[0]))
      buf[255] = '\0'  # defensive null-termination
      let err = newException(WolfSslError, $cast[cstring](addr buf[0]))
      err.code = errCode
      raise err
else:
  proc checkRet(ret: cint) {.inline, raises: [WolfSslError].} =
    if ret != SSL_SUCCESS:
      var buf: array[256, char]
      discard wolfSSL_ERR_error_string(culong(cast[cuint](ret)), cast[cstring](addr buf[0]))
      buf[255] = '\0'
      let msg = $cast[cstring](addr buf[0])
      let err = newException(WolfSslError,
        if msg.len > 0 and msg != "unknown error number": msg
        else: "wolfSSL error: " & $ret)
      err.code = ret
      raise err

  proc checkRet(ssl: ptr Wolfssl, ret: cint) {.inline, raises: [WolfSslError].} =
    if ret != SSL_SUCCESS and ret <= 0:
      let errCode = wolfSSL_get_error(ssl, ret)
      var buf: array[256, char]
      discard wolfSSL_ERR_error_string(culong(cast[cuint](errCode)), cast[cstring](addr buf[0]))
      buf[255] = '\0'  # defensive null-termination
      let err = newException(WolfSslError, $cast[cstring](addr buf[0]))
      err.code = errCode
      raise err

proc raiseStateError(msg: string) {.noinline, noreturn, raises: [WolfSslError].} =
  ## Raise WolfSslError for state machine violations. Unlike doAssert,
  ## this is never compiled out — misuse is always caught, even with -d:danger.
  raise newException(WolfSslError, msg)

proc isEofError(err: cint): bool {.inline.} =
  ## True if the wolfSSL error code represents an EOF condition.
  ## Used by both read() and readInto() to ensure consistent behavior.
  ## SSL_ERROR_SYSCALL is included because it covers the common case of
  ## the peer closing the TCP connection (recv returns 0).
  err == SSL_ERROR_ZERO_RETURN or err == SSL_ERROR_NONE or
  err == SSL_ERROR_SYSCALL or err == SOCKET_PEER_CLOSED_E

# -- Public API --------------------------------------------------------------

when not defined(wolfsslStatic):
  {.push raises: [WolfSslError, SoftlinkError].}
else:
  {.push raises: [WolfSslError].}

proc state*(ctx: TlsContext): TlsState {.inline, raises: [].} = ctx.state

proc close*(ctx: var TlsContext) =
  ## Send close_notify (if connected) and free all resources.
  ## Safe to call multiple times or on a never-connected context.
  ##
  ## Sends a unidirectional close_notify: we notify the peer we're done
  ## but don't wait for their response. This avoids blocking on an
  ## unresponsive peer while still enabling a clean TLS shutdown.
  if ctx.state == tsConnected and ctx.ssl != nil:
    # Best-effort unidirectional close_notify. Retry WANT codes up to 3
    # times; stop once we've sent (ret >= 0) or hit a real error.
    try:
      var retries = 0
      while retries < 3:
        let ret = wolfSSL_shutdown(ctx.ssl)
        if ret >= 0: break  # 0 = unidirectional done
        let err = wolfSSL_get_error(ctx.ssl, ret)
        if err != SSL_ERROR_WANT_READ and err != SSL_ERROR_WANT_WRITE:
          break  # real error — give up, best-effort
        inc retries
    except CatchableError:
      discard  # best-effort; teardown below always runs
  `=destroy`(ctx)
  wasMoved(ctx)

proc newTlsContext*(version = tlsAuto, caFile = "", caPath = "",
                    caData: openArray[byte] = [],
                    certFile = "", keyFile = "",
                    certData: openArray[byte] = [],
                    keyData: openArray[byte] = [],
                    verify = true): TlsContext =
  ## Create a TLS client context.
  ##
  ## *version* — TLS version selection (default negotiates highest).
  ## *caFile* — path to a PEM CA certificate file.
  ## *caPath* — path to a directory of PEM CA certificates.
  ## *caData* — PEM/DER CA certificates as bytes (avoids disk I/O on repeat use).
  ## *certFile* — path to PEM client certificate for mutual TLS.
  ## *keyFile* — path to PEM private key for mutual TLS.
  ## *certData* — PEM/DER client certificate as bytes for mutual TLS.
  ## *keyData* — PEM/DER private key as bytes for mutual TLS.
  ## *verify* — require valid server certificate chain (default ``true``).
  ##
  ## CA source precedence: *caData* > *caFile* > *caPath*. Only one is used.
  ## Client cert precedence: *certData* > *certFile*. Only one is used.
  ## Client key precedence: *keyData* > *keyFile*. Only one is used.
  ##
  ## If no CA source is provided and *verify* is ``true``, certificate
  ## verification will fail at handshake.
  ##
  ## In dynamic mode (default), the caller must load the library before calling
  ## this proc: ``discard loadWolfssl()``. Calling without loading raises
  ## ``SoftlinkError``.
  ##
  ## Raises ``WolfSslError`` if any wolfSSL call fails. On failure all
  ## partially-allocated resources are freed automatically via ``=destroy``
  ## on ``result``.

  ensureInit()

  result.sockFd = osInvalidSocket

  # Select method based on TLS version.
  let meth = case version
    of tlsAuto: wolfSSLv23_client_method()
    of tls12: wolfTLSv1_2_client_method()
    of tls13: wolfTLSv1_3_client_method()

  result.ctx = wolfSSL_CTX_new(meth)
  if result.ctx == nil:
    raise newException(WolfSslError, "wolfSSL_CTX_new failed")
  result.state = tsReady  # =destroy now knows there is work to do

  # Floor minimum at TLS 1.2 for tlsAuto to prevent negotiating
  # deprecated TLS 1.0/1.1 (RFC 8996).
  if version == tlsAuto:
    checkRet wolfSSL_CTX_SetMinVersion(result.ctx, WOLFSSL_TLSV1_2)

  # CA certificate loading — fallible operations. If checkRet raises,
  # =destroy cleans up `result`.
  if caData.len > 0:
    checkRet wolfSSL_CTX_load_verify_buffer(result.ctx,
      cast[ptr byte](unsafeAddr caData[0]), clong(caData.len), SSL_FILETYPE_PEM)
  elif caFile.len > 0:
    checkRet wolfSSL_CTX_load_verify_locations(result.ctx,
      caFile.cstring, nil)
  elif caPath.len > 0:
    checkRet wolfSSL_CTX_load_verify_locations(result.ctx,
      nil, caPath.cstring)

  # Client certificate for mutual TLS.
  if certData.len > 0:
    checkRet wolfSSL_CTX_use_certificate_buffer(result.ctx,
      cast[ptr byte](unsafeAddr certData[0]), clong(certData.len), SSL_FILETYPE_PEM)
  elif certFile.len > 0:
    checkRet wolfSSL_CTX_use_certificate_file(result.ctx,
      certFile.cstring, SSL_FILETYPE_PEM)

  # Client private key for mutual TLS.
  if keyData.len > 0:
    checkRet wolfSSL_CTX_use_PrivateKey_buffer(result.ctx,
      cast[ptr byte](unsafeAddr keyData[0]), clong(keyData.len), SSL_FILETYPE_PEM)
  elif keyFile.len > 0:
    checkRet wolfSSL_CTX_use_PrivateKey_file(result.ctx,
      keyFile.cstring, SSL_FILETYPE_PEM)

  if verify:
    wolfSSL_CTX_set_verify(result.ctx, SSL_VERIFY_PEER, nil)
  else:
    wolfSSL_CTX_set_verify(result.ctx, SSL_VERIFY_NONE, nil)

proc connect*(ctx: var TlsContext, hostname: string, port: int,
              alpn: openArray[string] = []) =
  ## TCP connect + TLS handshake with SNI and hostname verification.
  ##
  ## Resolves *hostname* via DNS, iterates all returned addresses
  ## (IPv4 and IPv6) until one connects. Then creates a wolfSSL session,
  ## sets SNI, hostname verification, optional ALPN, and performs the
  ## TLS handshake.
  ##
  ## *alpn* — ALPN protocol list (e.g., ``["h2", "http/1.1"]``). Empty = no ALPN.
  ## Raises ``WolfSslError`` on DNS failure, TCP failure, or TLS failure.
  ## Can only be called once on a freshly-created context.
  ## After a failed connect the context should be closed.
  if ctx.state != tsReady:
    raiseStateError("connect requires a fresh TlsContext (state is " & $ctx.state & ")")
  if hostname.len == 0:
    raiseStateError("connect requires a non-empty hostname")
  if port < 0 or port > 65535:
    raiseStateError("port must be 0..65535, got " & $port)

  # DNS resolution + TCP connect with multi-address fallback.
  # OSError from getAddrInfo is wrapped so callers only need to catch WolfSslError.
  try:
    var aiList = getAddrInfo(hostname, Port(port), AfUnspec, SockStream, IPPROTO_TCP)
    defer: freeAddrInfo(aiList)
    var ai = aiList
    while ai != nil:
      let sock = createNativeSocket(cast[Domain](ai.ai_family), SockStream, IPPROTO_TCP)
      if sock != osInvalidSocket:
        if nativesockets.connect(sock, ai.ai_addr, ai.ai_addrlen.SockLen) == 0.cint:
          ctx.sockFd = sock
          break
        sock.close()
      ai = ai.ai_next
  except OSError as e:
    raise newException(WolfSslError,
      "DNS/TCP connect failed for " & hostname & ":" & $port & ": " & e.msg)
  if ctx.sockFd == osInvalidSocket:
    raise newException(WolfSslError, "TCP connect failed for " & hostname & ":" & $port)

  # Create per-connection wolfSSL session.
  ctx.ssl = wolfSSL_new(ctx.ctx)
  if ctx.ssl == nil:
    ctx.sockFd.close()
    ctx.sockFd = osInvalidSocket
    raise newException(WolfSslError, "wolfSSL_new failed")

  checkRet wolfSSL_set_fd(ctx.ssl, ctx.sockFd.cint)

  # SNI — required for virtual-hosted servers.
  checkRet wolfSSL_UseSNI(ctx.ssl, WOLFSSL_SNI_HOST_NAME,
    cast[pointer](addr hostname[0]), cushort(hostname.len))

  # Hostname verification — ensures the peer certificate CN/SAN matches.
  # Without this, any CA-signed cert would pass verification (MITM).
  checkRet wolfSSL_check_domain_name(ctx.ssl, hostname.cstring)

  # ALPN — Application-Layer Protocol Negotiation (e.g., for HTTP/2).
  if alpn.len > 0:
    # wolfSSL expects a comma-separated protocol list.
    let alpnStr = alpn.join(",")
    checkRet wolfSSL_UseALPN(ctx.ssl, alpnStr.cstring,
      cuint(alpnStr.len), uint8(WOLFSSL_ALPN_FAILED_ON_MISMATCH))

  # TLS handshake with bounded WANT_READ/WANT_WRITE retry.
  const maxHandshakeRetries = 100
  var ret = wolfSSL_connect(ctx.ssl)
  var retries = 0
  while ret != SSL_SUCCESS:
    let err = wolfSSL_get_error(ctx.ssl, ret)
    if err != SSL_ERROR_WANT_READ and err != SSL_ERROR_WANT_WRITE:
      checkRet(ctx.ssl, ret)
    inc retries
    if retries >= maxHandshakeRetries:
      raise newException(WolfSslError, "TLS handshake exceeded " & $maxHandshakeRetries & " retries")
    ret = wolfSSL_connect(ctx.ssl)
  ctx.state = tsConnected

proc writeBuffer(ctx: var TlsContext, data: pointer, dataLen: int) =
  ## Internal: send raw bytes over TLS. Handles partial writes.
  if ctx.state != tsConnected:
    raiseStateError("write requires an active connection (state is " & $ctx.state & ")")
  if dataLen == 0: return
  const maxWantRetries = 100
  var offset = 0
  var wantRetries = 0
  while offset < dataLen:
    let ret = wolfSSL_write(ctx.ssl,
      cast[pointer](cast[uint](data) + uint(offset)), cint(dataLen - offset))
    if ret <= 0:
      let err = wolfSSL_get_error(ctx.ssl, ret)
      if err == SSL_ERROR_WANT_WRITE or err == SSL_ERROR_WANT_READ:
        inc wantRetries
        if wantRetries >= maxWantRetries:
          raise newException(WolfSslError, "write exceeded " & $maxWantRetries & " WANT retries")
        continue
      checkRet(ctx.ssl, ret)
    else:
      offset += ret
      wantRetries = 0  # reset on progress

proc write*(ctx: var TlsContext, data: string) =
  ## Send string *data* over the TLS channel. Handles partial writes internally.
  if data.len > 0:
    ctx.writeBuffer(addr data[0], data.len)

proc write*(ctx: var TlsContext, data: openArray[byte]) =
  ## Send binary *data* over the TLS channel. Handles partial writes internally.
  if data.len > 0:
    ctx.writeBuffer(unsafeAddr data[0], data.len)

proc read*(ctx: var TlsContext, bufSize = 4096, maxSize = 8_388_608): string =
  ## Read from the TLS channel until the peer closes the connection.
  ##
  ## *bufSize* — initial buffer size (doubled as needed), clamped to *maxSize*.
  ## *maxSize* — upper bound on bytes read; raises ``WolfSslError`` if
  ## exceeded. Pass ``int.high`` for unlimited.
  ##
  ## **EOF handling:** Both a clean TLS close_notify (SSL_ERROR_ZERO_RETURN)
  ## and a bare connection close (ret == 0) are treated as EOF. This means
  ## a TLS truncation attack — where an adversary terminates the connection
  ## without sending close_notify — is indistinguishable from a normal close
  ## at this API level. Callers who need truncation detection should use the
  ## low-level bindings (wolfSSL_read + wolfSSL_get_error) directly.
  if ctx.state != tsConnected:
    raiseStateError("read requires an active connection (state is " & $ctx.state & ")")
  let initSize = max(1, min(bufSize, maxSize))
  result = newString(initSize)
  var pos = 0
  while true:
    if pos == result.len:
      # Guard against integer overflow before doubling.
      if result.len > maxSize div 2:
        raise newException(WolfSslError, "read exceeded maxSize of " & $maxSize & " bytes")
      result.setLen(result.len * 2)
    let ret = wolfSSL_read(ctx.ssl,
      cast[pointer](addr result[pos]), cint(result.len - pos))
    if ret <= 0:
      let err = wolfSSL_get_error(ctx.ssl, ret)
      if err == SSL_ERROR_WANT_READ or err == SSL_ERROR_WANT_WRITE:
        continue
      if isEofError(err):
        break  # EOF — clean close, transport closed, or syscall EOF
      checkRet(ctx.ssl, ret)
    else:
      pos += ret
  result.setLen(pos)

proc readInto*(ctx: var TlsContext, buf: var openArray[byte]): int =
  ## Read up to ``buf.len`` bytes from the TLS channel into *buf*.
  ##
  ## Returns the number of bytes read. Returns 0 on EOF (clean close or
  ## transport closed). Raises ``WolfSslError`` on TLS errors.
  ##
  ## This is the low-level streaming read primitive. Use ``read()`` for
  ## convenience when you want to buffer the entire response.
  if ctx.state != tsConnected:
    raiseStateError("readInto requires an active connection (state is " & $ctx.state & ")")
  if buf.len == 0: return 0
  while true:
    let ret = wolfSSL_read(ctx.ssl,
      addr buf[0], cint(buf.len))
    if ret > 0:
      return ret
    let err = wolfSSL_get_error(ctx.ssl, ret)
    if err == SSL_ERROR_WANT_READ or err == SSL_ERROR_WANT_WRITE:
      continue
    if isEofError(err):
      return 0  # EOF
    checkRet(ctx.ssl, ret)

proc peerCertDer*(ctx: TlsContext): seq[byte] =
  ## Return the peer's certificate in DER format after a successful handshake.
  ##
  ## Returns an empty seq if no peer certificate is available (e.g., not
  ## connected, or peer sent no certificate).
  ##
  ## Useful for certificate pinning and expiry monitoring.
  if ctx.state != tsConnected or ctx.ssl == nil:
    return @[]
  let x509 = wolfSSL_get_peer_certificate(ctx.ssl)
  if x509 == nil:
    return @[]
  defer: wolfSSL_X509_free(x509)
  var derLen: cint = 0
  let derPtr = wolfSSL_X509_get_der(x509, addr derLen)
  if derPtr == nil or derLen <= 0:
    return @[]
  result = newSeq[byte](derLen)
  copyMem(addr result[0], derPtr, derLen)

{.pop.}  # raises
