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
## ``std/once`` and is safe under concurrent ``newTlsContext`` calls.

import std/[nativesockets, once]
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
    tsClosed      ## Zero value — nothing allocated or already freed
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

var initOnce: Once

proc ensureInit() =
  initOnce.once:
    if wolfSSL_Init() != SSL_SUCCESS:
      raise newException(WolfSslError, "wolfSSL_Init failed")

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

proc `=copy`*(dst: var TlsContext, src: TlsContext) {.error:
  "TlsContext cannot be copied; use 'move' to transfer ownership".}

# -- Error translation ------------------------------------------------------

when not defined(wolfsslStatic):
  proc checkRet(ret: cint) {.inline, raises: [WolfSslError, SoftlinkError].} =
    ## Translate a non-success wolfSSL return code into an exception.
    ## For global/CTX-level calls where no ssl session exists.
    if ret != SSL_SUCCESS:
      let err = newException(WolfSslError, "wolfSSL error: " & $ret)
      err.code = ret
      raise err

  proc checkRet(ssl: ptr Wolfssl, ret: cint) {.inline, raises: [WolfSslError, SoftlinkError].} =
    ## Translate a wolfSSL session-level error into an exception.
    ## Uses wolfSSL_get_error + wolfSSL_ERR_error_string for detail.
    if ret != SSL_SUCCESS and ret <= 0:
      let errCode = wolfSSL_get_error(ssl, ret)
      var buf: array[256, char]
      discard wolfSSL_ERR_error_string(culong(errCode), cast[cstring](addr buf[0]))
      let err = newException(WolfSslError, $cast[cstring](addr buf[0]))
      err.code = errCode
      raise err
else:
  proc checkRet(ret: cint) {.inline, raises: [WolfSslError].} =
    if ret != SSL_SUCCESS:
      let err = newException(WolfSslError, "wolfSSL error: " & $ret)
      err.code = ret
      raise err

  proc checkRet(ssl: ptr Wolfssl, ret: cint) {.inline, raises: [WolfSslError].} =
    if ret != SSL_SUCCESS and ret <= 0:
      let errCode = wolfSSL_get_error(ssl, ret)
      var buf: array[256, char]
      discard wolfSSL_ERR_error_string(culong(errCode), cast[cstring](addr buf[0]))
      let err = newException(WolfSslError, $cast[cstring](addr buf[0]))
      err.code = errCode
      raise err

proc raiseStateError(msg: string) {.noinline, noreturn, raises: [WolfSslError].} =
  ## Raise WolfSslError for state machine violations. Unlike doAssert,
  ## this is never compiled out — misuse is always caught, even with -d:danger.
  raise newException(WolfSslError, msg)

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
                    caData = "", verify = true): TlsContext =
  ## Create a TLS client context.
  ##
  ## *version* — TLS version selection (default negotiates highest).
  ## *caFile* — path to a PEM CA certificate file.
  ## *caPath* — path to a directory of PEM CA certificates.
  ## *caData* — PEM CA certificates as a string (avoids disk I/O on repeat use).
  ## *verify* — require valid server certificate chain (default ``true``).
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

  # CA certificate loading — fallible operations. If checkRet raises,
  # =destroy cleans up `result`.
  if caData.len > 0:
    checkRet wolfSSL_CTX_load_verify_buffer(result.ctx,
      cast[ptr byte](addr caData[0]), clong(caData.len), SSL_FILETYPE_PEM)
  elif caFile.len > 0:
    checkRet wolfSSL_CTX_load_verify_locations(result.ctx,
      caFile.cstring, nil)
  elif caPath.len > 0:
    checkRet wolfSSL_CTX_load_verify_locations(result.ctx,
      nil, caPath.cstring)

  if verify:
    wolfSSL_CTX_set_verify(result.ctx, SSL_VERIFY_PEER, nil)
  else:
    wolfSSL_CTX_set_verify(result.ctx, SSL_VERIFY_NONE, nil)

proc connect*(ctx: var TlsContext, hostname: string, port: int) =
  ## TCP connect + TLS handshake with SNI.
  ##
  ## Resolves *hostname* via DNS, iterates all returned addresses
  ## (IPv4 and IPv6) until one connects. Then creates a wolfSSL session,
  ## sets SNI, and performs the TLS handshake.
  ##
  ## Can only be called once on a freshly-created context.
  ## After a failed connect the context should be closed.
  if ctx.state != tsReady:
    raiseStateError("connect requires a fresh TlsContext (state is " & $ctx.state & ")")

  # DNS resolution + TCP connect with multi-address fallback.
  var aiList = getAddrInfo(hostname, Port(port), AfUnspec, SockStream, ProtoTcp)
  defer: freeAddrInfo(aiList)
  var ai = aiList
  while ai != nil:
    let sock = createNativeSocket(ai.ai_family.Domain, SockStream, ProtoTcp)
    if sock != osInvalidSocket:
      if nativesockets.connect(sock, ai.ai_addr, ai.ai_addrlen.SockLen) == 0.cint:
        ctx.sockFd = sock
        break
      sock.close()
    ai = ai.ai_next
  if ctx.sockFd == osInvalidSocket:
    raise newException(WolfSslError, "TCP connect failed for " & hostname & ":" & $port)

  # Create per-connection wolfSSL session.
  ctx.ssl = wolfSSL_new(ctx.ctx)
  if ctx.ssl == nil:
    ctx.sockFd.close()
    ctx.sockFd = osInvalidSocket
    raise newException(WolfSslError, "wolfSSL_new failed")

  checkRet wolfSSL_set_fd(ctx.ssl, ctx.sockFd.cint)

  # SNI — required for virtual-hosted servers and certificate matching.
  let hostnameLen = hostname.len
  checkRet wolfSSL_UseSNI(ctx.ssl, WOLFSSL_SNI_HOST_NAME,
    cast[pointer](addr hostname[0]), cushort(hostnameLen))

  # TLS handshake with WANT_READ/WANT_WRITE retry.
  var ret = wolfSSL_connect(ctx.ssl)
  while ret != SSL_SUCCESS:
    let err = wolfSSL_get_error(ctx.ssl, ret)
    if err != SSL_ERROR_WANT_READ and err != SSL_ERROR_WANT_WRITE:
      checkRet(ctx.ssl, ret)
    ret = wolfSSL_connect(ctx.ssl)
  ctx.state = tsConnected

proc write*(ctx: var TlsContext, data: string) =
  ## Send *data* over the TLS channel. Handles partial writes internally.
  if ctx.state != tsConnected:
    raiseStateError("write requires an active connection (state is " & $ctx.state & ")")
  if data.len == 0: return
  var offset = 0
  while offset < data.len:
    let ret = wolfSSL_write(ctx.ssl,
      cast[pointer](addr data[offset]), cint(data.len - offset))
    if ret <= 0:
      let err = wolfSSL_get_error(ctx.ssl, ret)
      if err == SSL_ERROR_WANT_WRITE or err == SSL_ERROR_WANT_READ:
        continue
      checkRet(ctx.ssl, ret)
    else:
      offset += ret

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
      let newLen = result.len * 2
      if newLen > maxSize:
        raise newException(WolfSslError, "read exceeded maxSize of " & $maxSize & " bytes")
      result.setLen(newLen)
    let ret = wolfSSL_read(ctx.ssl,
      cast[pointer](addr result[pos]), cint(result.len - pos))
    if ret <= 0:
      let err = wolfSSL_get_error(ctx.ssl, ret)
      if err == SSL_ERROR_WANT_READ or err == SSL_ERROR_WANT_WRITE:
        continue
      if err == SSL_ERROR_ZERO_RETURN or ret == 0:
        break  # EOF — clean close or truncation (see docstring)
      checkRet(ctx.ssl, ret)
    else:
      pos += ret
  result.setLen(pos)

{.pop.}  # raises
