# nim-wolfssl Implementation Plan

Nim wrapper for wolfSSL 5.x. Modeled on nim-mbedtls, incorporating all lessons learned from being the first library to adopt [softlink](https://github.com/coreyleavitt/softlink).

## Reference Implementation

nim-mbedtls (`~/projects/nim-mbedtls`) is the template. Copy its architecture, conventions, and patterns — this plan documents only the wolfSSL-specific differences and the full file layout.

## Key Differences from mbedTLS

| Aspect | mbedTLS | wolfSSL |
|--------|---------|---------|
| Library count | 3 (`libmbedcrypto`, `libmbedx509`, `libmbedtls`) | 1 (`libwolfssl`) |
| I/O model | Callback-only (`set_bio`) | Socket FD (`set_fd`) — simpler |
| Error handling | Negative return codes | `wolfSSL_get_error(ssl, ret)` pattern |
| Init/cleanup | Per-context `_init`/`_free` | Global `wolfSSL_Init()`/`wolfSSL_Cleanup()` |
| Context creation | Allocate + init + configure | `wolfSSL_CTX_new(method)` — one call |
| Struct opacity | `incompleteStruct` in Nim | Same — all opaque, pointer-only |
| Header layout | Many headers (`ssl.h`, `entropy.h`, etc.) | Single primary header (`wolfssl/ssl.h`) |
| Protocol selection | Config struct fields | Method functions (`wolfTLSv1_2_client_method()`, etc.) |
| SNI | `mbedtls_ssl_set_hostname()` | `wolfSSL_UseSNI()` |

## Architecture

### Two-layer design (same as nim-mbedtls)

- `src/wolfssl.nim` — High-level `TlsContext` API
- `src/wolfssl/ssl.nim` — Types, constants, and static-mode `importc` procs
- `src/wolfssl/loader.nim` — Softlink `dynlib` block (dynamic mode)

### Single library = single dynlib block

wolfSSL ships everything in one `.so` — no multi-library orchestration needed. This eliminates the `loadMbedTlsLibs()` / three-loader pattern.

```nim
# loader.nim — just one block
dynlib "libwolfssl.so(.42|.41|.35|)":
  proc wolfSSL_Init(): cint {.cdecl, header: "<wolfssl/ssl.h>".}
  # ... all functions
```

Generated helpers: `loadWolfssl()`, `wolfsslLoaded()`, `unloadWolfssl()`.

## File Layout

```
nim-wolfssl/
  wolfssl.nimble
  CLAUDE.md
  src/
    wolfssl.nim              # High-level TlsContext API
    wolfssl/
      ssl.nim                # Types, constants, static-mode importc procs
      loader.nim             # Softlink dynlib block (dynamic mode)
  tests/
    t_bindings.nim           # Tier 1: init/free round-trips, offline
    t_tls_client.nim         # Tier 2: real HTTPS connections
```

## Types and Constants (`src/wolfssl/ssl.nim`)

### Opaque types (always present, both modes)

```nim
type
  WolfsslCtx* {.importc: "WOLFSSL_CTX", header: "<wolfssl/ssl.h>", incompleteStruct.} = object
  Wolfssl* {.importc: "WOLFSSL", header: "<wolfssl/ssl.h>", incompleteStruct.} = object
  WolfsslMethod* {.importc: "WOLFSSL_METHOD", header: "<wolfssl/ssl.h>", incompleteStruct.} = object
```

### Constants

```nim
const
  SSL_SUCCESS* = 1
  SSL_FAILURE* = 0
  SSL_FILETYPE_PEM* = 1
  SSL_FILETYPE_ASN1* = 2  # DER
  SSL_ERROR_NONE* = 0
  SSL_ERROR_WANT_READ* = 2
  SSL_ERROR_WANT_WRITE* = 3
  SSL_VERIFY_NONE* = 0
  SSL_VERIFY_PEER* = 1
  SSL_VERIFY_FAIL_IF_NO_PEER_CERT* = 2
```

### Static-mode procs (behind `when defined(wolfsslStatic)`)

```nim
when defined(wolfsslStatic):
  {.passL: "-Wl,-Bstatic -lwolfssl -Wl,-Bdynamic".}

  # Init/cleanup
  proc wolfSSL_Init*(): cint {.importc, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_Cleanup*(): cint {.importc, header: "<wolfssl/ssl.h>".}

  # Method selection
  proc wolfTLSv1_2_client_method*(): ptr WolfsslMethod {.importc, header: "<wolfssl/ssl.h>".}
  proc wolfTLSv1_3_client_method*(): ptr WolfsslMethod {.importc, header: "<wolfssl/ssl.h>".}
  proc wolfSSLv23_client_method*(): ptr WolfsslMethod {.importc, header: "<wolfssl/ssl.h>".}

  # Context
  proc wolfSSL_CTX_new*(meth: ptr WolfsslMethod): ptr WolfsslCtx {.importc, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_CTX_free*(ctx: ptr WolfsslCtx) {.importc, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_CTX_load_verify_locations*(ctx: ptr WolfsslCtx, file, path: cstring): cint {.importc, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_CTX_set_verify*(ctx: ptr WolfsslCtx, mode: cint, cb: pointer) {.importc, header: "<wolfssl/ssl.h>".}

  # Session
  proc wolfSSL_new*(ctx: ptr WolfsslCtx): ptr Wolfssl {.importc, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_free*(ssl: ptr Wolfssl) {.importc, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_set_fd*(ssl: ptr Wolfssl, fd: cint): cint {.importc, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_connect*(ssl: ptr Wolfssl): cint {.importc, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_shutdown*(ssl: ptr Wolfssl): cint {.importc, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_write*(ssl: ptr Wolfssl, data: pointer, sz: cint): cint {.importc, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_read*(ssl: ptr Wolfssl, data: pointer, sz: cint): cint {.importc, header: "<wolfssl/ssl.h>".}

  # SNI
  proc wolfSSL_UseSNI*(ssl: ptr Wolfssl, typ: cint, data: pointer, size: cushort): cint {.importc, header: "<wolfssl/ssl.h>".}

  # Error
  proc wolfSSL_get_error*(ssl: ptr Wolfssl, ret: cint): cint {.importc, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_ERR_error_string*(err: culong, buf: cstring): cstring {.importc, header: "<wolfssl/ssl.h>".}
```

## Softlink Loader (`src/wolfssl/loader.nim`)

Single `dynlib` block. All angle-bracket headers for full dyntype verification.

No callback types needed — wolfSSL uses `set_fd()` for I/O, not callback function pointers. The `cbPtr` macro from nim-mbedtls is not needed here.

```nim
import softlink
import wolfssl/ssl

export softlink

dynlib "libwolfssl.so(.42|.41|.40|.39|.38|.37|.36|.35|)":
  # Init/cleanup
  proc wolfSSL_Init(): cint {.cdecl, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_Cleanup(): cint {.cdecl, header: "<wolfssl/ssl.h>".}

  # Method selection
  proc wolfTLSv1_2_client_method(): ptr WolfsslMethod {.cdecl, header: "<wolfssl/ssl.h>".}
  proc wolfTLSv1_3_client_method(): ptr WolfsslMethod {.cdecl, header: "<wolfssl/ssl.h>".}
  proc wolfSSLv23_client_method(): ptr WolfsslMethod {.cdecl, header: "<wolfssl/ssl.h>".}

  # Context
  proc wolfSSL_CTX_new(meth: ptr WolfsslMethod): ptr WolfsslCtx {.cdecl, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_CTX_free(ctx: ptr WolfsslCtx) {.cdecl, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_CTX_load_verify_locations(ctx: ptr WolfsslCtx, file, path: cstring): cint {.cdecl, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_CTX_set_verify(ctx: ptr WolfsslCtx, mode: cint, cb: pointer) {.cdecl, header: "<wolfssl/ssl.h>".}

  # Session
  proc wolfSSL_new(ctx: ptr WolfsslCtx): ptr Wolfssl {.cdecl, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_free(ssl: ptr Wolfssl) {.cdecl, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_set_fd(ssl: ptr Wolfssl, fd: cint): cint {.cdecl, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_connect(ssl: ptr Wolfssl): cint {.cdecl, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_shutdown(ssl: ptr Wolfssl): cint {.cdecl, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_write(ssl: ptr Wolfssl, data: pointer, sz: cint): cint {.cdecl, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_read(ssl: ptr Wolfssl, data: pointer, sz: cint): cint {.cdecl, header: "<wolfssl/ssl.h>".}

  # SNI
  proc wolfSSL_UseSNI(ssl: ptr Wolfssl, typ: cint, data: pointer, size: cushort): cint {.cdecl, header: "<wolfssl/ssl.h>".}

  # Error
  proc wolfSSL_get_error(ssl: ptr Wolfssl, ret: cint): cint {.cdecl, header: "<wolfssl/ssl.h>".}
  proc wolfSSL_ERR_error_string(err: culong, buf: cstring): cstring {.cdecl, header: "<wolfssl/ssl.h>".}

proc wolfsslAvailable*(): bool = wolfsslLoaded()
```

## High-Level API (`src/wolfssl.nim`)

### Design differences from nim-mbedtls

1. **Simpler resource ownership** — only 3 heap objects (`WolfsslCtx`, `Wolfssl`, socket fd) vs mbedTLS's 6
2. **Socket FD model** — wolfSSL manages its own TCP socket via `set_fd()`. We use `posix.socket()` + `posix.connect()` to create the socket, then hand the fd to wolfSSL. No callback function pointers needed.
3. **Global init** — `wolfSSL_Init()` must be called once before anything. Use a module-level `var initialized = false` flag.
4. **Error handling** — `wolfSSL_get_error(ssl, ret)` returns an error code, then `wolfSSL_ERR_error_string()` converts it. Two-step vs mbedTLS's one-step `mbedtls_strerror(ret)`.

### TlsContext structure

```nim
type
  TlsContext* = object
    state: TlsState
    ctx: ptr WolfsslCtx
    ssl: ptr Wolfssl
    sockFd: cint  # POSIX socket file descriptor, -1 when unset
```

### Key API functions

```nim
proc newTlsContext*(caFile = "", caPath = "", verify = true): TlsContext
  ## Creates WolfsslCtx with wolfSSLv23_client_method().
  ## Loads CA certs. Does NOT create Wolfssl object yet (that's per-connection).

proc connect*(ctx: var TlsContext, hostname: string, port: int)
  ## 1. POSIX socket() + connect() to establish TCP
  ## 2. wolfSSL_new(ctx.ctx) to create session
  ## 3. wolfSSL_set_fd(ctx.ssl, sockFd)
  ## 4. wolfSSL_UseSNI() for hostname verification
  ## 5. wolfSSL_connect() for TLS handshake

proc write*(ctx: var TlsContext, data: string)
  ## wolfSSL_write() with WANT_READ/WANT_WRITE retry

proc read*(ctx: var TlsContext, bufSize = 4096, maxSize = 8_388_608): string
  ## wolfSSL_read() with buffer growth, same pattern as nim-mbedtls

proc close*(ctx: var TlsContext)
  ## wolfSSL_shutdown() + close(sockFd) + wolfSSL_free() + wolfSSL_CTX_free()
```

### TCP socket handling

Unlike mbedTLS (which has `mbedtls_net_connect()`), wolfSSL doesn't provide TCP helpers. We need POSIX socket calls:

```nim
import std/posix  # or std/nativesockets

# In connect():
let sockFd = socket(AF_INET, SOCK_STREAM, 0)
# getaddrinfo() for DNS resolution
# posix.connect(sockFd, ...) for TCP connection
wolfSSL_set_fd(ctx.ssl, sockFd)
```

Use `std/nativesockets` or `std/net` for cross-platform socket creation, or raw POSIX for embedded Linux. Given the OpenWrt target, POSIX is fine.

### Ownership and lifecycle

Same patterns as nim-mbedtls:
- `=copy` disabled (move-only)
- `=destroy` nil-checks each pointer, calls free in reverse order
- `close` = `=destroy` + `wasMoved`
- State machine: `tsClosed` -> `tsReady` -> `tsConnected`
- Exception-safe init with `checkRet`

### Error translation

```nim
proc checkRet(ssl: ptr Wolfssl, ret: cint) {.inline.} =
  ## wolfSSL pattern: check ret, then call get_error for the code.
  if ret != SSL_SUCCESS and ret <= 0:
    let errCode = wolfSSL_get_error(ssl, ret)
    if errCode == SSL_ERROR_WANT_READ or errCode == SSL_ERROR_WANT_WRITE:
      return  # caller handles retry
    var buf: array[80, char]
    discard wolfSSL_ERR_error_string(culong(errCode), cast[cstring](addr buf[0]))
    let err = newException(WolfSslError, $cast[cstring](addr buf[0]))
    err.code = errCode
    raise err
```

## Softlink Patterns (lessons from nim-mbedtls)

### What carries over directly
- `when defined(wolfsslStatic)` dual-mode compilation
- `{.push raises: [WolfSslError, SoftlinkError].}` / `{.push raises: [WolfSslError].}`
- Angle-bracket headers for dyntype verification
- `wolfsslAvailable()` check before use
- Conditional `checkRet` with different `{.raises.}` per mode

### What's simpler
- **One dynlib block** instead of three — single `loadWolfssl()` call
- **No callback types / `cbPtr` macro** — wolfSSL uses `set_fd()`, not function pointer callbacks
- **No `xxxPtr()` usage** — no callbacks to pass as raw pointers

### What's different
- **Global init** — `wolfSSL_Init()` must be called once. Handle in `loadWolfsslLib()` wrapper or document as caller responsibility.
- **POSIX dependency** — need `import std/posix` or `std/nativesockets` for TCP socket creation

## Docker Build Environment

```bash
docker build -t nim-wolfssl-dev -f - . <<'EOF'
FROM opensuse/tumbleweed
RUN zypper --non-interactive install nim wolfssl-devel gcc ca-certificates-mozilla
WORKDIR /work
EOF
```

Check if `wolfssl-devel` is available on Tumbleweed. If not, build from source:
```bash
RUN zypper --non-interactive install nim gcc ca-certificates-mozilla git cmake make && \
    git clone --depth 1 https://github.com/wolfSSL/wolfssl.git /tmp/wolfssl && \
    cd /tmp/wolfssl && ./autogen.sh && ./configure --enable-sni && make && make install && \
    ldconfig
```

## Test Plan

### Tier 1 (`t_bindings.nim`) — offline, no network
- Library loading (dynamic mode)
- `wolfSSL_Init()` / `wolfSSL_Cleanup()` round-trip
- Context creation and free (`wolfSSL_CTX_new` / `wolfSSL_CTX_free`)
- Session creation and free (`wolfSSL_new` / `wolfSSL_free`)
- Error string conversion
- High-level API lifecycle (create, close, move, state enforcement)

### Tier 2 (`t_tls_client.nim`) — requires network
- HTTPS GET with CA verification
- Destructor cleanup of connected context
- Connection failure handling
- Verification failure without CA certs

## Nimble File

```nim
version       = "0.1.0"
author        = "Corey Leavitt"
description   = "Nim wrapper for wolfSSL 5.x"
license       = "Apache-2.0"
srcDir        = "src"

requires "nim >= 2.0.0"
requires "https://github.com/coreyleavitt/softlink >= 0.3.1"

task test, "Run binding validation tests (Tier 1, no network)":
  exec "nim c -r --path:src tests/t_bindings.nim"

task test_integration, "Run integration tests (Tier 2, requires network)":
  exec "nim c -r --path:src tests/t_tls_client.nim"
```

## Implementation Order

1. Scaffold: nimble, CLAUDE.md, directory structure
2. `src/wolfssl/ssl.nim` — types, constants, static-mode procs
3. `src/wolfssl/loader.nim` — softlink dynlib block
4. `tests/t_bindings.nim` — tier 1 (verify init/free, loading)
5. `src/wolfssl.nim` — high-level API with TCP socket handling
6. `tests/t_tls_client.nim` — tier 2 (real connections)
7. Verify both `-d:wolfsslStatic` and dynamic modes
