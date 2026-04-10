# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Nim wrapper for wolfSSL 5.x. Two-layer design: low-level FFI bindings (`src/wolfssl/ssl.nim`, `src/wolfssl/loader.nim`) and a high-level convenience API (`src/wolfssl.nim`). Targets embedded Linux (OpenWrt) where wolfSSL is a system package. Modeled on nim-mbedtls (`~/projects/nim-mbedtls`) — copy its architecture, conventions, and patterns.

## Linking Modes

Two compile-time linking modes:

- **Dynamic** (default): uses [softlink](https://github.com/coreyleavitt/softlink) for runtime `dlopen` of `libwolfssl.so`. Call `wolfsslAvailable()` to check. Compile-time type verification via `_Static_assert` catches signature mismatches against headers.
- **Static** (`-d:wolfsslStatic`): links `.a` archives at build time via `-Wl,-Bstatic -lwolfssl -Wl,-Bdynamic`. Requires static libraries at compile time.

Both modes require wolfSSL development headers at compile time. Single library (`libwolfssl`) unlike mbedTLS's three.

## Build & Test

Requires Nim >= 2.0.0, softlink >= 0.3.1, and wolfSSL 5.x development headers. Use the `nim-wolfssl-dev` Docker image for compilation:

```bash
# Build via container (dynamic mode, default)
docker run --rm -v "$PWD://work" -w //work nim-wolfssl-dev nim c --path:src src/wolfssl.nim

# Build with static linking
docker run --rm -v "$PWD://work" -w //work nim-wolfssl-dev nim c -d:wolfsslStatic --path:src src/wolfssl.nim

# Tier 1 tests (no network)
docker run --rm -v "$PWD://work" -w //work nim-wolfssl-dev nim c -r --path:src tests/t_bindings.nim

# Tier 2 integration tests (network required)
docker run --rm -v "$PWD://work" -w //work nim-wolfssl-dev nim c -r --path:src tests/t_tls_client.nim

# Nimble tasks
nimble test              # tier 1 (binding validation)
nimble test_integration  # tier 2 (real TLS connections)
```

Docker dev image (Ubuntu with Nim via choosenim + wolfSSL from source):
```bash
docker build -t nim-wolfssl-dev -f - . <<'EOF'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y gcc ca-certificates curl git autoconf automake libtool make xz-utils
RUN curl https://nim-lang.org/choosenim/init.sh -sSf | sh -s -- -y
ENV PATH="/root/.nimble/bin:${PATH}"
RUN git clone --depth 1 --branch v5.7.6-stable https://github.com/wolfSSL/wolfssl.git /tmp/wolfssl && \
    cd /tmp/wolfssl && ./autogen.sh && \
    ./configure --enable-sni --enable-opensslextra --enable-alpn --enable-static --prefix=/usr && \
    make -j$(nproc) && make install && ldconfig && rm -rf /tmp/wolfssl
WORKDIR /work
EOF
```

wolfSSL must be built with `--enable-sni --enable-opensslextra --enable-alpn` for the full feature set (SNI, X509 peer cert inspection, ALPN negotiation).

Install wolfSSL headers natively: `opkg install libwolfssl-dev` (OpenWrt).

## Architecture

- `src/wolfssl.nim` — High-level `TlsContext` API: `newTlsContext`, `connect`, `read`, `readInto`, `write` (string and openArray[byte]), `close`, `peerCertDer`, `negotiatedAlpn`. Supports mTLS via `certFile`/`keyFile`/`certData`/`keyData` params. Owns `WolfsslCtx`, `Wolfssl`, and a socket fd (via `std/nativesockets`). Uses `=destroy` for cleanup. In dynamic mode, exposes `loadWolfssl()` / `wolfsslAvailable()`.
- `src/wolfssl/ssl.nim` — Opaque type definitions (`WolfsslCtx`, `Wolfssl`, `WolfsslMethod`) and constants. In static mode (`-d:wolfsslStatic`), also contains `importc` proc bindings.
- `src/wolfssl/loader.nim` — Single softlink `dynlib` block for runtime loading (dynamic mode only). One block for `libwolfssl.so` — simpler than mbedTLS's three-loader pattern.
- `tests/t_bindings.nim` — Tier 1: init/free round-trips, library loading, state enforcement (offline).
- `tests/t_tls_client.nim` — Tier 2: real HTTPS connections (network required).

## Key Differences from nim-mbedtls

- **Single library** — one `dynlib` block, one `loadWolfssl()` call (no multi-library orchestration).
- **Socket FD model** — wolfSSL uses `set_fd()` with POSIX sockets, not callback function pointers. No `cbPtr` macro needed.
- **Global init** — `wolfSSL_Init()` must be called once before any other wolfSSL function; `wolfSSL_Cleanup()` at shutdown.
- **Two-step error handling** — `wolfSSL_get_error(ssl, ret)` returns error code, then `wolfSSL_ERR_error_string()` converts to string (vs mbedTLS's one-step `mbedtls_strerror`).
- **TCP is manual** — use `std/posix` or `std/nativesockets` for `socket()` + `connect()` since wolfSSL has no `net_connect()` helper.
- **Context creation** — `wolfSSL_CTX_new(method)` is a single call (vs mbedTLS's allocate + init + configure).

## FFI Conventions

- Opaque C structs use `{.importc, header: "<wolfssl/ssl.h>", incompleteStruct.}` — always passed by `ptr`, never copied. Type definitions are always present regardless of linking mode.
- All FFI functions come from a single header: `<wolfssl/ssl.h>`.
- **`options.h` must be included before `ssl.h`** — wolfSSL requires `<wolfssl/options.h>` first to enable compile-time feature flags (TLS 1.3, SNI, etc.). Without it, functions like `wolfTLSv1_3_client_method` are not declared. Both `ssl.nim` and `loader.nim` use `{.emit: """/*INCLUDESECTION*/\n#include <wolfssl/options.h>\n""".}` to ensure correct include order. Any new file that imports wolfSSL headers needs this emit.
- No callback types needed — wolfSSL uses `set_fd()` for I/O, not function pointer callbacks.
- Static mode: `{.passL: "-Wl,-Bstatic -lwolfssl -Wl,-Bdynamic".}` in `ssl.nim`.
- Dynamic mode: no `passL` — library loaded at runtime by `loader.nim`. Softlink dynlib procs use `{.cdecl.}`.

## Ownership & Safety (high-level API)

`TlsContext` is a move-only value type (same Nim 2.x idiom as nim-mbedtls):
- **`=copy` disabled** — prevents aliased pointers / double-free. Use `move` to transfer.
- **`=destroy`** nil-checks each `ptr` field, closes socket fd, calls free in reverse allocation order. Does NOT send close_notify — no network I/O in destructors.
- **`close`** sends unidirectional close_notify (best-effort, max 3 WANT retries), then calls `=destroy` + `wasMoved`. Use `close()` for clean TLS shutdown; objects falling out of scope get fast resource-only cleanup.
- **State machine** (`tsClosed` -> `tsReady` -> `tsConnected`) enforced by raising `WolfSslError`.
- **Exception-safe init** — if `checkRet` raises during setup, `=destroy` on `result` cleans up partial allocations.
- **3 heap objects** (`WolfsslCtx`, `Wolfssl`, socket fd) vs mbedTLS's 6.

Do not regress these invariants when modifying the high-level API.

## Adding New Bindings

Add the type definition unconditionally in `src/wolfssl/ssl.nim`. Wrap static-mode proc declarations in `when defined(wolfsslStatic)`. Add corresponding softlink declarations to the `dynlib` block in `src/wolfssl/loader.nim` with `{.cdecl, header: "<wolfssl/ssl.h>".}`. Add a Tier 1 test (init/free at minimum) in `tests/t_bindings.nim`.
