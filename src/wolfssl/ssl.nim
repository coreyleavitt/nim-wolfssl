## Low-level bindings for wolfSSL functions.
## Single header: <wolfssl/ssl.h> for all types, constants, and procs.
##
## wolfSSL requires <wolfssl/options.h> before <wolfssl/ssl.h> to enable
## compile-time feature flags (TLS 1.3, SNI, etc.). The emit below ensures
## correct include order in all generated C files.

{.emit: """/*INCLUDESECTION*/
#include <wolfssl/options.h>
""".}

when defined(wolfsslStatic):
  {.passL: "-Wl,-Bstatic -lwolfssl -Wl,-Bdynamic".}

# Opaque types — always present regardless of linking mode.
type
  WolfsslCtx* {.importc: "WOLFSSL_CTX", header: "<wolfssl/ssl.h>", incompleteStruct.} = object
  Wolfssl* {.importc: "WOLFSSL", header: "<wolfssl/ssl.h>", incompleteStruct.} = object
  WolfsslMethod* {.importc: "WOLFSSL_METHOD", header: "<wolfssl/ssl.h>", incompleteStruct.} = object


const
  SSL_SUCCESS* = 1
  SSL_FAILURE* = 0
  SSL_FILETYPE_PEM* = 1
  SSL_FILETYPE_ASN1* = 2  ## DER format
  SSL_ERROR_NONE* = 0
  SSL_ERROR_WANT_READ* = 2
  SSL_ERROR_WANT_WRITE* = 3
  SSL_ERROR_ZERO_RETURN* = 6
  SSL_VERIFY_NONE* = 0
  SSL_VERIFY_PEER* = 1
  SSL_VERIFY_FAIL_IF_NO_PEER_CERT* = 2
  WOLFSSL_SNI_HOST_NAME* = 0

when defined(wolfsslStatic):
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
  proc wolfSSL_CTX_load_verify_buffer*(ctx: ptr WolfsslCtx, buf: ptr byte, sz: clong, format: cint): cint {.importc, header: "<wolfssl/ssl.h>".}
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
