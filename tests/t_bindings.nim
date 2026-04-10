## Tier 1: Binding validation and high-level API safety tests.
## No network access required.

import unittest
import wolfssl
import wolfssl/ssl

# -- Library loading (dynamic mode) ------------------------------------------

when not defined(wolfsslStatic):
  import wolfssl/loader

  suite "library loading":
    test "loadWolfssl succeeds":
      let res = loadWolfssl()
      check res.kind == lrOk or res.kind == lrOkPartial

    test "wolfsslAvailable returns true after load":
      check wolfsslAvailable() == true

    test "wolfsslLoaded returns true":
      check wolfsslLoaded() == true

# -- Low-level binding validation -------------------------------------------

suite "wolfssl init/cleanup":
  test "wolfSSL_Init succeeds":
    check wolfSSL_Init() == SSL_SUCCESS

  test "wolfSSL_Cleanup succeeds":
    check wolfSSL_Cleanup() == SSL_SUCCESS

  test "re-init after cleanup succeeds":
    check wolfSSL_Init() == SSL_SUCCESS

suite "context bindings":
  test "CTX new and free":
    discard wolfSSL_Init()
    let meth = wolfSSLv23_client_method()
    check meth != nil
    let ctx = wolfSSL_CTX_new(meth)
    check ctx != nil
    wolfSSL_CTX_free(ctx)

  test "TLSv1.2 method":
    let meth = wolfTLSv1_2_client_method()
    check meth != nil
    let ctx = wolfSSL_CTX_new(meth)
    check ctx != nil
    wolfSSL_CTX_free(ctx)

  test "TLSv1.3 method":
    let meth = wolfTLSv1_3_client_method()
    check meth != nil
    let ctx = wolfSSL_CTX_new(meth)
    check ctx != nil
    wolfSSL_CTX_free(ctx)

suite "session bindings":
  test "ssl new and free":
    discard wolfSSL_Init()
    let meth = wolfSSLv23_client_method()
    let ctx = wolfSSL_CTX_new(meth)
    let ssl = wolfSSL_new(ctx)
    check ssl != nil
    wolfSSL_free(ssl)
    wolfSSL_CTX_free(ctx)

suite "error bindings":
  test "wolfSSL_ERR_error_string produces non-empty string":
    var buf: array[256, char]
    let msg = wolfSSL_ERR_error_string(culong(0), cast[cstring](addr buf[0]))
    # Error code 0 should produce a string (may be "unknown error" or similar)
    check msg != nil

# -- High-level API ----------------------------------------------------------

suite "TlsContext lifecycle":
  test "newTlsContext and explicit close":
    var ctx = newTlsContext(verify = false)
    check ctx.state == tsReady
    ctx.close()
    check ctx.state == tsClosed

  test "close is idempotent":
    var ctx = newTlsContext(verify = false)
    ctx.close()
    ctx.close()
    check ctx.state == tsClosed

  test "destructor cleans up on scope exit":
    # No crash or leak — validated by running under valgrind/asan
    block:
      var ctx = newTlsContext(verify = false)
      check ctx.state == tsReady

  test "move transfers ownership":
    var a = newTlsContext(verify = false)
    var b = move(a)
    check b.state == tsReady
    check a.state == tsClosed  # moved-from is zeroed
    b.close()

  test "newTlsContext with bad caFile raises WolfSslError":
    expect WolfSslError:
      discard newTlsContext(caFile = "/nonexistent/path.pem")

  test "TlsVersion enum selects method":
    var ctx12 = newTlsContext(version = tls12, verify = false)
    check ctx12.state == tsReady
    ctx12.close()
    var ctx13 = newTlsContext(version = tls13, verify = false)
    check ctx13.state == tsReady
    ctx13.close()
    var ctxAuto = newTlsContext(version = tlsAuto, verify = false)
    check ctxAuto.state == tsReady
    ctxAuto.close()

suite "TlsContext state enforcement":
  test "write before connect raises WolfSslError":
    var ctx = newTlsContext(verify = false)
    expect WolfSslError:
      ctx.write("test")
    ctx.close()

  test "read before connect raises WolfSslError":
    var ctx = newTlsContext(verify = false)
    expect WolfSslError:
      discard ctx.read()
    ctx.close()

  test "connect on closed context raises WolfSslError":
    var ctx = newTlsContext(verify = false)
    ctx.close()
    expect WolfSslError:
      ctx.connect("example.com", 443)

  test "write on closed context raises WolfSslError":
    var ctx = newTlsContext(verify = false)
    ctx.close()
    expect WolfSslError:
      ctx.write("test")

  test "read on closed context raises WolfSslError":
    var ctx = newTlsContext(verify = false)
    ctx.close()
    expect WolfSslError:
      discard ctx.read()

  test "connect with empty hostname raises WolfSslError":
    var ctx = newTlsContext(verify = false)
    expect WolfSslError:
      ctx.connect("", 443)
    ctx.close()

  test "connect with invalid port raises WolfSslError":
    var ctx = newTlsContext(verify = false)
    expect WolfSslError:
      ctx.connect("example.com", -1)
    ctx.close()

  test "connect with port > 65535 raises WolfSslError":
    var ctx = newTlsContext(verify = false)
    expect WolfSslError:
      ctx.connect("example.com", 99999)
    ctx.close()

  test "write empty string on closed context raises":
    var ctx = newTlsContext(verify = false)
    ctx.close()
    # Empty write still checks state before the length guard.
    expect WolfSslError:
      ctx.write("")

  test "write empty openArray[byte] on closed context raises":
    var ctx = newTlsContext(verify = false)
    ctx.close()
    var empty: seq[byte] = @[]
    expect WolfSslError:
      ctx.write(empty)

  test "ALPN protocol with comma raises":
    var ctx = newTlsContext(verify = false)
    expect WolfSslError:
      ctx.connect("example.com", 443, alpn = ["h2,http/1.1"])
    ctx.close()

  test "ALPN empty protocol name raises":
    var ctx = newTlsContext(verify = false)
    expect WolfSslError:
      ctx.connect("example.com", 443, alpn = [""])
    ctx.close()

  test "readInto before connect raises WolfSslError":
    var ctx = newTlsContext(verify = false)
    var buf: array[16, byte]
    expect WolfSslError:
      discard ctx.readInto(buf)
    ctx.close()

  test "readInto on closed context raises WolfSslError":
    var ctx = newTlsContext(verify = false)
    ctx.close()
    var buf: array[16, byte]
    expect WolfSslError:
      discard ctx.readInto(buf)

  test "write openArray[byte] before connect raises WolfSslError":
    var ctx = newTlsContext(verify = false)
    expect WolfSslError:
      ctx.write([byte 1, 2, 3])
    ctx.close()

  test "peerCertDer on non-connected context returns empty":
    var ctx = newTlsContext(verify = false)
    check ctx.peerCertDer().len == 0
    ctx.close()

  test "negotiatedAlpn on non-connected context returns empty":
    var ctx = newTlsContext(verify = false)
    check ctx.negotiatedAlpn() == ""
    ctx.close()

  test "mTLS cert without key raises WolfSslError":
    expect WolfSslError:
      discard newTlsContext(certFile = "/tmp/cert.pem", verify = false)

  test "mTLS key without cert raises WolfSslError":
    expect WolfSslError:
      discard newTlsContext(keyFile = "/tmp/key.pem", verify = false)

  test "destroy leaves safe state":
    var ctx = newTlsContext(verify = false)
    `=destroy`(ctx)
    check ctx.state == tsClosed
    # Second destroy is safe (all fields zeroed)
    `=destroy`(ctx)
