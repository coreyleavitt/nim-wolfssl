# Package
version       = "0.1.0"
author        = "Corey Leavitt"
description   = "Nim wrapper for wolfSSL 5.x"
license       = "Apache-2.0"
srcDir        = "src"

# Dependencies
requires "nim >= 2.0.0"
requires "https://github.com/coreyleavitt/softlink >= 0.3.1"

task test, "Run binding validation tests (Tier 1, no network)":
  exec "nim c -r --path:src tests/t_bindings.nim"

task test_integration, "Run integration tests (Tier 2, requires network)":
  exec "nim c -r --path:src tests/t_tls_client.nim"
