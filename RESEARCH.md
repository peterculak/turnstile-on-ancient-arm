# Solving Cloudflare Turnstile on a Raspberry Pi 1 (2012, ARMv6) — without a browser

This started as a simple question — *how does Cloudflare Turnstile work, and how do
public "Turnstile solver" tools bypass it?* — and turned into a from-scratch
cross-compile of a real Rust no-browser solver for a 13-year-old, 32-bit ARM chip
that cannot run any modern browser at all. This document is the full writeup:
what we tried, what broke, how we fixed it, and a real end-to-end run against a
live Cloudflare Turnstile widget with timing.

**Test hardware:** Raspberry Pi 1 Model B (2012), single-core ARM1176JZF-S
@ ~700MHz, ARMv6 architecture, **no NEON SIMD unit**, 426MB usable RAM, running a
current Raspberry Pi OS (`armhf`, kernel 6.18).

## Background: how Turnstile actually works

Cloudflare Turnstile is a CAPTCHA replacement. A page embeds a widget tied to a
*sitekey*; the widget loads Cloudflare's `api.js`, which runs an obfuscated
challenge script inside an iframe. That script does two things: a proof-of-work
style computation, and passive browser fingerprinting (canvas/WebGL rendering,
`navigator` properties, timing behavior, TLS fingerprint of the connection).
Based on a risk score it either passes silently, shows an interactive checkbox,
or fails. On success it writes a single-use token into the page, which the
site's backend validates server-side via Cloudflare's `siteverify` API.

Public "Turnstile solver" tools (e.g. [Theyka/Turnstile-Solver](https://github.com/Theyka/Turnstile-Solver))
typically don't break this cryptographically — they drive a real, stealth-patched
browser (Camoufox / Patchright) through the challenge, the same way a real user's
browser would, and read back the token Cloudflare's own script produces.

**That approach is a non-starter on this hardware.** We installed Chromium on
the Pi 1 to confirm directly rather than assume it:

```
$ chromium --headless --no-sandbox --disable-gpu --dump-dom about:blank
The hardware on this system lacks support for NEON SIMD extensions.
We now require NEON or equivalent architecture extensions on ARM-based machines.
```

This is not a performance problem — it's an instruction-set wall. NEON only
exists from ARMv7 onward; Firefox has the same baseline now. No amount of
patience or resource tuning gets a real browser running on ARMv6 silicon.

## Part 1: a genuinely no-browser solve, using Cloudflare's own testing sitekey

Before attempting the hard version, we proved the "no browser at all" concept
end-to-end using Cloudflare's own [published testing keys](https://developers.cloudflare.com/turnstile/troubleshooting/testing/):
the sitekey `1x00000000000000000000AA` always passes and its JS always produces
one fixed, documented literal token: `XXXX.DUMMY.TOKEN.XXXX`. Knowing that fact
is the entire "solve" — no JS execution, no fingerprinting, just a Python
`urllib` POST of that literal string, verified for real against Cloudflare's
live `siteverify` endpoint with the matching test secret key.

See [`dummy-sitekey-ctf/`](dummy-sitekey-ctf/) for the Flask target
(`app.py`) and the Pi 1 solver (`solver_pi1.py`, pure stdlib, zero
dependencies). One real gotcha we found along the way: the "always passes"
test *secret* key accepts **any** non-empty token, not just the documented
dummy string — so the Flask app explicitly checks for the exact dummy token
itself, otherwise the "challenge" is trivially beaten by posting garbage.

This is a fun, legitimate demo, but it's not really "solving Turnstile" — it's
knowing a documented shortcut. Part 2 is the real thing.

## Part 2: cross-compiling a real no-browser solver for ARMv6

[cfsolve](https://github.com/chris124567/cfsolve) (this repo's upstream) is a
serious, from-scratch reimplementation: it parses and deobfuscates Cloudflare's
actual challenge JavaScript with a real JS parser/analyzer (`oxc`), runs it
through its own Rust-written bytecode VM, and separately patches BoringSSL to
emit an exact browser-shaped TLS ClientHello plus replay recorded real-browser
check responses from a "profile" — because Cloudflare ties its clearance to a
consistent IP, user-agent, *and* TLS fingerprint, not just a JS answer.

It has no published ARMv6 build, and its own README warns the author plans to
stop maintaining it soon — which is exactly why this fork exists: to keep a
working, fixed copy around.

### Why running the binary isn't the problem — building it is

A compiled Rust binary doing HTTP + bytecode interpretation has nothing like a
browser's footprint. ARMv6 (`arm-unknown-linux-gnueabihf`) is a real Rust
target, and running one on Pi 1's 426MB RAM is trivial. The entire difficulty
is *compiling* cfsolve for that target, because it builds a patched BoringSSL
from source via CMake + a C/C++ toolchain + `bindgen`, none of which is
remotely fast or simple to cross-compile. We cross-compiled on a 10-core/16GB
Mac using [`cross`](https://github.com/cross-rs/cross) (Docker-based), rather
than attempting a native build on the Pi itself — building BoringSSL natively
on a single 700MHz ARMv6 core with 426MB RAM would realistically thrash swap
for hours or just OOM.

### The five build bugs, in the order we hit them

**1. `__STDC_FORMAT_MACROS` not defined for C++ (BoringSSL)**

```
error: expected ')' before 'PRIX32'
    snprintf(buf, sizeof(buf), "\\W%08" PRIX32, c);
```

BoringSSL's own `bn.h` documents this exact issue: some C++ toolchains gate
`PRIx32`/`PRIX32` (from `<inttypes.h>`) behind `__STDC_FORMAT_MACROS`, and says
callers "may need to define it externally." Fixed by adding
`add_definitions(-D__STDC_FORMAT_MACROS)` to BoringSSL's `CMakeLists.txt`
(see `vendor/btls-sys/deps/boringssl/CMakeLists.txt`).

**2. Missing `AT_HWCAP2` constant (BoringSSL)**

```
error: 'AT_HWCAP2' was not declared in this scope
     unsigned long hwcap2 = getauxval(AT_HWCAP2);
```

This cross toolchain's glibc headers predate `AT_HWCAP2` (ironically, an
ARMv7+-era CPU-feature-detection constant — irrelevant to real ARMv6 hardware,
but still referenced in the generic ARM feature-detection code path). It's a
stable, architecture-independent Linux auxv tag number, so we defined it
ourselves as a fallback (`crypto/cpu_arm_linux.cc`):

```c
#ifndef AT_HWCAP2
#define AT_HWCAP2 26
#endif
```

**3. `libclang` missing at runtime (bindgen)**

```
Unable to find libclang: "couldn't find any valid shared libraries matching: [...]"
```

The `cross-rs` base image's `dpkg` database claims `libclang1-18` is
installed, but the actual `.so` files were stripped from the image (likely to
shrink it) while the package metadata was left intact. Fixed with a custom
image (`Dockerfile.cross-armv6`) that force-reinstalls the package so the real
shared library gets re-extracted:

```dockerfile
RUN apt-get update && \
    apt-get install -y --reinstall --no-install-recommends libclang1-18 && \
    rm -rf /var/lib/apt/lists/*
```

**4. Same error, different cause — `clang-sys` wasn't checking the right path**

Even with the file verifiably present and readable on disk
(`/usr/lib/llvm-18/lib/libclang.so.1`), the exact same "Unable to find
libclang" error recurred. `clang-sys`'s search logic simply wasn't scanning
that directory. Fixed by setting `LIBCLANG_PATH` explicitly and passing it
through to the build container via `Cross.toml`:

```toml
[target.arm-unknown-linux-gnueabihf.env]
passthrough = ["LIBCLANG_PATH"]
```
(with `LIBCLANG_PATH=/usr/lib/llvm-18/lib` exported on the host before
invoking `cross build`.)

**5. 32-bit vs 64-bit type mismatch (cfsolve's own code)**

```
error[E0308]: mismatched types
    time.tv_sec * 1_000_000 + time.tv_nsec / 1000
    expected `i64`, found `i32`
```

`libc::timespec`'s `tv_sec`/`tv_nsec` fields are `i32` on 32-bit Linux targets
and `i64` on 64-bit ones — the original code assumed 64-bit. Fixed in
`src/performance_clock.rs` with explicit casts (not just `.into()` at the end,
which would still risk `i32` overflow before conversion):

```rust
time.tv_sec as i64 * 1_000_000 + time.tv_nsec as i64 / 1000
```

After these five fixes, `cross build --release --bin challenge --target
arm-unknown-linux-gnueabihf` completes cleanly — `Finished \`release\` profile
[optimized] target(s) in 17m 12s` on the build machine, producing a genuine
32-bit ARM EABI5 binary:

```
$ file challenge
challenge: ELF 32-bit LSB pie executable, ARM, EABI5 version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux-armhf.so.3, for GNU/Linux 4.19.255
```

Copied to the Pi and run directly — no toolchain needed there at all:

```
$ ~/challenge --help
Usage: challenge <iframe-url> <output-directory> --fingerprint <fingerprint.json>
...
```

It runs. Exit code 0. The NEON wall that stops a real browser dead does not
apply here at all.

## Part 3: a real end-to-end solve against a live Cloudflare Turnstile widget

To test this for real (not against a dummy sitekey), we created a genuine
Cloudflare Turnstile widget (Managed mode) — no domain or DNS changes needed;
new widgets automatically allow `localhost`/`127.0.0.1` as hostnames — pointed
the Pi 1's compiled binary at a page serving that real widget, and ran:

```
challenge --page http://<host>/real ./out --solve \
  --fingerprint profiles/safari-26-ios.json --sitekey <real-sitekey>
```

Result: a genuine, full-length Turnstile token (not the trivial dummy-token
format from Part 1), which our backend then submitted to Cloudflare's **real**
`siteverify` API — not a simulation — and got back `"success": true`.

### Timing breakdown (from file timestamps on the Pi)

| Phase | Duration |
|---|---|
| Page fetch + render | ~0.7s |
| Deobfuscate 606KB of live challenge JS + build first payload + POST round-trip | ~30s |
| **VM execution / answering 38 fingerprint probes** | **~1m 55s** |
| Second payload + final POST + token saved | ~2s |
| **Total, page load to accepted token** | **~2m 27s** |

The dominant cost is the VM/probe-answering phase — genuinely interpreting
Cloudflare's challenge bytecode on a single 700MHz ARMv6 core with no SIMD.
For comparison, a normal browser clears Turnstile's non-interactive/invisible
path in roughly 1-2 seconds (that's the common case for most real visitors);
this same compiled binary would very likely do the same work in well under a
second on a modern x86_64/arm64 machine. Pi 1 is probably running it something
like 100-150x slower than that — a real, measured cost of avoiding a browser
on 13-year-old hardware, not a flaw in the approach itself.

## Reproducing this

1. Install [`cross`](https://github.com/cross-rs/cross) and Docker.
2. From this repo's root: build the custom image and build:
   ```
   docker build --platform linux/amd64 -t cfsolve-cross-armv6:local -f Dockerfile.cross-armv6 .
   export LIBCLANG_PATH=/usr/lib/llvm-18/lib
   cross build --release --bin challenge --target arm-unknown-linux-gnueabihf
   ```
3. Copy `target/arm-unknown-linux-gnueabihf/release/challenge` and the
   `profiles/` directory to your ARMv6 device and run it directly — see the
   main `README.md` for full CLI usage.
4. For the no-browser dummy-sitekey demo instead, see
   [`dummy-sitekey-ctf/`](dummy-sitekey-ctf/).

## Credits

- [chris124567/cfsolve](https://github.com/chris124567/cfsolve) — the
  no-browser Turnstile/challenge solver this repo forks and fixes for ARMv6.
  MIT licensed; this fork preserves its full history and license.
- [Theyka/Turnstile-Solver](https://github.com/Theyka/Turnstile-Solver) — a
  real-browser-automation Turnstile solver that was the starting point for
  understanding how Turnstile works and how it's typically bypassed, before
  we went looking for a no-browser approach.
- Cloudflare's own [Turnstile testing documentation](https://developers.cloudflare.com/turnstile/troubleshooting/testing/)
  for the published dummy sitekey/secret behavior used in Part 1.

## Scope note

Everything here was run against infrastructure we control: a self-hosted
Flask target on our own LAN, and a Cloudflare Turnstile widget created in our
own account for this purpose. This is a hardware/build-portability research
exercise, not a tool aimed at any third-party site.
