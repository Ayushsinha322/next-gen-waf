# Third-Party Notices

Swaraj Kavach incorporates the components listed below. Each is the property of
its respective authors and is used under the licence shown.

This file is **generated** by `deploy/gen-notices.py`, which the bundle build
re-runs during packaging. Run it after changing a dependency. Do not edit by hand.

It records what each component **declares** in its own manifest. It is an
attribution inventory, not a legal review.

**418 redistributed components** across Rust, Go, npm and container images.
A further 105 Rust crates and 399 npm packages are
build- or development-only: they are compiled or installed here but never
shipped, and are listed separately at the end so the two are never confused.

Full licence texts that must ship with a redistribution are under `licenses/`;
the OWASP Core Rule Set keeps its own copy at `rules/owasp-crs/LICENSE`.

> The licence of Swaraj Kavach **itself** is not stated here and there is no
> LICENSE file in this repository. That is a business decision, not a generated
> one — it needs to be made before anything is handed to a customer.

## Audit of the redistributed set

- No AGPL, GPL-only, SSPL or CC-BY-SA component is redistributed.
- Every redistributed component declares a licence.

## Rust crates (data plane)
Reachable through normal (non-dev, non-build) edges from a shipped binary, so these are compiled into what customers run. Workspace members excluded.
**280 components.**

### MIT OR Apache-2.0 — 143 component(s)
- ahash 0.8.12
- anstream 1.0.0
- anstyle 1.0.14
- anstyle-parse 1.0.0
- anstyle-query 1.1.5
- anyhow 1.0.102
- arbitrary 1.4.2
- arc-swap 1.9.1
- async-trait 0.1.89
- base64 0.21.7
- base64 0.22.1
- bitflags 2.11.1
- block-buffer 0.10.4
- bumpalo 3.20.2
- cfg-if 1.0.4
- chacha20 0.10.0
- chrono 0.4.44
- clap 4.6.1
- clap_builder 4.6.0
- clap_derive 4.6.1
- clap_lex 1.1.0
- cobs 0.3.0
- colorchoice 1.0.5
- cpp_demangle 0.4.5
- cpufeatures 0.2.17
- cpufeatures 0.3.0
- crc32fast 1.5.0
- crossbeam-channel 0.5.17
- crossbeam-deque 0.8.6
- crossbeam-epoch 0.9.21
- crossbeam-utils 0.8.21
- crypto-common 0.1.7
- deranged 0.3.11
- digest 0.10.7
- directories-next 2.0.0
- dirs-sys-next 0.1.2
- either 1.15.0
- errno 0.3.14
- flate2 1.1.9
- form_urlencoded 1.2.2
- futures 0.3.32
- futures-channel 0.3.32
- futures-core 0.3.32
- futures-executor 0.3.32
- futures-io 0.3.32
- futures-macro 0.3.32
- futures-sink 0.3.32
- futures-task 0.3.32
- futures-util 0.3.32
- fxprof-processed-profile 0.6.0
- getrandom 0.2.17
- getrandom 0.4.2
- gimli 0.29.0
- hashbrown 0.13.2
- hashbrown 0.14.5
- hashbrown 0.15.5
- hashbrown 0.17.1
- heck 0.4.1
- heck 0.5.0
- hex 0.4.3
- hmac 0.12.1
- http 1.4.0
- httparse 1.10.1
- httpdate 1.0.3
- iana-time-zone 0.1.65
- idna 0.5.0
- ipnet 2.12.0
- ipnetwork 0.20.0
- is_terminal_polyfill 1.70.2
- itertools 0.12.1
- itoa 1.0.18
- lazy_static 1.5.0
- leb128 0.2.6
- leb128fmt 0.1.0
- libc 0.2.186
- lock_api 0.4.14
- log 0.4.29
- memfd 0.6.5
- num-bigint 0.4.8
- num-conv 0.1.0
- num-integer 0.1.46
- num-traits 0.2.19
- once_cell 1.21.4
- parking_lot 0.12.5
- parking_lot_core 0.9.12
- paste 1.0.15
- percent-encoding 2.3.2
- postcard 1.1.3
- powerfmt 0.2.0
- proc-macro2 1.0.106
- quinn 0.11.11
- quinn-proto 0.11.19
- quinn-udp 0.5.14
- quote 1.0.45
- rand 0.10.1
- rand_core 0.10.1
- rand_pcg 0.10.2
- rayon 1.12.0
- rayon-core 1.13.0
- rcgen 0.12.1
- regex 1.12.3
- regex-automata 0.4.14
- regex-syntax 0.8.10
- rustls-pki-types 1.14.1
- rustversion 1.0.22
- scopeguard 1.2.0
- semver 1.0.28
- serde 1.0.228
- serde_core 1.0.228
- serde_derive 1.0.228
- serde_json 1.0.149
- serde_spanned 0.6.9
- serde_yaml 0.9.34+deprecated
- sha2 0.10.9
- signal-hook-registry 1.4.8
- smallvec 1.15.1
- socket2 0.6.3
- sptr 0.3.2
- syn 2.0.117
- tar 0.4.45
- thiserror 1.0.69
- thiserror 2.0.18
- thiserror-impl 1.0.69
- thiserror-impl 2.0.18
- thread_local 1.1.9
- time 0.3.36
- time-core 0.1.2
- time-macros 0.2.18
- tokio-rustls 0.26.4
- toml 0.8.23
- toml_datetime 0.6.11
- toml_edit 0.22.27
- toml_write 0.1.2
- typenum 1.20.0
- unicode-bidi 0.3.18
- unicode-normalization 0.1.25
- unicode-width 0.2.2
- unicode-xid 0.2.6
- ureq 2.12.1
- url 2.5.2
- xattr 1.6.1
- yasna 0.5.2
- zstd-safe 7.2.4

### MIT — 41 component(s)
- bytes 1.11.1
- combine 4.6.7
- dashmap 6.1.0
- generic-array 0.14.7
- h2 0.4.20
- h3 0.0.8
- h3-quinn 0.0.10
- http-body 1.0.1
- http-body-util 0.1.3
- hyper 1.9.0
- hyper-util 0.1.20
- jsonwebtoken 9.3.1
- libm 0.2.16
- matchers 0.2.0
- mio 1.2.0
- nom 7.1.3
- nu-ansi-term 0.50.3
- pem 3.0.6
- sharded-slab 0.1.7
- simd-adler32 0.3.9
- slab 0.4.12
- slice-group-by 0.3.1
- strsim 0.11.1
- tokio 1.52.3
- tokio-macros 2.7.0
- tokio-util 0.7.18
- tower-layer 0.3.3
- tower-service 0.3.3
- tracing 0.1.44
- tracing-appender 0.2.5
- tracing-attributes 0.1.31
- tracing-core 0.1.36
- tracing-log 0.2.0
- tracing-serde 0.2.0
- tracing-subscriber 0.3.23
- try-lock 0.2.5
- unsafe-libyaml 0.2.11
- want 0.3.1
- winnow 0.7.15
- zmij 1.0.21
- zstd 0.13.3

### Apache-2.0 WITH LLVM-exception — 25 component(s)
- cranelift-bforest 0.111.13
- cranelift-bitset 0.111.13
- cranelift-codegen 0.111.13
- cranelift-codegen-shared 0.111.13
- cranelift-control 0.111.13
- cranelift-entity 0.111.13
- cranelift-frontend 0.111.13
- cranelift-native 0.111.13
- cranelift-wasm 0.111.13
- regalloc2 0.9.3
- target-lexicon 0.12.16
- wasmtime 24.0.13
- wasmtime-asm-macros 24.0.13
- wasmtime-cache 24.0.13
- wasmtime-component-macro 24.0.13
- wasmtime-component-util 24.0.13
- wasmtime-cranelift 24.0.13
- wasmtime-environ 24.0.13
- wasmtime-fiber 24.0.13
- wasmtime-jit-debug 24.0.13
- wasmtime-jit-icache-coherence 24.0.13
- wasmtime-slab 24.0.13
- wasmtime-types 24.0.13
- wasmtime-versioned-export-macros 24.0.13
- wasmtime-wit-bindgen 24.0.13

### Apache-2.0 OR MIT — 15 component(s)
- addr2line 0.22.0
- async-lock 3.4.2
- atomic-waker 1.1.2
- equivalent 1.0.2
- event-listener 5.4.2
- event-listener-strategy 0.5.4
- fastrand 2.4.1
- indexmap 2.14.0
- object 0.36.7
- parking 2.2.1
- pin-project-lite 0.2.17
- rustc-hash 2.1.2
- utf8parse 0.2.2
- uuid 1.23.1
- zeroize 1.8.2

### Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT — 11 component(s)
- linux-raw-sys 0.12.1
- linux-raw-sys 0.4.15
- rustix 0.38.44
- rustix 1.1.4
- wasm-encoder 0.215.0
- wasm-encoder 0.248.0
- wasmparser 0.215.0
- wasmprinter 0.215.0
- wast 248.0.0
- wat 1.248.0
- wit-parser 0.215.0

### MIT/Apache-2.0 — 6 component(s)
- filetime 0.2.28
- id-arena 2.3.0
- minimal-lexical 0.2.1
- rustc-demangle 0.1.27
- symlink 0.1.0
- zstd-sys 2.0.16+zstd.1.5.7

### BSD-3-Clause — 4 component(s)
- libinjectionrs 0.1.1
- redis 1.2.2
- sha1_smol 1.0.1
- subtle 2.6.1

### ISC — 4 component(s)
- maxminddb 0.24.0
- rustls-webpki 0.103.15
- simple_asn1 0.6.3
- untrusted 0.9.0

### Unlicense OR MIT — 4 component(s)
- aho-corasick 1.1.4
- byteorder 1.5.0
- memchr 2.8.0
- termcolor 1.4.1

### Apache-2.0 OR ISC OR MIT — 3 component(s)
- hyper-rustls 0.27.9
- rustls 0.23.46
- rustls-pemfile 2.2.0

### Apache-2.0 — 2 component(s)
- backon 1.6.0
- debugid 0.8.0

### Apache-2.0/MIT — 2 component(s)
- fxhash 0.2.1
- rustc-hash 1.1.0

### CDLA-Permissive-2.0 — 2 component(s)
- webpki-roots 0.26.11
- webpki-roots 1.0.7

### GPL-2.0-only OR BSD-3-Clause — 2 component(s)
- ittapi 0.4.0
- ittapi-sys 0.4.0

### MIT OR Apache-2.0 OR Zlib — 2 component(s)
- lru-slab 0.1.2
- tinyvec_macros 0.1.1

### (Apache-2.0 OR MIT) AND BSD-3-Clause — 1 component(s)
- encoding_rs 0.8.35

### (MIT OR Apache-2.0) AND Unicode-3.0 — 1 component(s)
- unicode-ident 1.0.24

### 0BSD OR MIT OR Apache-2.0 — 1 component(s)
- adler2 2.0.1

### Apache-2.0 / MIT — 1 component(s)
- fnv 1.0.7

### Apache-2.0 AND ISC — 1 component(s)
- ring 0.17.14

### Apache-2.0 OR BSL-1.0 — 1 component(s)
- ryu 1.0.23

### Apache-2.0 OR MIT OR Zlib — 1 component(s)
- arcstr 1.2.0

### BSD-2-Clause OR Apache-2.0 OR MIT — 1 component(s)
- zerocopy 0.8.48

### BSL-1.0 — 1 component(s)
- xxhash-rust 0.8.19

### ISC AND (Apache-2.0 OR ISC) — 1 component(s)
- aws-lc-rs 1.18.1

### ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND (Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR ISC OR MIT-0) — 1 component(s)
- aws-lc-sys 0.45.0

### MIT OR Zlib OR Apache-2.0 — 1 component(s)
- miniz_oxide 0.8.9

### Zlib — 1 component(s)
- foldhash 0.1.5

### Zlib OR Apache-2.0 OR MIT — 1 component(s)
- tinyvec 1.11.0

## Go modules (control plane)
In the `controllerd` module graph. Go modules carry no licence field in the graph itself; each module's own repository is authoritative.
**55 components.**

### see module source — 55 component(s)
- github.com/bytedance/sonic v1.11.6
- github.com/bytedance/sonic/loader v0.1.1
- github.com/cloudwego/base64x v0.1.4
- github.com/cloudwego/iasm v0.2.0
- github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc
- github.com/gabriel-vasile/mimetype v1.4.3
- github.com/gin-contrib/sse v0.1.0
- github.com/gin-gonic/gin v1.10.0
- github.com/go-playground/assert/v2 v2.2.0
- github.com/go-playground/locales v0.14.1
- github.com/go-playground/universal-translator v0.18.1
- github.com/go-playground/validator/v10 v10.20.0
- github.com/goccy/go-json v0.10.2
- github.com/golang-jwt/jwt/v5 v5.2.2
- github.com/golang/protobuf v1.5.0
- github.com/google/go-cmp v0.6.0
- github.com/google/gofuzz v1.0.0
- github.com/jackc/pgpassfile v1.0.0
- github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761
- github.com/jackc/pgx/v5 v5.9.2
- github.com/jackc/puddle/v2 v2.2.2
- github.com/json-iterator/go v1.1.12
- github.com/klauspost/cpuid/v2 v2.2.7
- github.com/knz/go-libedit v1.10.1
- github.com/kr/pretty v0.3.0
- github.com/kr/text v0.2.0
- github.com/leodido/go-urn v1.4.0
- github.com/mattn/go-isatty v0.0.20
- github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd
- github.com/modern-go/reflect2 v1.0.2
- github.com/pelletier/go-toml/v2 v2.2.2
- github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2
- github.com/rogpeppe/go-internal v1.16.0
- github.com/stretchr/objx v0.5.2
- github.com/stretchr/testify v1.11.1
- github.com/twitchyliquid64/golang-asm v0.15.1
- github.com/ugorji/go/codec v1.2.12
- go.uber.org/goleak v1.3.0
- go.uber.org/multierr v1.10.0
- go.uber.org/zap v1.27.0
- golang.org/x/arch v0.8.0
- golang.org/x/crypto v0.57.0
- golang.org/x/mod v0.41.0
- golang.org/x/net v0.60.0
- golang.org/x/sync v0.23.0
- golang.org/x/sys v0.48.0
- golang.org/x/term v0.46.0
- golang.org/x/text v0.42.0
- golang.org/x/tools v0.49.0
- golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543
- google.golang.org/protobuf v1.34.2
- gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c
- gopkg.in/yaml.v3 v3.0.1
- nullprogram.com/x/optparse v1.0.0
- rsc.io/pdf v0.1.1

## npm packages (dashboard, production)
Production dependencies only — `npm ls --omit=dev`. Next.js bundles a subset of these into the shipped client.
**76 components.**

### MIT — 48 component(s)
- @babel/runtime 7.27.0
- @babel/runtime 7.29.7
- @emnapi/runtime 1.11.3
- @img/colour 1.1.0
- @next/env 15.5.27
- @next/swc-linux-x64-gnu 15.5.27
- @next/swc-linux-x64-musl 15.5.27
- @tanstack/query-core 5.100.10
- @tanstack/react-query 5.100.10
- @types/d3-array 3.2.2
- @types/d3-color 3.1.3
- @types/d3-ease 3.0.2
- @types/d3-interpolate 3.0.4
- @types/d3-path 3.1.1
- @types/d3-scale 4.0.9
- @types/d3-shape 3.1.8
- @types/d3-time 3.0.4
- @types/d3-timer 3.0.2
- client-only 0.0.1
- clsx 2.1.1
- csstype 3.2.3
- date-fns 3.6.0
- decimal.js-light 2.5.1
- dom-helpers 5.2.1
- eventemitter3 4.0.7
- fast-equals 5.4.3
- framer-motion 12.40.0
- js-tokens 4.0.0
- lodash 4.18.1
- loose-envify 1.4.0
- motion-dom 12.40.0
- motion-utils 12.39.0
- nanoid 3.3.19
- next 15.5.27
- object-assign 4.1.1
- postcss 8.5.28
- prop-types 15.8.1
- react 19.3.0
- react-dom 19.3.0
- react-is 16.13.1
- react-is 18.3.1
- react-is 19.2.0-canary-0bdb9206-20250818
- react-smooth 4.0.4
- recharts 2.15.4
- recharts-scale 0.4.5
- styled-jsx 5.1.6
- tailwind-merge 2.6.1
- tiny-invariant 1.3.3

### ISC — 14 component(s)
- d3-array 3.2.4
- d3-color 3.1.0
- d3-format 3.1.2
- d3-interpolate 3.0.1
- d3-path 3.1.0
- d3-scale 4.0.2
- d3-shape 3.2.0
- d3-time 3.1.0
- d3-time-format 4.1.0
- d3-timer 3.0.1
- internmap 2.0.3
- picocolors 1.1.1
- semver 6.3.1
- semver 7.8.5

### Apache-2.0 — 5 component(s)
- @img/sharp-linux-x64 0.35.5
- @img/sharp-linuxmusl-x64 0.35.5
- @swc/helpers 0.5.15
- detect-libc 2.1.2
- sharp 0.35.5

### BSD-3-Clause — 3 component(s)
- d3-ease 3.0.1
- react-transition-group 4.4.5
- source-map-js 1.2.2

### LGPL-3.0-or-later — 2 component(s)
- @img/sharp-libvips-linux-x64 1.3.4
- @img/sharp-libvips-linuxmusl-x64 1.3.4

### 0BSD — 1 component(s)
- tslib 2.8.1

### Apache-2.0 AND LGPL-3.0-or-later AND MIT — 1 component(s)
- @img/sharp-wasm32 0.35.5

### CC-BY-4.0 — 1 component(s)
- caniuse-lite 1.0.30001792

### MIT AND ISC — 1 component(s)
- victory-vendor 36.9.2

## Container images and vendored content

### OWASP Core Rule Set 4.7.0

- **Licence:** Apache-2.0
- Vendored at rules/owasp-crs/. Full text at rules/owasp-crs/LICENSE. Copyright (c) 2006-2020 Trustwave and contributors; (c) 2021-2024 CRS project.

### PostgreSQL (postgres:16-alpine) 16

- **Licence:** PostgreSQL License
- Container image, pulled at install time — not redistributed in the bundle.

### Valkey (valkey/valkey:8-alpine) 8

- **Licence:** BSD-3-Clause
- Container image. Replaced redis:7-alpine, which resolves to 7.4 and is RSALv2/SSPL — not open source and not redistributable in a bundle.

### ClickHouse (clickhouse-server:26.3.35.3-alpine) 26.3.35.3

- **Licence:** Apache-2.0
- Container image, pulled at install time.

### Prometheus (prom/prometheus) v2.54.1

- **Licence:** Apache-2.0
- Container image, pulled at install time.

### HAProxy (haproxy:2.9-alpine) 2.9

- **Licence:** GPL-2.0-or-later WITH openvpn-openssl-exception / LGPL-2.1
- Container image used unmodified as a load balancer; not linked into any product binary.

### OWASP Juice Shop 20.1.1

- **Licence:** MIT
- DEMO TARGET ONLY, behind the `demo` compose profile. Never started in a customer installation.

---

# Build- and development-only components

Present in this working tree, **not redistributed**: test harnesses, build scripts, linters, type checkers. Listed for completeness so that a reader can tell the two sets apart rather than assuming.

## Rust (dev- and build-dependencies)

**105 components.**

### MIT OR Apache-2.0 — 49 component(s)
- anes 0.1.6
- anstyle-wincon 3.0.11
- cast 0.3.0
- cc 1.2.62
- cmake 0.1.58
- core-foundation 0.9.4
- core-foundation-sys 0.8.7
- embedded-io 0.4.0
- embedded-io 0.6.1
- find-msvc-tools 0.1.9
- getrandom 0.3.4
- half 2.7.1
- hermit-abi 0.5.2
- iana-time-zone-haiku 0.1.2
- jobserver 0.1.34
- js-sys 0.3.98
- once_cell_polyfill 1.70.2
- pkg-config 0.3.33
- prettyplease 0.2.37
- psm 0.1.31
- shlex 1.3.0
- stable_deref_trait 1.2.1
- system-configuration 0.7.0
- system-configuration-sys 0.6.0
- tempfile 3.27.0
- wasm-bindgen 0.2.121
- wasm-bindgen-macro 0.2.121
- wasm-bindgen-macro-support 0.2.121
- wasm-bindgen-shared 0.2.121
- web-sys 0.3.98
- web-time 1.1.0
- windows-core 0.62.2
- windows-implement 0.60.2
- windows-interface 0.59.3
- windows-link 0.2.1
- windows-registry 0.6.1
- windows-result 0.4.1
- windows-strings 0.5.1
- windows-sys 0.52.0
- windows-sys 0.61.2
- windows-targets 0.52.6
- windows_aarch64_gnullvm 0.52.6
- windows_aarch64_msvc 0.52.6
- windows_i686_gnu 0.52.6
- windows_i686_gnullvm 0.52.6
- windows_i686_msvc 0.52.6
- windows_x86_64_gnu 0.52.6
- windows_x86_64_gnullvm 0.52.6
- windows_x86_64_msvc 0.52.6

### Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT — 14 component(s)
- wasi 0.11.1+wasi-snapshot-preview1
- wasip2 1.0.3+wasi-0.2.9
- wasip3 0.4.0+wasi-0.3.0-rc-2026-01-06
- wasm-encoder 0.244.0
- wasm-metadata 0.244.0
- wasmparser 0.244.0
- wasmparser 0.248.0
- wit-bindgen 0.51.0
- wit-bindgen 0.57.1
- wit-bindgen-core 0.51.0
- wit-bindgen-rust 0.51.0
- wit-bindgen-rust-macro 0.51.0
- wit-component 0.244.0
- wit-parser 0.244.0

### MIT — 14 component(s)
- cfg_aliases 0.2.1
- crunchy 0.2.4
- fs_extra 1.3.0
- is-terminal 0.4.17
- libredox 0.1.16
- oorandom 11.1.5
- plotters 0.3.7
- plotters-backend 0.3.7
- plotters-svg 0.3.7
- redox_syscall 0.5.18
- redox_users 0.4.6
- tokio-stream 0.1.18
- tokio-test 0.4.5
- valuable 0.1.1

### MIT/Apache-2.0 — 8 component(s)
- android_system_properties 0.1.5
- criterion-plot 0.5.0
- fallible-iterator 0.3.0
- itertools 0.10.5
- version_check 0.9.5
- winapi 0.3.9
- winapi-i686-pc-windows-gnu 0.4.0
- winapi-x86_64-pc-windows-gnu 0.4.0

### Apache-2.0 WITH LLVM-exception — 5 component(s)
- ar_archive_writer 0.5.1
- cranelift-codegen-meta 0.111.13
- cranelift-isle 0.111.13
- wasmtime-winch 24.0.13
- winch-codegen 0.22.13

### Apache-2.0 OR MIT — 4 component(s)
- autocfg 1.5.0
- criterion 0.5.1
- object 0.37.3
- tinytemplate 1.2.1

### Apache-2.0 — 3 component(s)
- ciborium 0.2.2
- ciborium-io 0.2.2
- ciborium-ll 0.2.2

### MIT OR Apache-2.0 OR LGPL-2.1-or-later — 2 component(s)
- r-efi 5.3.0
- r-efi 6.0.0

### Unlicense/MIT — 2 component(s)
- same-file 1.0.6
- walkdir 2.5.0

### BSD-2-Clause OR Apache-2.0 OR MIT — 1 component(s)
- zerocopy-derive 0.8.48

### BSD-2-Clause OR MIT OR Apache-2.0 — 1 component(s)
- mach2 0.4.3

### CC0-1.0 OR MIT-0 OR Apache-2.0 — 1 component(s)
- dunce 1.0.5

### Unlicense OR MIT — 1 component(s)
- winapi-util 0.1.11

## npm (devDependencies)

**399 components.**

### MIT — 344 component(s)
- @alloc/quick-lru 5.2.0
- @edge-runtime/cookies 6.0.0
- @edge-runtime/ponyfill 4.0.0
- @edge-runtime/primitives 6.0.0
- @esbuild/linux-x64 0.21.5
- @eslint-community/eslint-utils 4.9.1
- @eslint-community/regexpp 4.12.2
- @eslint/eslintrc 2.1.4
- @eslint/js 8.57.1
- @jridgewell/gen-mapping 0.3.13
- @jridgewell/resolve-uri 3.1.2
- @jridgewell/sourcemap-codec 1.5.5
- @jridgewell/trace-mapping 0.3.31
- @my-scope/package-a 0.0.0
- @my-scope/package-b 0.0.0
- @next/eslint-plugin-next 15.5.26
- @nodelib/fs.scandir 2.1.5
- @nodelib/fs.stat 2.0.5
- @nodelib/fs.walk 1.2.8
- @nolyfill/is-core-module 1.0.39
- @rollup/rollup-linux-x64-gnu 4.62.2
- @rollup/rollup-linux-x64-musl 4.62.2
- @rtsao/scc 1.1.0
- @rushstack/eslint-patch 1.16.1
- @types/estree 1.0.9
- @types/json5 0.0.29
- @types/node 20.19.41
- @types/qrcode 1.5.6
- @types/react 19.3.0
- @types/react-dom 19.3.0
- @typescript-eslint/eslint-plugin 8.59.3
- @typescript-eslint/parser 8.59.3
- @typescript-eslint/project-service 8.59.3
- @typescript-eslint/scope-manager 8.59.3
- @typescript-eslint/tsconfig-utils 8.59.3
- @typescript-eslint/type-utils 8.59.3
- @typescript-eslint/types 8.59.3
- @typescript-eslint/typescript-estree 8.59.3
- @typescript-eslint/utils 8.59.3
- @typescript-eslint/visitor-keys 8.59.3
- @unrs/resolver-binding-linux-x64-gnu 1.11.1
- @unrs/resolver-binding-linux-x64-musl 1.11.1
- @vitest/expect 2.1.9
- @vitest/mocker 2.1.9
- @vitest/pretty-format 2.1.9
- @vitest/runner 2.1.9
- @vitest/snapshot 2.1.9
- @vitest/spy 2.1.9
- @vitest/utils 2.1.9
- acorn 8.16.0
- acorn-jsx 5.3.2
- ajv 6.15.0
- ansi-regex 5.0.1
- ansi-styles 4.3.0
- any-promise 1.3.0
- arg 5.0.2
- array-buffer-byte-length 1.0.2
- array-includes 3.1.9
- array.prototype.findlast 1.2.5
- array.prototype.findlastindex 1.2.6
- array.prototype.flat 1.3.3
- array.prototype.flatmap 1.3.3
- array.prototype.tosorted 1.1.4
- arraybuffer.prototype.slice 1.0.4
- assertion-error 2.0.1
- ast-types-flow 0.0.8
- async-function 1.0.0
- autoprefixer 10.5.0
- available-typed-arrays 1.0.7
- balanced-match 1.0.2
- balanced-match 4.0.4
- binary-extensions 2.3.0
- brace-expansion 1.1.14
- brace-expansion 5.0.6
- braces 3.0.3
- browserslist 4.28.2
- cac 6.7.14
- call-bind 1.0.9
- call-bind-apply-helpers 1.0.2
- call-bound 1.0.4
- callsites 3.1.0
- camelcase 5.3.1
- camelcase-css 2.0.1
- chai 5.3.3
- chalk 4.1.2
- check-error 2.1.3
- chokidar 3.6.0
- color-convert 2.0.1
- color-name 1.1.4
- commander 4.1.1
- concat-map 0.0.1
- cross-spawn 7.0.6
- cssesc 3.0.0
- data-view-buffer 1.0.2
- data-view-byte-length 1.0.2
- data-view-byte-offset 1.0.1
- debug 3.2.7
- debug 4.4.3
- decamelize 1.2.0
- deep-eql 5.0.2
- deep-is 0.1.4
- define-data-property 1.1.4
- define-properties 1.2.1
- dijkstrajs 1.0.3
- dlv 1.1.3
- dunder-proto 1.0.1
- emoji-regex 8.0.0
- emoji-regex 9.2.2
- es-abstract 1.24.2
- es-define-property 1.0.1
- es-errors 1.3.0
- es-iterator-helpers 1.3.2
- es-module-lexer 1.7.0
- es-object-atoms 1.1.1
- es-set-tostringtag 2.1.0
- es-shim-unscopables 1.1.0
- es-to-primitive 1.3.0
- esbuild 0.21.5
- escalade 3.2.0
- escape-string-regexp 4.0.0
- eslint 8.57.1
- eslint-config-next 15.5.26
- eslint-import-resolver-node 0.3.10
- eslint-module-utils 2.12.1
- eslint-plugin-import 2.32.0
- eslint-plugin-jsx-a11y 6.10.2
- eslint-plugin-react 7.37.5
- eslint-plugin-react-hooks 5.2.0
- estree-walker 3.0.3
- fast-deep-equal 3.1.3
- fast-glob 3.3.1
- fast-glob 3.3.3
- fast-json-stable-stringify 2.1.0
- fast-levenshtein 2.0.6
- fdir 6.5.0
- file-entry-cache 6.0.1
- fill-range 7.1.1
- find-up 4.1.0
- find-up 5.0.0
- flat-cache 3.2.0
- for-each 0.3.5
- fraction.js 5.3.4
- function-bind 1.1.2
- function.prototype.name 1.1.8
- functions-have-names 1.2.3
- generator-function 2.0.1
- get-intrinsic 1.3.0
- get-proto 1.0.1
- get-symbol-description 1.1.0
- get-tsconfig 4.14.0
- globals 13.24.0
- globalthis 1.0.4
- gopd 1.2.0
- graphemer 1.4.0
- has-bigints 1.1.0
- has-flag 4.0.0
- has-property-descriptors 1.0.2
- has-proto 1.2.0
- has-symbols 1.1.0
- has-tostringtag 1.0.2
- hasown 2.0.3
- ignore 5.3.2
- ignore 7.0.5
- import-fresh 3.3.1
- imurmurhash 0.1.4
- internal-slot 1.1.0
- is-array-buffer 3.0.5
- is-async-function 2.1.1
- is-bigint 1.1.0
- is-binary-path 2.1.0
- is-boolean-object 1.2.2
- is-bun-module 2.0.0
- is-callable 1.2.7
- is-core-module 2.16.2
- is-data-view 1.0.2
- is-date-object 1.1.0
- is-extglob 2.1.1
- is-finalizationregistry 1.1.1
- is-fullwidth-code-point 3.0.0
- is-generator-function 1.1.2
- is-glob 4.0.3
- is-map 2.0.3
- is-negative-zero 2.0.3
- is-number 7.0.0
- is-number-object 1.1.1
- is-path-inside 3.0.3
- is-regex 1.2.1
- is-set 2.0.3
- is-shared-array-buffer 1.0.4
- is-string 1.1.1
- is-symbol 1.1.1
- is-typed-array 1.1.15
- is-weakmap 2.0.2
- is-weakref 1.1.1
- is-weakset 2.0.4
- isarray 2.0.5
- iterator.prototype 1.1.5
- jiti 1.21.7
- js-yaml 4.1.1
- json-buffer 3.0.1
- json-schema-traverse 0.4.1
- json-stable-stringify-without-jsonify 1.0.1
- json5 1.0.2
- jsx-ast-utils 3.3.5
- keyv 4.5.4
- language-tags 1.0.9
- levn 0.4.1
- lilconfig 3.1.3
- lines-and-columns 1.2.4
- ljharb-monorepo-symlink-test 0.0.0
- locate-path 5.0.0
- locate-path 6.0.0
- lodash.merge 4.6.2
- loupe 3.2.1
- magic-string 0.30.21
- math-intrinsics 1.1.0
- merge2 1.4.1
- micromatch 4.0.8
- minimist 1.2.8
- ms 2.1.3
- mz 2.7.0
- napi-postinstall 0.3.4
- natural-compare 1.4.0
- node-exports-info 1.6.0
- node-releases 2.0.44
- normalize-path 3.0.0
- object-hash 3.0.0
- object-inspect 1.13.4
- object-keys 1.1.1
- object.assign 4.1.7
- object.entries 1.1.9
- object.fromentries 2.0.8
- object.groupby 1.0.3
- object.values 1.2.1
- optionator 0.9.4
- own-keys 1.0.1
- p-limit 2.3.0
- p-limit 3.1.0
- p-locate 4.1.0
- p-locate 5.0.0
- p-try 2.2.0
- parent-module 1.0.1
- path-exists 4.0.0
- path-is-absolute 1.0.1
- path-key 3.1.1
- path-parse 1.0.7
- pathe 1.1.2
- pathval 2.0.1
- picomatch 2.3.2
- picomatch 4.0.4
- pify 2.3.0
- pirates 4.0.7
- pngjs 5.0.0
- possible-typed-array-names 1.1.0
- postcss-import 15.1.0
- postcss-js 4.1.0
- postcss-load-config 6.0.1
- postcss-nested 6.2.0
- postcss-selector-parser 6.1.2
- postcss-value-parser 4.2.0
- prelude-ls 1.2.1
- punycode 2.3.1
- qrcode 1.5.4
- queue-microtask 1.2.3
- react-refresh 0.12.0
- read-cache 1.0.0
- readdirp 3.6.0
- reflect.getprototypeof 1.0.10
- regenerator-runtime 0.13.4
- regexp.prototype.flags 1.5.4
- require-directory 2.1.1
- resolve 1.22.12
- resolve 2.0.0-next.6
- resolve-from 4.0.0
- resolve-pkg-maps 1.0.0
- reusify 1.1.0
- rollup 4.62.2
- run-parallel 1.2.0
- safe-array-concat 1.1.4
- safe-push-apply 1.0.0
- safe-regex-test 1.1.0
- scheduler 0.28.0
- server-only 0.0.1
- set-function-length 1.2.2
- set-function-name 2.0.2
- set-proto 1.0.0
- shebang-command 2.0.0
- shebang-regex 3.0.0
- side-channel 1.1.0
- side-channel-list 1.0.1
- side-channel-map 1.0.1
- side-channel-weakmap 1.0.2
- stable-hash 0.0.5
- stackback 0.0.2
- std-env 3.10.0
- stop-iteration-iterator 1.1.0
- string-width 4.2.3
- string.prototype.includes 2.0.1
- string.prototype.matchall 4.0.12
- string.prototype.repeat 1.0.0
- string.prototype.trim 1.2.10
- string.prototype.trimend 1.0.9
- string.prototype.trimstart 1.0.8
- strip-ansi 6.0.1
- strip-bom 3.0.0
- strip-json-comments 3.1.1
- sucrase 3.35.1
- supports-color 7.2.0
- supports-preserve-symlinks-flag 1.0.0
- tailwindcss 3.4.19
- text-table 0.2.0
- thenify 3.3.1
- thenify-all 1.6.0
- tinybench 2.9.0
- tinyexec 0.3.2
- tinyglobby 0.2.16
- tinypool 1.1.1
- tinyrainbow 1.2.0
- tinyspy 3.0.2
- to-regex-range 5.0.1
- ts-api-utils 2.5.0
- tsconfig-paths 3.15.0
- type-check 0.4.0
- typed-array-buffer 1.0.3
- typed-array-byte-length 1.0.3
- typed-array-byte-offset 1.0.4
- typed-array-length 1.0.7
- unbox-primitive 1.1.0
- undici-types 6.21.0
- unrs-resolver 1.11.1
- update-browserslist-db 1.2.3
- util-deprecate 1.0.2
- vite 5.4.21
- vite-node 2.1.9
- vitest 2.1.9
- which-boxed-primitive 1.1.1
- which-builtin-type 1.2.1
- which-collection 1.0.2
- which-typed-array 1.1.20
- why-is-node-running 2.3.0
- word-wrap 1.2.5
- wrap-ansi 6.2.0
- yargs 15.4.1
- yocto-queue 0.1.0

### ISC — 27 component(s)
- @ungap/structured-clone 1.3.1
- anymatch 3.1.3
- cliui 6.0.0
- electron-to-chromium 1.5.354
- eslint-import-resolver-typescript 3.10.1
- fastq 1.20.1
- flatted 3.4.2
- fs.realpath 1.0.0
- get-caller-file 2.0.5
- glob 7.2.3
- glob-parent 5.1.2
- glob-parent 6.0.2
- inflight 1.0.6
- inherits 2.0.4
- isexe 2.0.0
- minimatch 3.1.5
- mylib 0.0.0
- once 1.4.0
- require-main-filename 2.0.0
- rimraf 3.0.2
- set-blocking 2.0.0
- siginfo 2.0.0
- which 2.0.2
- which-module 2.0.1
- wrappy 1.0.2
- y18n 4.0.3
- yargs-parser 18.1.3

### Apache-2.0 — 13 component(s)
- @humanwhocodes/config-array 0.13.0
- @humanwhocodes/module-importer 1.0.1
- aria-query 5.3.2
- axobject-query 4.1.0
- baseline-browser-mapping 2.10.29
- didyoumean 1.2.2
- doctrine 2.1.0
- doctrine 3.0.0
- eslint-visitor-keys 3.4.3
- eslint-visitor-keys 5.0.1
- expect-type 1.4.0
- ts-interface-checker 0.1.13
- typescript 5.9.3

### BSD-2-Clause — 7 component(s)
- damerau-levenshtein 1.0.8
- eslint-scope 7.2.2
- espree 9.6.1
- esrecurse 4.3.0
- estraverse 5.3.0
- esutils 2.0.3
- uri-js 4.4.1

### BSD-3-Clause — 2 component(s)
- @humanwhocodes/object-schema 2.0.3
- esquery 1.7.0

### MPL-2.0 — 2 component(s)
- @vercel/og 0.7.2
- axe-core 4.11.4

### (MIT OR CC0-1.0) — 1 component(s)
- type-fest 0.20.2

### BlueOak-1.0.0 — 1 component(s)
- minimatch 10.2.5

### CC0-1.0 — 1 component(s)
- language-subtag-registry 0.3.23

### Python-2.0 — 1 component(s)
- argparse 2.0.1

