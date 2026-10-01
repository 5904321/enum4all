# enum4mac

A native, self-contained **macOS/Rust port of [enum4linux](https://github.com/CiscoCXSecurity/enum4linux)**.

The original `enum4linux` is a Perl wrapper around the Samba client tools
(`smbclient`, `rpcclient`, `nmblookup`, `net`). macOS ships none of those, and
Perl is deprecated on the platform. `enum4mac` reimplements the enumeration
directly over SMB2/3 and MSRPC in pure Rust, so it runs as a **single binary
with no external dependencies** — no Samba install required.

> **Authorized use only.** This is a security-testing tool. Only run it against
> hosts you own or have explicit written permission to test.

## Install / build

```bash
cargo build --release
./target/release/enum4mac --help
```

## Usage

```bash
# Default: null session, runs the "simple" set (-U -S -G -P -o -n)
enum4mac 10.0.0.5

# Authenticated
enum4mac -u alice -p 'P@ssw0rd' -w CORP 10.0.0.5

# Just shares, with access testing
enum4mac -S -d 10.0.0.5

# Machine-readable output
enum4mac --json 10.0.0.5
```

Flags mirror the original `enum4linux` where possible (`-U -S -G -P -o -n -r -a`,
`-u/-p/-w`, `-R`, `-d`). See `enum4mac --help` for the full list.

## Feature status

| Feature                         | Flag | Status        | Mechanism                              |
|---------------------------------|------|---------------|----------------------------------------|
| NetBIOS node status             | `-n` | ✅ Implemented | Native NBNS over UDP/137               |
| OS / dialect / signing info     | `-o` | ✅ Implemented | SMB2 NEGOTIATE probe                   |
| Null-session detection          |      | ✅ Implemented | `smb2-client` anonymous logon          |
| Share enumeration (+ access)    | `-S` | ✅ Implemented | SRVSVC `NetrShareEnum`                 |
| User enumeration                | `-U` | ✅ Implemented | SAMR `EnumDomainUsers`                 |
| Active sessions                 |      | ✅ Implemented | SRVSVC `NetrSessionEnum`               |
| Logged-on users                 |      | ✅ Implemented | WKSSVC `NetrWkstaUserEnum`             |
| Group + member enumeration      | `-G` | 🚧 Planned     | SAMR `EnumDomainGroups`/`GetMembers`   |
| Password policy                 | `-P` | 🚧 Planned     | SAMR `QueryInformationDomain`          |
| RID cycling                     | `-r` | 🚧 Planned     | LSA `LsarLookupSids` over a RID range  |

The planned items require raw NDR opnum marshaling (not covered by the
high-level crate clients) and are the subject of the next phase.

## Architecture

```
src/
  main.rs      orchestration + human/JSON reporting
  cli.rs       clap argument parsing (enum4linux-compatible flags)
  output.rs    structured Report (serde) + sectioned printing
  netbios.rs   hand-written NetBIOS Name Service client (UDP/137)
  smb.rs       SMB session + MSRPC enumeration
```

Built on the pure-Rust ["icedracon" offensive-AD crates](https://github.com/icedracon/dcerpc):

- [`smb2-client`](https://crates.io/crates/smb2-client) — SMB2/3 negotiate, NTLMv2 session setup, signing
- [`dcerpc`](https://crates.io/crates/dcerpc) — DCE/RPC over named pipes + SRVSVC / SAMR / LSAT / WKSSVC clients

## Status / caveats

- **Verification pending against a live host.** The NetBIOS layer and all
  parsing/CLI logic are unit-tested, and the whole tool compiles and runs
  end-to-end with correct timeout/error handling. The MSRPC paths are written
  against the crate APIs but have **not yet been validated against a real SMB
  server** — do that before relying on the output.
- The underlying RPC crates are young (0.1–0.2.x); behaviour on hardened
  (2019+) Windows DCs that block anonymous access will be "session rejected",
  as expected.

## License

MIT
