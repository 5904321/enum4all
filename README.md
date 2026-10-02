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

All features below are **verified live against a Samba server**.

| Feature                            | Flag | Mechanism                                        |
|------------------------------------|------|--------------------------------------------------|
| NetBIOS node status                | `-n` | Native NBNS over UDP/137                          |
| OS / dialect / signing             | `-o` | SMB2 NEGOTIATE probe + SRVSVC `NetrServerGetInfo` |
| Null-session detection             |      | `smb2-client` anonymous logon                    |
| Share enumeration (+ access test)  | `-S` | SRVSVC `NetrShareEnum`                            |
| User enumeration                   | `-U` | SAMR `EnumDomainUsers`                            |
| Active sessions                    |      | SRVSVC `NetrSessionEnum`                          |
| Logged-on users                    |      | WKSSVC `NetrWkstaUserEnum`                        |
| Groups + aliases + **members**     | `-G` | SAMR `EnumGroups`/`EnumAliases` + `GetMembers*`   |
| Password policy (incl. lockout)    | `-P` | SAMR `QueryInformationDomain` (classes 1 + 12)    |
| RID cycling (account + Builtin)    | `-r` | SAMR `LookupIdsInDomain` over a range             |
| Printer enumeration                | `-i` | spoolss `RpcEnumPrinters` (level 1)               |

The `-G`/`-P`/`-r`/`-i` paths are implemented with raw NDR opnum marshaling (in
[`src/samr_ext.rs`](src/samr_ext.rs), [`src/srvsvc_ext.rs`](src/srvsvc_ext.rs),
[`src/rprn_ext.rs`](src/rprn_ext.rs)) since the high-level crate clients don't
expose them; their decoders have synthetic-buffer unit tests and were confirmed
against live Samba output. Groups, aliases and RID cycling cover both the
account domain and the Builtin domain (S-1-5-32).

Anonymous (null-session) enumeration is implemented and works against targets
that permit it; modern Samba/Windows that disable anonymous IPC$ return
`STATUS_ACCESS_DENIED`, as expected — supply credentials with `-u`/`-p` there.

## Architecture

```
src/
  main.rs      orchestration + human/JSON reporting
  cli.rs       clap argument parsing (enum4linux-compatible flags)
  output.rs    structured Report (serde) + sectioned printing
  netbios.rs   hand-written NetBIOS Name Service client (UDP/137)
  smb.rs       SMB session + MSRPC enumeration (high-level clients)
  samr_ext.rs  raw SAMR opnums: password policy, groups+members, RID cycling
  srvsvc_ext.rs raw SRVSVC NetrServerGetInfo (OS/server details)
  rprn_ext.rs  raw spoolss RpcEnumPrinters (printer enumeration)
```

Built on the pure-Rust ["icedracon" offensive-AD crates](https://github.com/icedracon/dcerpc):

- [`smb2-client`](https://crates.io/crates/smb2-client) — SMB2/3 negotiate, NTLMv2 session setup, signing
- [`dcerpc`](https://crates.io/crates/dcerpc) — DCE/RPC over named pipes + SRVSVC / SAMR / LSAT / WKSSVC clients

## Status / caveats

- **Verified live.** Every feature was validated against a Samba server
  (users, shares, groups+members across both domains, password policy with
  lockout, RID cycling, server info, printers, and NetBIOS node status against
  real `nmbd`). Decoders also have synthetic-buffer unit tests.
- The underlying RPC crates are young (0.1–0.2.x). Field orders for the NDR
  unions (password/lockout info, server info) were corrected against live wire
  captures; behaviour against Windows (vs. Samba) may differ in edge cases.
- Per-operation timeouts bound every network call (`-t`, default 5s).

## License

MIT
