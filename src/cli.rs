//! Command-line interface, modelled on the original `enum4linux` options.

use clap::Parser;

/// enum4all — a native, cross-platform Rust port of enum4linux.
///
/// Enumerates information from SMB/NetBIOS hosts (Windows and Samba) without
/// requiring the Samba client tools. By default it performs a null session.
#[derive(Debug, Parser)]
#[command(name = "enum4all", version, about, long_about = None)]
pub struct Cli {
    /// Target host (IP address or hostname).
    pub target: String,

    /// Username for authentication (default: anonymous / null session).
    #[arg(short = 'u', long = "user", default_value = "")]
    pub user: String,

    /// Password for authentication (default: empty).
    #[arg(short = 'p', long = "pass", default_value = "")]
    pub pass: String,

    /// Workgroup / domain to use during authentication.
    #[arg(short = 'w', long = "workgroup", default_value = "")]
    pub workgroup: String,

    /// Do all simple enumeration (-U -S -G -P -o -n -i). This is the default
    /// when no other enumeration flag is given.
    #[arg(short = 'a', long = "all")]
    pub all: bool,

    /// Get userlist (SAMR EnumDomainUsers).
    #[arg(short = 'U', long = "users")]
    pub users: bool,

    /// Get sharelist (SRVSVC NetShareEnum) and test access.
    #[arg(short = 'S', long = "shares")]
    pub shares: bool,

    /// Get group and membership list (SAMR).
    #[arg(short = 'G', long = "groups")]
    pub groups: bool,

    /// Get password policy information (SAMR).
    #[arg(short = 'P', long = "pass-pol")]
    pub pass_pol: bool,

    /// Get OS information (SMB negotiate / session + SRVSVC server info).
    #[arg(short = 'o', long = "os")]
    pub os: bool,

    /// Do NetBIOS name-service lookup / node status (UDP 137).
    #[arg(short = 'n', long = "netbios")]
    pub netbios: bool,

    /// Get printer information (spoolss RpcEnumPrinters).
    #[arg(short = 'i', long = "printers")]
    pub printers: bool,

    /// Enumerate users via RID cycling (LSA LookupSids over a RID range).
    #[arg(short = 'r', long = "rid-cycle")]
    pub rid_cycle: bool,

    /// RID ranges to use for RID cycling (comma-separated, e.g. "500-550,1000-1050").
    #[arg(short = 'R', long = "rid-range", default_value = "500-550,1000-1050")]
    pub rid_range: String,

    /// UDP port for NetBIOS name service (default 137; override for testing).
    #[arg(long = "nbt-port", default_value_t = 137)]
    pub nbt_port: u16,

    /// Be detailed, applies to user and share enumeration.
    #[arg(short = 'd', long = "detail")]
    pub detail: bool,

    /// Emit machine-readable JSON instead of the human-readable report.
    #[arg(long = "json")]
    pub json: bool,

    /// Connection/response timeout in seconds.
    #[arg(short = 't', long = "timeout", default_value_t = 5)]
    pub timeout: u64,

    /// Verbose output (show protocol-level detail and errors).
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}

impl Cli {
    /// Whether this is an anonymous / null session (no credentials supplied).
    pub fn is_null_session(&self) -> bool {
        self.user.is_empty() && self.pass.is_empty()
    }

    /// Resolve which enumeration actions should run, applying the `-a`/default
    /// behaviour. Returns a copy with the individual flags set accordingly.
    pub fn resolved(mut self) -> Self {
        let any_specific = self.users
            || self.shares
            || self.groups
            || self.pass_pol
            || self.os
            || self.netbios
            || self.printers
            || self.rid_cycle;

        // `-a`, or no specific flag at all, means "do the simple set".
        if self.all || !any_specific {
            self.users = true;
            self.shares = true;
            self.groups = true;
            self.pass_pol = true;
            self.os = true;
            self.netbios = true;
            self.printers = true;
            // RID cycling is intentionally NOT part of `-a` in enum4linux.
        }
        self
    }
}

/// Parse one or more RID ranges like "500-550,1000-1050,1337" into a flat,
/// de-duplicated, sorted list of RIDs.
pub fn parse_rid_ranges(spec: &str) -> anyhow::Result<Vec<u32>> {
    use anyhow::{Context, bail};
    let mut rids: Vec<u32> = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if let Some((lo, hi)) = part.split_once('-') {
            let lo: u32 = lo
                .trim()
                .parse()
                .with_context(|| format!("invalid RID '{lo}'"))?;
            let hi: u32 = hi
                .trim()
                .parse()
                .with_context(|| format!("invalid RID '{hi}'"))?;
            if lo > hi {
                bail!("RID range '{part}' is reversed (low > high)");
            }
            if hi - lo > 1_000_000 {
                bail!("RID range '{part}' is unreasonably large");
            }
            rids.extend(lo..=hi);
        } else {
            let rid: u32 = part
                .parse()
                .with_context(|| format!("invalid RID '{part}'"))?;
            rids.push(rid);
        }
    }
    rids.sort_unstable();
    rids.dedup();
    Ok(rids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_range() {
        assert_eq!(
            parse_rid_ranges("500-503").unwrap(),
            vec![500, 501, 502, 503]
        );
    }

    #[test]
    fn parse_multi_range_and_singletons() {
        let got = parse_rid_ranges("1000-1002, 500 ,1337").unwrap();
        assert_eq!(got, vec![500, 1000, 1001, 1002, 1337]);
    }

    #[test]
    fn dedup_overlap() {
        assert_eq!(
            parse_rid_ranges("500-502,501-503").unwrap(),
            vec![500, 501, 502, 503]
        );
    }

    #[test]
    fn reversed_range_errors() {
        assert!(parse_rid_ranges("550-500").is_err());
    }

    #[test]
    fn bad_input_errors() {
        assert!(parse_rid_ranges("abc").is_err());
    }
}
