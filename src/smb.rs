//! SMB session layer built on `smb2-client`, plus MSRPC enumeration via the
//! high-level `dcerpc` clients (SRVSVC shares/sessions, SAMR users, WKSSVC
//! logged-on users).
//!
//! All protocol errors from the underlying crates are flattened into
//! `anyhow::Error` with context so the orchestrator can record them per-section.

use crate::output::{GroupInfo, OsInfo, PasswordPolicy, ShareInfo, UserInfo};
use crate::samr_ext;
use anyhow::{Result, anyhow};
use dcerpc::samr::SamrClient;
use dcerpc::srvsvc::SrvsvcClient;
use dcerpc::transport::SmbPipe;
use dcerpc::wkssvc::WkstaUserClient;
use smb2_client::SmbClient;
use std::time::Duration;
use tokio::time::timeout;

/// Run `fut`, converting an elapsed timeout into an `anyhow` error labelled `what`.
async fn with_timeout<T>(
    dur: Duration,
    what: &str,
    fut: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    match timeout(dur, fut).await {
        Ok(r) => r,
        Err(_) => Err(anyhow!("{what} timed out after {}s", dur.as_secs())),
    }
}

/// Ensure `host` carries an explicit port; default to 445 (direct SMB).
fn with_port(host: &str) -> String {
    if host.starts_with('[') {
        // Bracketed IPv6: "[::1]" (no port) or "[::1]:445" (port present).
        if host.contains("]:") { host.to_string() } else { format!("{host}:445") }
    } else {
        match host.matches(':').count() {
            // host or ipv4, no port.
            0 => format!("{host}:445"),
            // Exactly one colon: "host:port".
            1 => host.to_string(),
            // Multiple colons: bare IPv6 literal, needs brackets + port.
            _ => format!("[{host}]:445"),
        }
    }
}

/// Strip any `:port` suffix to get the bare hostname used for NTLM target / UNC.
fn bare_host(host: &str) -> String {
    if host.starts_with('[') {
        // [ipv6]:port or [ipv6]
        if let Some(end) = host.find(']') {
            return host[1..end].to_string();
        }
    }
    // host:port (but not bare IPv6 with multiple colons)
    if host.matches(':').count() == 1 {
        if let Some((h, p)) = host.rsplit_once(':') {
            if p.parse::<u16>().is_ok() {
                return h.to_string();
            }
        }
    }
    host.to_string()
}

/// Translate an SMB2 dialect revision into a human string.
fn dialect_name(d: u16) -> String {
    match d {
        0x0202 => "SMB 2.0.2".into(),
        0x0210 => "SMB 2.1".into(),
        0x0300 => "SMB 3.0".into(),
        0x0302 => "SMB 3.0.2".into(),
        0x0311 => "SMB 3.1.1".into(),
        0x02FF => "SMB 2.? (wildcard)".into(),
        other => format!("unknown (0x{other:04x})"),
    }
}

/// An authenticated (or null) SMB session with the IPC$ tree connected.
pub struct SmbSession {
    client: SmbClient,
    /// Bare hostname used for the SAMR server argument.
    server: String,
    pub null_session: bool,
    /// Per-operation timeout.
    dur: Duration,
}

impl SmbSession {
    /// Probe the host for dialect + signing policy on a throwaway connection.
    /// This works even against hosts that refuse authentication.
    pub async fn probe_os(host: &str, timeout_secs: u64) -> Result<OsInfo> {
        let dur = Duration::from_secs(timeout_secs);
        let host = host.to_string();
        with_timeout(dur, "OS probe", async move {
            let mut c = SmbClient::connect(&with_port(&host))
                .await
                .map_err(|e| anyhow!("connect failed: {e}"))?;
            let (dialect, signing) = c
                .probe_signing()
                .await
                .map_err(|e| anyhow!("negotiate failed: {e}"))?;
            Ok(OsInfo {
                dialect: Some(dialect_name(dialect)),
                signing: Some(if signing { "required".into() } else { "not required".into() }),
                ..Default::default()
            })
        })
        .await
    }

    /// Open a session: null/anonymous if `user` and `pass` are both empty,
    /// otherwise an NTLM logon. The IPC$ tree is connected on success.
    pub async fn open(
        host: &str,
        user: &str,
        pass: &str,
        workgroup: &str,
        timeout_secs: u64,
    ) -> Result<Self> {
        let dur = Duration::from_secs(timeout_secs);
        let server = bare_host(host);
        let null_session = user.is_empty() && pass.is_empty();
        let (host, user, pass, workgroup, server2) = (
            host.to_string(),
            user.to_string(),
            pass.to_string(),
            workgroup.to_string(),
            server.clone(),
        );

        let client = with_timeout(dur, "SMB session setup", async move {
            let mut client = SmbClient::connect(&with_port(&host))
                .await
                .map_err(|e| anyhow!("connect failed: {e}"))?;
            if null_session {
                client
                    .login_null(&server2)
                    .await
                    .map_err(|e| anyhow!("null session rejected: {e}"))?;
            } else {
                client
                    .login(&server2, &workgroup, &user, &pass)
                    .await
                    .map_err(|e| anyhow!("authentication failed: {e}"))?;
            }
            client
                .tree_connect(&format!(r"\\{server2}\IPC$"))
                .await
                .map_err(|e| anyhow!("tree connect to IPC$ failed: {e}"))?;
            Ok(client)
        })
        .await?;

        Ok(SmbSession { client, server, null_session, dur })
    }

    /// Enumerate shares via SRVSVC NetrShareEnum (level 1).
    pub async fn shares(&mut self) -> Result<Vec<ShareInfo>> {
        let dur = self.dur;
        with_timeout(dur, "share enumeration", async {
            let fid = self
                .client
                .open_pipe("srvsvc")
                .await
                .map_err(|e| anyhow!("open \\srvsvc failed: {e}"))?;
            let mut cli = SrvsvcClient::bind(&mut self.client, fid)
                .await
                .map_err(|e| anyhow!("SRVSVC bind failed: {e}"))?;
            let (shares, _total) = cli
                .enum_shares()
                .await
                .map_err(|e| anyhow!("NetrShareEnum failed: {e}"))?;
            Ok(shares
                .into_iter()
                .map(|s| ShareInfo {
                    name: s.netname.clone(),
                    share_type: s.stype_label().to_string(),
                    comment: if s.remark.is_empty() { None } else { Some(s.remark.clone()) },
                    access: None,
                })
                .collect())
        })
        .await
    }

    /// Test read access to a share by attempting a tree connect.
    /// Returns "OK" if the connect succeeds, "DENIED" otherwise.
    pub async fn test_share_access(&mut self, share: &str) -> String {
        let unc = format!(r"\\{}\{}", self.server, share);
        match timeout(self.dur, self.client.tree_connect(&unc)).await {
            Ok(Ok(())) => {
                // Reconnect IPC$ so later pipe opens keep working.
                let _ = self.client.tree_connect(&format!(r"\\{}\IPC$", self.server)).await;
                "OK".into()
            }
            Ok(Err(_)) => "DENIED".into(),
            Err(_) => "TIMEOUT".into(),
        }
    }

    /// Enumerate domain users via SAMR (connect → enum domains → enum users).
    pub async fn users(&mut self) -> Result<Vec<UserInfo>> {
        let dur = self.dur;
        let server = self.server.clone();
        with_timeout(dur, "user enumeration", async {
            let fid = self
                .client
                .open_pipe("samr")
                .await
                .map_err(|e| anyhow!("open \\samr failed: {e}"))?;
            let mut cli = SamrClient::bind(&mut self.client, fid)
                .await
                .map_err(|e| anyhow!("SAMR bind failed: {e}"))?;
            let users = cli
                .enumerate_all_users(&server)
                .await
                .map_err(|e| anyhow!("SAMR EnumDomainUsers failed: {e}"))?;
            Ok(users
                .into_iter()
                .map(|(rid, name)| UserInfo { rid, name, ..Default::default() })
                .collect())
        })
        .await
    }

    /// Enumerate active sessions via SRVSVC NetrSessionEnum (level 10).
    /// Returns (client_computer, username) pairs.
    pub async fn sessions(&mut self) -> Result<Vec<(String, String)>> {
        let dur = self.dur;
        with_timeout(dur, "session enumeration", async {
            let fid = self
                .client
                .open_pipe("srvsvc")
                .await
                .map_err(|e| anyhow!("open \\srvsvc failed: {e}"))?;
            let mut cli = SrvsvcClient::bind(&mut self.client, fid)
                .await
                .map_err(|e| anyhow!("SRVSVC bind failed: {e}"))?;
            let (sessions, _total) = cli
                .enum_sessions()
                .await
                .map_err(|e| anyhow!("NetrSessionEnum failed: {e}"))?;
            Ok(sessions.into_iter().map(|s| (s.client, s.user)).collect())
        })
        .await
    }

    /// Enumerate logged-on users via WKSSVC NetrWkstaUserEnum (level 1).
    /// Returns (username, logon_domain) pairs.
    pub async fn logged_on_users(&mut self) -> Result<Vec<(String, String)>> {
        let dur = self.dur;
        with_timeout(dur, "logged-on user enumeration", async {
            let fid = self
                .client
                .open_pipe("wkssvc")
                .await
                .map_err(|e| anyhow!("open \\wkssvc failed: {e}"))?;
            let mut cli = WkstaUserClient::bind(&mut self.client, fid)
                .await
                .map_err(|e| anyhow!("WKSSVC bind failed: {e}"))?;
            let (users, _total) = cli
                .enum_users()
                .await
                .map_err(|e| anyhow!("NetrWkstaUserEnum failed: {e}"))?;
            Ok(users.into_iter().map(|u| (u.username, u.logon_domain)).collect())
        })
        .await
    }

    /// Query the domain password policy via raw SAMR (Phase 3b).
    pub async fn password_policy(&mut self) -> Result<PasswordPolicy> {
        let dur = self.dur;
        let server = self.server.clone();
        with_timeout(dur, "password policy", async {
            let fid = self
                .client
                .open_pipe("samr")
                .await
                .map_err(|e| anyhow!("open \\samr failed: {e}"))?;
            let mut pipe = SmbPipe::new(&mut self.client, fid);
            let dom = samr_ext::setup(&mut pipe, &server).await?;
            samr_ext::password_policy(&mut pipe, &dom).await
        })
        .await
    }

    /// Enumerate groups and aliases via raw SAMR (Phase 3b).
    pub async fn groups(&mut self) -> Result<Vec<GroupInfo>> {
        let dur = self.dur;
        let server = self.server.clone();
        with_timeout(dur, "group enumeration", async {
            let fid = self
                .client
                .open_pipe("samr")
                .await
                .map_err(|e| anyhow!("open \\samr failed: {e}"))?;
            let mut pipe = SmbPipe::new(&mut self.client, fid);
            let dom = samr_ext::setup(&mut pipe, &server).await?;
            samr_ext::enum_groups(&mut pipe, &dom).await
        })
        .await
    }

    /// RID cycling via SAMR LookupIdsInDomain (Phase 3b). Returns the domain SID
    /// alongside the resolved accounts.
    pub async fn rid_cycle(&mut self, rids: &[u32]) -> Result<(String, Vec<UserInfo>)> {
        let dur = self.dur;
        let server = self.server.clone();
        with_timeout(dur, "RID cycling", async {
            let fid = self
                .client
                .open_pipe("samr")
                .await
                .map_err(|e| anyhow!("open \\samr failed: {e}"))?;
            let mut pipe = SmbPipe::new(&mut self.client, fid);
            let dom = samr_ext::setup(&mut pipe, &server).await?;
            let users = samr_ext::rid_cycle(&mut pipe, &dom, rids).await?;
            Ok((dom.domain_sid, users))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_defaults() {
        assert_eq!(with_port("10.0.0.1"), "10.0.0.1:445");
        assert_eq!(with_port("host.example"), "host.example:445");
        assert_eq!(with_port("10.0.0.1:139"), "10.0.0.1:139");
    }

    #[test]
    fn bare_host_strips_port() {
        assert_eq!(bare_host("10.0.0.1:445"), "10.0.0.1");
        assert_eq!(bare_host("host.example"), "host.example");
        assert_eq!(bare_host("[::1]:445"), "::1");
    }

    #[test]
    fn dialects() {
        assert_eq!(dialect_name(0x0311), "SMB 3.1.1");
        assert_eq!(dialect_name(0x0202), "SMB 2.0.2");
        assert!(dialect_name(0x1234).contains("unknown"));
    }
}
