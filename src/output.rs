//! Output helpers: human-readable sectioned reporting plus a structured
//! [`Report`] that can be serialized to JSON for machine consumption.

use serde::Serialize;
use std::collections::BTreeMap;

/// Print a top-level banner/section header, enum4linux style.
pub fn section(title: &str) {
    println!();
    println!("{}", "=".repeat(title.len() + 8));
    println!("|   {title}   |");
    println!("{}", "=".repeat(title.len() + 8));
}

/// Print an informational line.
pub fn info(msg: impl AsRef<str>) {
    println!("[*] {}", msg.as_ref());
}

/// Print a positive/finding line.
pub fn good(msg: impl AsRef<str>) {
    println!("[+] {}", msg.as_ref());
}

/// Print a warning line.
pub fn warn(msg: impl AsRef<str>) {
    eprintln!("[!] {}", msg.as_ref());
}

/// Print an error line.
pub fn error(msg: impl AsRef<str>) {
    eprintln!("[-] {}", msg.as_ref());
}

/// A discovered SMB share.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ShareInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub share_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Result of attempting to connect (e.g. "OK", "DENIED", "N/A").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
}

/// A user account (from SAMR enumeration or RID cycling).
#[derive(Debug, Clone, Serialize, Default)]
pub struct UserInfo {
    pub rid: u32,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
}

/// A group or alias plus its members.
#[derive(Debug, Clone, Serialize, Default)]
pub struct GroupInfo {
    pub rid: u32,
    pub name: String,
    #[serde(rename = "type")]
    pub group_type: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
}

/// Domain password policy.
#[derive(Debug, Clone, Serialize, Default)]
pub struct PasswordPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history_length: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age_days: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_age_days: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub complexity: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lockout_threshold: Option<u32>,
}

/// OS / server information gathered from the SMB layer and SRVSVC.
#[derive(Debug, Clone, Serialize, Default)]
pub struct OsInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dialect: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub computer_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing: Option<String>,
}

/// A NetBIOS node-status entry.
#[derive(Debug, Clone, Serialize, Default)]
pub struct NetbiosName {
    pub name: String,
    pub suffix: u8,
    #[serde(rename = "type")]
    pub kind: String,
    pub flags: String,
}

/// The full enumeration result for one target.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Report {
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub null_session: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_info: Option<OsInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub netbios: Vec<NetbiosName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workgroup: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shares: Vec<ShareInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<UserInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<GroupInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password_policy: Option<PasswordPolicy>,
    /// Non-fatal errors encountered per section, for diagnostics.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub errors: BTreeMap<String, String>,
}

impl Report {
    pub fn new(target: impl Into<String>) -> Self {
        Report { target: target.into(), ..Default::default() }
    }

    /// Record a non-fatal, per-section error.
    pub fn note_error(&mut self, section: impl Into<String>, msg: impl Into<String>) {
        self.errors.insert(section.into(), msg.into());
    }

    /// Serialize to pretty JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }
}
