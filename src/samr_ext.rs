//! Extended SAMR operations not covered by the high-level `dcerpc::samr`
//! client: password policy (QueryInformationDomain), group/alias enumeration,
//! and RID cycling (LookupIdsInDomain).
//!
//! These are implemented with raw NDR marshaling against
//! `dcerpc::transport::SmbPipe`, reusing the crate's public `encode_*`/`decode_*`
//! helpers where the wire shapes match (SAMPR_RID_ENUMERATION).
//!
//! ⚠️ Written against the MS-SAMR spec and **not yet verified against a live
//! host**. The decoders are exercised by synthetic-buffer unit tests that
//! encode the author's understanding of the wire format.

use crate::output::{GroupInfo, PasswordPolicy, UserInfo};
use anyhow::{Result, anyhow, bail};
use dcerpc::ndr::{NdrDecoder, NdrEncoder};
use dcerpc::samr::{
    SamrHandle, access, decode_enum_domains, decode_lookup_domain, encode_connect2,
    encode_enum_domains, encode_lookup_domain, encode_open_domain, opnum, samr_syntax,
};
use dcerpc::transport::SmbPipe;

/// Opnums beyond those exposed by `dcerpc::samr::opnum`.
mod ext_opnum {
    pub const QUERY_INFO_DOMAIN: u16 = 8;
    pub const ENUM_GROUPS: u16 = 11;
    pub const ENUM_ALIASES: u16 = 15;
    pub const LOOKUP_IDS: u16 = 18;
    pub const OPEN_GROUP: u16 = 19;
    pub const GET_MEMBERS_IN_GROUP: u16 = 25;
    pub const OPEN_ALIAS: u16 = 27;
    pub const GET_MEMBERS_IN_ALIAS: u16 = 33;
}

const STATUS_MORE_ENTRIES: u32 = 0x0000_0105;
const STATUS_SOME_NOT_MAPPED: u32 = 0x0000_0107;
const STATUS_NONE_MAPPED: u32 = 0xC000_0073;

/// DomainPasswordInformation info class.
const DOMAIN_PASSWORD_INFORMATION: u16 = 1;

/// Read the trailing NTSTATUS from an RPC response stub (last 4 bytes, LE).
/// (`dcerpc`'s own `required_tail_u32` is `pub(crate)`, so we reimplement it.)
fn tail_status(stub: &[u8]) -> Result<u32> {
    let n = stub.len();
    if n < 4 {
        bail!("RPC response too short ({n} bytes)");
    }
    Ok(u32::from_le_bytes([stub[n - 4], stub[n - 3], stub[n - 2], stub[n - 1]]))
}

/// Format a SID from its components as `S-R-A[-sub...]`.
fn sid_string(revision: u8, authority: u64, subs: &[u32]) -> String {
    let mut s = format!("S-{revision}-{authority}");
    for sub in subs {
        s.push('-');
        s.push_str(&sub.to_string());
    }
    s
}

/// Human label for a SID_NAME_USE value.
fn sid_name_use(use_val: u32) -> &'static str {
    match use_val {
        1 => "User",
        2 => "Group",
        3 => "Domain",
        4 => "Alias",
        5 => "WellKnownGroup",
        6 => "DeletedAccount",
        7 => "Invalid",
        9 => "Computer",
        10 => "Label",
        _ => "Unknown",
    }
}

/// Handles + identifiers for the opened SAM domains.
pub struct SamrDomain {
    /// Server handle from Connect2 (retained for completeness / future handle close).
    #[allow(dead_code)]
    pub server: SamrHandle,
    /// Account (primary) domain handle + name + SID.
    pub account: SamrHandle,
    pub account_name: String,
    pub domain_sid: String,
    /// Builtin domain (S-1-5-32) handle + SID, if present.
    pub builtin: Option<SamrHandle>,
    pub builtin_sid: Option<String>,
}

/// Bind SAMR on the pipe, connect, and open both the account (non-"Builtin")
/// domain and, when present, the Builtin domain. Shared setup for every
/// extended operation.
pub async fn setup(pipe: &mut SmbPipe<'_>, server_name: &str) -> Result<SamrDomain> {
    pipe.bind(samr_syntax()).await.map_err(|e| anyhow!("SAMR bind failed: {e}"))?;

    // Connect2 → server handle.
    let resp = pipe
        .call(opnum::CONNECT2, &encode_connect2(server_name, access::MAXIMUM_ALLOWED))
        .await
        .map_err(|e| anyhow!("SamrConnect2 failed: {e}"))?;
    let st = tail_status(&resp)?;
    if st != 0 {
        bail!("SamrConnect2 failed (NTSTATUS 0x{st:08x})");
    }
    let mut d = NdrDecoder::new(&resp);
    let server = SamrHandle::decode(&mut d).map_err(|e| anyhow!("decode server handle: {e}"))?;

    // Enumerate SAM domains (typically Builtin + the account domain).
    let resp = pipe
        .call(opnum::ENUM_DOMAINS, &encode_enum_domains(&server, 0, 0x1000))
        .await
        .map_err(|e| anyhow!("SamrEnumerateDomains failed: {e}"))?;
    let (_next, domains) =
        decode_enum_domains(&resp).map_err(|e| anyhow!("decode domains: {e}"))?;
    let names: Vec<String> = domains.into_iter().map(|(_, n)| n).collect();
    let account_name = names
        .iter()
        .find(|n| !n.eq_ignore_ascii_case("Builtin"))
        .cloned()
        .ok_or_else(|| anyhow!("no account domain found"))?;

    let (account, domain_sid) = open_domain_by_name(pipe, &server, &account_name).await?;

    let (builtin, builtin_sid) = if names.iter().any(|n| n.eq_ignore_ascii_case("Builtin")) {
        match open_domain_by_name(pipe, &server, "Builtin").await {
            Ok((h, sid)) => (Some(h), Some(sid)),
            Err(_) => (None, None),
        }
    } else {
        (None, None)
    };

    Ok(SamrDomain { server, account, account_name, domain_sid, builtin, builtin_sid })
}

/// Look up a domain by name and open it, returning (handle, SID string).
async fn open_domain_by_name(
    pipe: &mut SmbPipe<'_>,
    server: &SamrHandle,
    name: &str,
) -> Result<(SamrHandle, String)> {
    let resp = pipe
        .call(opnum::LOOKUP_DOMAIN, &encode_lookup_domain(server, name))
        .await
        .map_err(|e| anyhow!("SamrLookupDomain({name}) failed: {e}"))?;
    let sid = decode_lookup_domain(&resp).map_err(|e| anyhow!("decode {name} SID: {e}"))?;
    let sid_str = sid_string(sid.revision, sid.identifier_authority, &sid.sub_authorities);

    let resp = pipe
        .call(opnum::OPEN_DOMAIN, &encode_open_domain(server, access::MAXIMUM_ALLOWED, &sid))
        .await
        .map_err(|e| anyhow!("SamrOpenDomain({name}) failed: {e}"))?;
    let st = tail_status(&resp)?;
    if st != 0 {
        bail!("SamrOpenDomain({name}) failed (NTSTATUS 0x{st:08x})");
    }
    let mut d = NdrDecoder::new(&resp);
    let handle = SamrHandle::decode(&mut d).map_err(|e| anyhow!("decode {name} handle: {e}"))?;
    Ok((handle, sid_str))
}

/// Enumerate groups (opnum 11) and aliases (opnum 15) — with members — across
/// both the account domain and the Builtin domain.
pub async fn enum_groups(pipe: &mut SmbPipe<'_>, dom: &SamrDomain) -> Result<Vec<GroupInfo>> {
    let mut out = Vec::new();

    // (label, &handle) for each domain to walk.
    let mut targets: Vec<(String, SamrHandle)> = vec![(dom.account_name.clone(), dom.account)];
    if let Some(b) = &dom.builtin {
        targets.push(("BUILTIN".to_string(), *b));
    }

    for (label, handle) in targets {
        // Global groups → members are RIDs in this domain.
        let groups = enum_rid_named(pipe, &handle, ext_opnum::ENUM_GROUPS, "SamrEnumerateGroupsInDomain")
            .await
            .unwrap_or_default();
        for (rid, name) in groups {
            let members = group_members(pipe, &handle, rid).await.unwrap_or_default();
            out.push(GroupInfo {
                rid,
                name: format!("{label}\\{name}"),
                group_type: "group".into(),
                members,
            });
        }

        // Aliases (local groups) → members are SIDs (possibly cross-domain).
        let aliases = enum_rid_named(pipe, &handle, ext_opnum::ENUM_ALIASES, "SamrEnumerateAliasesInDomain")
            .await
            .unwrap_or_default();
        for (rid, name) in aliases {
            let members = alias_members(pipe, dom, &handle, rid).await.unwrap_or_default();
            out.push(GroupInfo {
                rid,
                name: format!("{label}\\{name}"),
                group_type: "alias".into(),
                members,
            });
        }
    }
    Ok(out)
}

/// Open a group/alias sub-handle: request is DomainHandle + DesiredAccess + Rid.
async fn open_sub(
    pipe: &mut SmbPipe<'_>,
    domain: &SamrHandle,
    op: u16,
    rid: u32,
) -> Result<SamrHandle> {
    let mut e = NdrEncoder::new();
    domain.encode(&mut e);
    e.u32(access::MAXIMUM_ALLOWED);
    e.u32(rid);
    let resp = pipe.call(op, &e.into_bytes()).await.map_err(|e| anyhow!("open(rid {rid}): {e}"))?;
    let st = tail_status(&resp)?;
    if st != 0 {
        bail!("open(rid {rid}) failed (NTSTATUS 0x{st:08x})");
    }
    let mut d = NdrDecoder::new(&resp);
    SamrHandle::decode(&mut d).map_err(|e| anyhow!("decode sub-handle: {e}"))
}

/// Resolve the members of a global group: OpenGroup + GetMembersInGroup → RIDs,
/// then LookupIdsInDomain on the same domain.
async fn group_members(
    pipe: &mut SmbPipe<'_>,
    domain: &SamrHandle,
    group_rid: u32,
) -> Result<Vec<String>> {
    let gh = open_sub(pipe, domain, ext_opnum::OPEN_GROUP, group_rid).await?;
    let mut e = NdrEncoder::new();
    gh.encode(&mut e);
    let resp = pipe
        .call(ext_opnum::GET_MEMBERS_IN_GROUP, &e.into_bytes())
        .await
        .map_err(|e| anyhow!("GetMembersInGroup: {e}"))?;
    let st = tail_status(&resp)?;
    if st != 0 {
        bail!("GetMembersInGroup failed (NTSTATUS 0x{st:08x})");
    }
    let rids = decode_member_rids(&resp)?;
    if rids.is_empty() {
        return Ok(Vec::new());
    }
    let resolved = lookup_ids(pipe, domain, &rids).await.unwrap_or_default();
    Ok(resolved.into_iter().filter(|(_, n, _)| !n.is_empty()).map(|(_, n, _)| n).collect())
}

/// Decode SAMPR_GET_MEMBERS_BUFFER → member RIDs (attributes skipped).
fn decode_member_rids(stub: &[u8]) -> Result<Vec<u32>> {
    let mut d = NdrDecoder::new(stub);
    let buf_ref = d.u32().map_err(|e| anyhow!("members buf ref: {e}"))?;
    if buf_ref == 0 {
        return Ok(Vec::new());
    }
    let count = d.u32().map_err(|e| anyhow!("member count: {e}"))? as usize;
    let members_ref = d.u32().map_err(|e| anyhow!("members ref: {e}"))?;
    let _attrs_ref = d.u32().map_err(|e| anyhow!("attrs ref: {e}"))?;
    let mut rids = Vec::new();
    if members_ref != 0 {
        let _max = d.u32().map_err(|e| anyhow!("members max: {e}"))?;
        for _ in 0..count {
            rids.push(d.u32().map_err(|e| anyhow!("member rid: {e}"))?);
        }
    }
    Ok(rids)
}

/// Resolve the members of an alias: OpenAlias + GetMembersInAlias → SIDs, then
/// resolve each SID to a name when it belongs to a known (account/Builtin)
/// domain, otherwise keep the raw SID string.
async fn alias_members(
    pipe: &mut SmbPipe<'_>,
    dom: &SamrDomain,
    domain: &SamrHandle,
    alias_rid: u32,
) -> Result<Vec<String>> {
    let ah = open_sub(pipe, domain, ext_opnum::OPEN_ALIAS, alias_rid).await?;
    let mut e = NdrEncoder::new();
    ah.encode(&mut e);
    let resp = pipe
        .call(ext_opnum::GET_MEMBERS_IN_ALIAS, &e.into_bytes())
        .await
        .map_err(|e| anyhow!("GetMembersInAlias: {e}"))?;
    let st = tail_status(&resp)?;
    if st != 0 {
        bail!("GetMembersInAlias failed (NTSTATUS 0x{st:08x})");
    }
    let sids = decode_sid_array(&resp)?;

    let mut out = Vec::new();
    for sid in sids {
        out.push(resolve_member_sid(pipe, dom, &sid).await);
    }
    Ok(out)
}

/// Decode SAMPR_PSID_ARRAY → a list of SID strings.
fn decode_sid_array(stub: &[u8]) -> Result<Vec<String>> {
    let mut d = NdrDecoder::new(stub);
    let count = d.u32().map_err(|e| anyhow!("sid array count: {e}"))? as usize;
    let arr_ref = d.u32().map_err(|e| anyhow!("sid array ref: {e}"))?;
    if arr_ref == 0 || count == 0 {
        return Ok(Vec::new());
    }
    let _max = d.u32().map_err(|e| anyhow!("sid array max: {e}"))?;
    // Array of SAMPR_SID_INFORMATION — each a single PRPC_SID referent.
    let mut refs = Vec::with_capacity(count);
    for _ in 0..count {
        refs.push(d.u32().map_err(|e| anyhow!("sid ptr: {e}"))?);
    }
    let mut out = Vec::with_capacity(count);
    for r in refs {
        if r == 0 {
            continue;
        }
        // RPC_SID: max_count, revision, sub_count, 6-byte authority, sub-authorities.
        let _max = d.u32().map_err(|e| anyhow!("sid max: {e}"))?;
        let revision = d.u8().map_err(|e| anyhow!("sid revision: {e}"))?;
        let sub_count = d.u8().map_err(|e| anyhow!("sid subcount: {e}"))? as usize;
        let auth_bytes = d.read_bytes(6).map_err(|e| anyhow!("sid authority: {e}"))?;
        let authority = auth_bytes.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
        let mut subs = Vec::with_capacity(sub_count);
        for _ in 0..sub_count {
            subs.push(d.u32().map_err(|e| anyhow!("sid sub: {e}"))?);
        }
        out.push(sid_string(revision, authority, &subs));
    }
    Ok(out)
}

/// Resolve an alias member SID to `DOMAIN\name` when it belongs to the account
/// or Builtin domain; otherwise return the SID string unchanged.
async fn resolve_member_sid(pipe: &mut SmbPipe<'_>, dom: &SamrDomain, sid: &str) -> String {
    // Try account domain, then Builtin.
    if let Some(rid) = rid_within(sid, &dom.domain_sid) {
        if let Ok(v) = lookup_ids(pipe, &dom.account, &[rid]).await {
            if let Some((_, name, _)) = v.into_iter().find(|(_, n, _)| !n.is_empty()) {
                return format!("{}\\{}", dom.account_name, name);
            }
        }
    }
    if let (Some(bh), Some(bsid)) = (&dom.builtin, &dom.builtin_sid) {
        if let Some(rid) = rid_within(sid, bsid) {
            if let Ok(v) = lookup_ids(pipe, bh, &[rid]).await {
                if let Some((_, name, _)) = v.into_iter().find(|(_, n, _)| !n.is_empty()) {
                    return format!("BUILTIN\\{name}");
                }
            }
        }
    }
    sid.to_string()
}

/// If `sid` is `domain_sid` + one trailing RID, return that RID.
fn rid_within(sid: &str, domain_sid: &str) -> Option<u32> {
    let rest = sid.strip_prefix(domain_sid)?.strip_prefix('-')?;
    if rest.contains('-') {
        return None; // deeper than one RID below the domain
    }
    rest.parse().ok()
}

/// Shared paged enumeration for SAMPR_RID_ENUMERATION responses (users/groups/aliases).
async fn enum_rid_named(
    pipe: &mut SmbPipe<'_>,
    domain: &SamrHandle,
    op: u16,
    label: &str,
) -> Result<Vec<(u32, String)>> {
    let mut all = Vec::new();
    let mut resume = 0u32;
    loop {
        // Same input shape as SamrEnumerateDomainsInSamServer: (handle, ctx, prefMax).
        let stub = encode_enum_domains(domain, resume, 0x1000);
        let resp = pipe.call(op, &stub).await.map_err(|e| anyhow!("{label} failed: {e}"))?;
        if std::env::var("ENUM4MAC_DEBUG").is_ok() {
            eprintln!("[debug] {label} resp ({} bytes): {:02x?}", resp.len(), resp);
        }
        let (next, list) =
            decode_rid_enumeration(&resp).map_err(|e| anyhow!("{label} decode: {e}"))?;
        let got = list.len();
        all.extend(list);
        let st = tail_status(&resp)?;
        if st == 0 {
            break;
        }
        if st != STATUS_MORE_ENTRIES {
            bail!("{label} failed (NTSTATUS 0x{st:08x})");
        }
        if got == 0 || next == resume {
            bail!("{label} made no paging progress");
        }
        resume = next;
    }
    Ok(all)
}

/// Decode a SAMPR_ENUMERATION_BUFFER response (shared by EnumUsers / EnumGroups
/// / EnumAliases): `(EnumerationContext, [(rid, name)])`.
///
/// Unlike the crate's `decode_enum_domains`, this correctly handles a **null
/// array pointer** (zero entries), where the conformant `max_count` word is
/// absent — the case Samba returns for a standalone server with no domain
/// groups, which made the crate helper underrun.
fn decode_rid_enumeration(stub: &[u8]) -> Result<(u32, Vec<(u32, String)>)> {
    let tail = tail_status(stub)?;
    if tail != 0 && tail != STATUS_MORE_ENTRIES {
        bail!("enumeration failed (NTSTATUS 0x{tail:08x})");
    }
    let mut d = NdrDecoder::new(stub);
    let resume = d.u32().map_err(|e| anyhow!("resume: {e}"))?;
    let buffer_ref = d.u32().map_err(|e| anyhow!("buffer ref: {e}"))?;
    if buffer_ref == 0 {
        return Ok((resume, Vec::new()));
    }
    let entries = d.u32().map_err(|e| anyhow!("entries: {e}"))? as usize;
    let array_ref = d.u32().map_err(|e| anyhow!("array ref: {e}"))?;
    if array_ref == 0 || entries == 0 {
        // No conformant array follows when the pointer is null / list is empty.
        return Ok((resume, Vec::new()));
    }
    let max_count = d.u32().map_err(|e| anyhow!("max count: {e}"))? as usize;
    if entries > max_count {
        bail!("EntriesRead={entries} exceeds max_count={max_count}");
    }
    // Bounded-alloc guard: each entry is ≥12 wire bytes (rid + ustring header).
    if entries.checked_mul(12).is_none_or(|need| need > d.remaining()) {
        bail!("EntriesRead={entries} exceeds remaining stub");
    }

    let mut headers = Vec::with_capacity(entries);
    for _ in 0..entries {
        let rid = d.u32().map_err(|e| anyhow!("rid: {e}"))?;
        let _len = d.u16().map_err(|e| anyhow!("name len: {e}"))?;
        let _max = d.u16().map_err(|e| anyhow!("name max: {e}"))?;
        let name_ref = d.u32().map_err(|e| anyhow!("name ref: {e}"))?;
        headers.push((rid, name_ref));
    }
    let mut out = Vec::with_capacity(entries);
    for (rid, name_ref) in headers {
        let name = if name_ref != 0 {
            d.conformant_varying_wstr().map_err(|e| anyhow!("name: {e}"))?
        } else {
            String::new()
        };
        out.push((rid, name));
    }
    Ok((resume, out))
}

/// Query the domain password policy (opnum 8, DomainPasswordInformation).
pub async fn password_policy(
    pipe: &mut SmbPipe<'_>,
    dom: &SamrDomain,
) -> Result<PasswordPolicy> {
    let mut e = NdrEncoder::new();
    dom.account.encode(&mut e); // DomainHandle (20 bytes)
    e.u16(DOMAIN_PASSWORD_INFORMATION); // DomainInformationClass (enum16)
    let resp = pipe
        .call(ext_opnum::QUERY_INFO_DOMAIN, &e.into_bytes())
        .await
        .map_err(|e| anyhow!("SamrQueryInformationDomain failed: {e}"))?;
    let st = tail_status(&resp)?;
    if st != 0 {
        bail!("SamrQueryInformationDomain failed (NTSTATUS 0x{st:08x})");
    }
    let mut policy = decode_password_info(&resp)?;

    // Best-effort lockout info (class 12); failure leaves the field unset.
    if let Ok(threshold) = query_lockout_threshold(pipe, dom).await {
        policy.lockout_threshold = Some(threshold);
    }
    Ok(policy)
}

const DOMAIN_LOCKOUT_INFORMATION: u16 = 12;

/// Query DomainLockoutInformation (class 12) and return the lockout threshold.
async fn query_lockout_threshold(pipe: &mut SmbPipe<'_>, dom: &SamrDomain) -> Result<u32> {
    let mut e = NdrEncoder::new();
    dom.account.encode(&mut e);
    e.u16(DOMAIN_LOCKOUT_INFORMATION);
    let resp = pipe
        .call(ext_opnum::QUERY_INFO_DOMAIN, &e.into_bytes())
        .await
        .map_err(|e| anyhow!("SamrQueryInformationDomain(lockout) failed: {e}"))?;
    let st = tail_status(&resp)?;
    if st != 0 {
        bail!("lockout query failed (NTSTATUS 0x{st:08x})");
    }
    // Wire: info ptr (u32), discriminant (u16=12), pad→8, LockoutDuration (i64),
    // LockoutObservationWindow (i64), LockoutThreshold (u16).
    let mut d = NdrDecoder::new(&resp);
    let ptr = d.u32().map_err(|e| anyhow!("lockout ptr: {e}"))?;
    if ptr == 0 {
        bail!("lockout query returned null buffer");
    }
    let disc = d.u16().map_err(|e| anyhow!("lockout disc: {e}"))?;
    if disc != DOMAIN_LOCKOUT_INFORMATION {
        bail!("unexpected lockout info class: {disc}");
    }
    d.align(8);
    let _lockout_duration = d.u64().map_err(|e| anyhow!("lockout duration: {e}"))?;
    let _observation = d.u64().map_err(|e| anyhow!("observation window: {e}"))?;
    let threshold = d.u16().map_err(|e| anyhow!("lockout threshold: {e}"))? as u32;
    Ok(threshold)
}

/// Decode the SAMPR_DOMAIN_INFO_BUFFER for DomainPasswordInformation.
///
/// Wire: inner unique pointer (u32), discriminant (u16=1), pad→4, then
/// DOMAIN_PASSWORD_INFORMATION { MinPasswordLength u16, PasswordHistoryLength
/// u16, PasswordProperties u32, MaxPasswordAge OLD_LARGE_INTEGER (low u32, high
/// i32), MinPasswordAge OLD_LARGE_INTEGER }.
fn decode_password_info(stub: &[u8]) -> Result<PasswordPolicy> {
    let mut d = NdrDecoder::new(stub);
    let ptr = d.u32().map_err(|e| anyhow!("read buffer ptr: {e}"))?;
    if ptr == 0 {
        bail!("QueryInformationDomain returned a null buffer");
    }
    let disc = d.u16().map_err(|e| anyhow!("read discriminant: {e}"))?;
    if disc != DOMAIN_PASSWORD_INFORMATION {
        bail!("unexpected info class in response: {disc}");
    }
    d.align(4);
    let min_length = d.u16().map_err(|e| anyhow!("read min length: {e}"))? as u32;
    let history_length = d.u16().map_err(|e| anyhow!("read history: {e}"))? as u32;
    let properties = d.u32().map_err(|e| anyhow!("read properties: {e}"))?;
    let max_age = read_old_large_integer(&mut d)?;
    let min_age = read_old_large_integer(&mut d)?;

    Ok(PasswordPolicy {
        min_length: Some(min_length),
        history_length: Some(history_length),
        max_age_days: filetime_delta_to_days(max_age),
        min_age_days: filetime_delta_to_days(min_age),
        complexity: Some(properties & 0x0000_0001 != 0), // DOMAIN_PASSWORD_COMPLEX
        lockout_threshold: None, // requires DomainLockoutInformation (class 12)
    })
}

/// Read an OLD_LARGE_INTEGER (LowPart u32, HighPart i32) as a signed i64.
fn read_old_large_integer(d: &mut NdrDecoder) -> Result<i64> {
    let low = d.u32().map_err(|e| anyhow!("read LARGE_INTEGER low: {e}"))?;
    let high = d.u32().map_err(|e| anyhow!("read LARGE_INTEGER high: {e}"))? as i32;
    Ok(((high as i64) << 32) | (low as i64 & 0xFFFF_FFFF))
}

/// Convert a password-age delta (negative 100ns intervals) to whole days.
/// Returns `None` for "never" (the sentinel minimum / zero magnitude).
fn filetime_delta_to_days(delta: i64) -> Option<i64> {
    if delta == 0 || delta == i64::MIN {
        return None;
    }
    // delta is negative; magnitude in 100ns units.
    let magnitude = delta.unsigned_abs();
    let secs = magnitude / 10_000_000;
    Some((secs / 86_400) as i64)
}

/// RID cycling via SamrLookupIdsInDomain (opnum 18): resolve each RID against
/// both the account domain and the Builtin domain to a name + SID_NAME_USE.
/// Unmapped / Unknown / Invalid RIDs are skipped.
pub async fn rid_cycle(
    pipe: &mut SmbPipe<'_>,
    dom: &SamrDomain,
    rids: &[u32],
) -> Result<Vec<UserInfo>> {
    let mut out = Vec::new();

    let mut domains: Vec<(String, SamrHandle)> = vec![(dom.account_name.clone(), dom.account)];
    if let Some(b) = &dom.builtin {
        domains.push(("BUILTIN".to_string(), *b));
    }

    for (label, handle) in domains {
        let resolved = lookup_ids(pipe, &handle, rids).await.unwrap_or_default();
        for (rid, name, use_val) in resolved {
            if name.is_empty() || use_val == 8 || use_val == 7 {
                continue; // Unknown / Invalid
            }
            out.push(UserInfo {
                rid,
                name: format!("{label}\\{name}"),
                description: Some(sid_name_use(use_val).to_string()),
                full_name: None,
            });
        }
    }
    Ok(out)
}

/// Resolve a batch of RIDs against one open domain (chunked at 1000 per call).
async fn lookup_ids(
    pipe: &mut SmbPipe<'_>,
    domain: &SamrHandle,
    rids: &[u32],
) -> Result<Vec<(u32, String, u32)>> {
    let mut out = Vec::new();
    for chunk in rids.chunks(1000) {
        let stub = encode_lookup_ids(domain, chunk);
        let resp = pipe
            .call(ext_opnum::LOOKUP_IDS, &stub)
            .await
            .map_err(|e| anyhow!("SamrLookupIdsInDomain failed: {e}"))?;
        let st = tail_status(&resp)?;
        if st == STATUS_NONE_MAPPED {
            continue;
        }
        if st != 0 && st != STATUS_SOME_NOT_MAPPED {
            bail!("SamrLookupIdsInDomain failed (NTSTATUS 0x{st:08x})");
        }
        out.extend(decode_lookup_ids(&resp, chunk)?);
    }
    Ok(out)
}

/// Encode SamrLookupIdsInDomain request: handle, Count, then a conformant-
/// varying array `[size_is(1000), length_is(Count)]` of RIDs.
fn encode_lookup_ids(domain: &SamrHandle, rids: &[u32]) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    domain.encode(&mut e);
    e.u32(rids.len() as u32); // Count
    e.u32(1000); // max_count (size_is constant)
    e.u32(0); // offset
    e.u32(rids.len() as u32); // actual_count (length_is)
    for rid in rids {
        e.u32(*rid);
    }
    e.into_bytes()
}

/// Decode SamrLookupIdsInDomain response: a SAMPR_RETURNED_USTRING_ARRAY of
/// names and a SAMPR_ULONG_ARRAY of SID_NAME_USE values, index-aligned with the
/// input RIDs.
fn decode_lookup_ids(stub: &[u8], rids: &[u32]) -> Result<Vec<(u32, String, u32)>> {
    let mut d = NdrDecoder::new(stub);

    // Names: SAMPR_RETURNED_USTRING_ARRAY { Count, *Element }
    let name_count = d.u32().map_err(|e| anyhow!("names count: {e}"))? as usize;
    let name_ref = d.u32().map_err(|e| anyhow!("names ref: {e}"))?;
    let mut headers = Vec::with_capacity(name_count);
    if name_ref != 0 {
        let max = d.u32().map_err(|e| anyhow!("names array max: {e}"))? as usize;
        if max < name_count {
            bail!("names array max_count {max} < count {name_count}");
        }
        for _ in 0..name_count {
            let _len = d.u16().map_err(|e| anyhow!("name len: {e}"))?;
            let _maxlen = d.u16().map_err(|e| anyhow!("name maxlen: {e}"))?;
            let buf_ref = d.u32().map_err(|e| anyhow!("name buf ref: {e}"))?;
            headers.push(buf_ref);
        }
    }
    let mut names = Vec::with_capacity(name_count);
    for buf_ref in &headers {
        if *buf_ref != 0 {
            names.push(d.conformant_varying_wstr().map_err(|e| anyhow!("name str: {e}"))?);
        } else {
            names.push(String::new());
        }
    }

    // Use: SAMPR_ULONG_ARRAY { Count, *Element }
    let use_count = d.u32().map_err(|e| anyhow!("use count: {e}"))? as usize;
    let use_ref = d.u32().map_err(|e| anyhow!("use ref: {e}"))?;
    let mut uses = Vec::with_capacity(use_count);
    if use_ref != 0 {
        let _max = d.u32().map_err(|e| anyhow!("use array max: {e}"))?;
        for _ in 0..use_count {
            uses.push(d.u32().map_err(|e| anyhow!("use val: {e}"))?);
        }
    }

    let mut out = Vec::new();
    for (i, rid) in rids.iter().enumerate() {
        let name = names.get(i).cloned().unwrap_or_default();
        let use_val = uses.get(i).copied().unwrap_or(8); // default Unknown
        out.push((*rid, name, use_val));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_formatting() {
        assert_eq!(sid_string(1, 5, &[21, 111, 222, 333]), "S-1-5-21-111-222-333");
        assert_eq!(sid_string(1, 5, &[]), "S-1-5");
    }

    #[test]
    fn password_age_conversion() {
        // 30 days in negative 100ns intervals.
        let thirty_days = -(30i64 * 86_400 * 10_000_000);
        assert_eq!(filetime_delta_to_days(thirty_days), Some(30));
        assert_eq!(filetime_delta_to_days(0), None);
        assert_eq!(filetime_delta_to_days(i64::MIN), None);
    }

    #[test]
    fn decode_password_info_synthetic() {
        // Build a response per the documented wire layout.
        let mut b = Vec::new();
        b.extend_from_slice(&1u32.to_le_bytes()); // non-null buffer ptr
        b.extend_from_slice(&1u16.to_le_bytes()); // discriminant = DomainPasswordInformation
        b.extend_from_slice(&[0, 0]); // pad to 4-byte boundary
        b.extend_from_slice(&8u16.to_le_bytes()); // MinPasswordLength = 8
        b.extend_from_slice(&5u16.to_le_bytes()); // PasswordHistoryLength = 5
        b.extend_from_slice(&1u32.to_le_bytes()); // PasswordProperties: complex
        let max_age = -(42i64 * 86_400 * 10_000_000);
        b.extend_from_slice(&(max_age as u32).to_le_bytes()); // MaxPasswordAge low
        b.extend_from_slice(&(((max_age >> 32) as i32) as u32).to_le_bytes()); // high
        b.extend_from_slice(&0u32.to_le_bytes()); // MinPasswordAge low (0 → never)
        b.extend_from_slice(&0u32.to_le_bytes()); // high
        b.extend_from_slice(&0u32.to_le_bytes()); // trailing NTSTATUS = SUCCESS

        let pol = decode_password_info(&b).unwrap();
        assert_eq!(pol.min_length, Some(8));
        assert_eq!(pol.history_length, Some(5));
        assert_eq!(pol.complexity, Some(true));
        assert_eq!(pol.max_age_days, Some(42));
        assert_eq!(pol.min_age_days, None);
    }

    #[test]
    fn decode_rid_enumeration_empty_null_array() {
        // Exact 24-byte response captured from Samba EnumGroups with 0 groups:
        // resume=0, buffer_ref=non-null, entries=0, array_ref=NULL, count=0, status=0.
        // (No conformant max_count because the array pointer is null.)
        let bytes: [u8; 24] = [
            0x00, 0x00, 0x00, 0x00, // resume
            0x00, 0x00, 0x02, 0x00, // buffer_ref (non-null)
            0x00, 0x00, 0x00, 0x00, // entries = 0
            0x00, 0x00, 0x00, 0x00, // array_ref = NULL
            0x00, 0x00, 0x00, 0x00, // count_returned = 0
            0x00, 0x00, 0x00, 0x00, // status = 0
        ];
        let (resume, list) = decode_rid_enumeration(&bytes).unwrap();
        assert_eq!(resume, 0);
        assert!(list.is_empty());
    }

    #[test]
    fn decode_rid_enumeration_two_entries() {
        let mut b = Vec::new();
        b.extend_from_slice(&0u32.to_le_bytes()); // resume
        b.extend_from_slice(&0x0002_0000u32.to_le_bytes()); // buffer_ref non-null
        b.extend_from_slice(&2u32.to_le_bytes()); // entries
        b.extend_from_slice(&0x0002_0004u32.to_le_bytes()); // array_ref non-null
        b.extend_from_slice(&2u32.to_le_bytes()); // max_count
        for (rid, s) in [(512u32, "Domain Admins"), (513u32, "Domain Users")] {
            let blen = (s.encode_utf16().count() * 2) as u16;
            b.extend_from_slice(&rid.to_le_bytes());
            b.extend_from_slice(&blen.to_le_bytes()); // Length
            b.extend_from_slice(&blen.to_le_bytes()); // MaxLength
            b.extend_from_slice(&1u32.to_le_bytes()); // name ref
        }
        for s in ["Domain Admins", "Domain Users"] {
            let units: Vec<u16> = s.encode_utf16().collect();
            b.extend_from_slice(&(units.len() as u32).to_le_bytes()); // max_count
            b.extend_from_slice(&0u32.to_le_bytes()); // offset
            b.extend_from_slice(&(units.len() as u32).to_le_bytes()); // actual_count
            for u in units {
                b.extend_from_slice(&u.to_le_bytes());
            }
            if b.len() % 4 != 0 {
                b.extend_from_slice(&[0, 0]);
            }
        }
        b.extend_from_slice(&2u32.to_le_bytes()); // count_returned
        b.extend_from_slice(&0u32.to_le_bytes()); // status
        let (_resume, list) = decode_rid_enumeration(&b).unwrap();
        assert_eq!(list, vec![(512, "Domain Admins".into()), (513, "Domain Users".into())]);
    }

    #[test]
    fn decode_lookup_ids_synthetic() {
        // Two RIDs: 500 → "Administrator" (User=1), 501 → "Guest" (User=1).
        let mut b = Vec::new();
        // Names array: Count=2, ref!=0
        b.extend_from_slice(&2u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes()); // element ref
        b.extend_from_slice(&2u32.to_le_bytes()); // max_count
        // Two RPC_UNICODE_STRING headers
        for s in ["Administrator", "Guest"] {
            let blen = (s.encode_utf16().count() * 2) as u16;
            b.extend_from_slice(&blen.to_le_bytes()); // Length
            b.extend_from_slice(&blen.to_le_bytes()); // MaxLength
            b.extend_from_slice(&1u32.to_le_bytes()); // Buffer ref
        }
        // Two conformant-varying wstrings
        for s in ["Administrator", "Guest"] {
            let units: Vec<u16> = s.encode_utf16().collect();
            b.extend_from_slice(&(units.len() as u32).to_le_bytes()); // max_count
            b.extend_from_slice(&0u32.to_le_bytes()); // offset
            b.extend_from_slice(&(units.len() as u32).to_le_bytes()); // actual_count
            for u in units {
                b.extend_from_slice(&u.to_le_bytes());
            }
            // pad to 4-byte alignment if odd number of u16s
            if b.len() % 4 != 0 {
                b.extend_from_slice(&[0, 0]);
            }
        }
        // Use array: Count=2, ref!=0, max, two u32 (User=1)
        b.extend_from_slice(&2u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&2u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        // trailing NTSTATUS
        b.extend_from_slice(&0u32.to_le_bytes());

        let rids = [500u32, 501u32];
        let decoded = decode_lookup_ids(&b, &rids).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0], (500, "Administrator".to_string(), 1));
        assert_eq!(decoded[1], (501, "Guest".to_string(), 1));
    }
}
