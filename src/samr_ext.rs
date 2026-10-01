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

/// Handles + identifiers for an opened SAM account domain.
pub struct SamrDomain {
    /// Server handle from Connect2 (retained for completeness / future handle close).
    #[allow(dead_code)]
    pub server: SamrHandle,
    pub domain: SamrHandle,
    pub domain_name: String,
    pub domain_sid: String,
}

/// Bind SAMR on the pipe, connect, locate the account (non-"Builtin") domain,
/// and open it. Shared setup for every extended operation.
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

    // Enumerate SAM domains (Builtin + account); pick the account domain.
    let resp = pipe
        .call(opnum::ENUM_DOMAINS, &encode_enum_domains(&server, 0, 0x1000))
        .await
        .map_err(|e| anyhow!("SamrEnumerateDomains failed: {e}"))?;
    let (_next, domains) =
        decode_enum_domains(&resp).map_err(|e| anyhow!("decode domains: {e}"))?;
    let account = domains
        .into_iter()
        .map(|(_, n)| n)
        .find(|n| !n.eq_ignore_ascii_case("Builtin"))
        .ok_or_else(|| anyhow!("no account domain found"))?;

    // Lookup the account domain SID.
    let resp = pipe
        .call(opnum::LOOKUP_DOMAIN, &encode_lookup_domain(&server, &account))
        .await
        .map_err(|e| anyhow!("SamrLookupDomain failed: {e}"))?;
    let sid = decode_lookup_domain(&resp).map_err(|e| anyhow!("decode domain SID: {e}"))?;
    let domain_sid = sid_string(sid.revision, sid.identifier_authority, &sid.sub_authorities);

    // Open the account domain.
    let resp = pipe
        .call(opnum::OPEN_DOMAIN, &encode_open_domain(&server, access::MAXIMUM_ALLOWED, &sid))
        .await
        .map_err(|e| anyhow!("SamrOpenDomain failed: {e}"))?;
    let st = tail_status(&resp)?;
    if st != 0 {
        bail!("SamrOpenDomain failed (NTSTATUS 0x{st:08x})");
    }
    let mut d = NdrDecoder::new(&resp);
    let domain = SamrHandle::decode(&mut d).map_err(|e| anyhow!("decode domain handle: {e}"))?;

    Ok(SamrDomain { server, domain, domain_name: account, domain_sid })
}

/// Enumerate groups (opnum 11) and aliases (opnum 15) in the open domain.
/// Both reuse the SAMPR_RID_ENUMERATION wire shape of `enumerate_domains`.
pub async fn enum_groups(pipe: &mut SmbPipe<'_>, dom: &SamrDomain) -> Result<Vec<GroupInfo>> {
    let mut out = Vec::new();
    for (op, label, gtype) in [
        (ext_opnum::ENUM_GROUPS, "SamrEnumerateGroupsInDomain", "group"),
        (ext_opnum::ENUM_ALIASES, "SamrEnumerateAliasesInDomain", "alias"),
    ] {
        let list = enum_rid_named(pipe, &dom.domain, op, label).await?;
        for (rid, name) in list {
            out.push(GroupInfo { rid, name, group_type: gtype.to_string(), members: Vec::new() });
        }
    }
    Ok(out)
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
        let (next, list) =
            decode_enum_domains(&resp).map_err(|e| anyhow!("{label} decode: {e}"))?;
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

/// Query the domain password policy (opnum 8, DomainPasswordInformation).
pub async fn password_policy(
    pipe: &mut SmbPipe<'_>,
    dom: &SamrDomain,
) -> Result<PasswordPolicy> {
    let mut e = NdrEncoder::new();
    dom.domain.encode(&mut e); // DomainHandle (20 bytes)
    e.u16(DOMAIN_PASSWORD_INFORMATION); // DomainInformationClass (enum16)
    let resp = pipe
        .call(ext_opnum::QUERY_INFO_DOMAIN, &e.into_bytes())
        .await
        .map_err(|e| anyhow!("SamrQueryInformationDomain failed: {e}"))?;
    let st = tail_status(&resp)?;
    if st != 0 {
        bail!("SamrQueryInformationDomain failed (NTSTATUS 0x{st:08x})");
    }
    decode_password_info(&resp)
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

/// RID cycling via SamrLookupIdsInDomain (opnum 18): resolve each RID in the
/// open domain to a name + SID_NAME_USE. Unmapped RIDs are skipped.
pub async fn rid_cycle(
    pipe: &mut SmbPipe<'_>,
    dom: &SamrDomain,
    rids: &[u32],
) -> Result<Vec<UserInfo>> {
    let mut out = Vec::new();
    // SamrLookupIdsInDomain caps Count at 1000 per call.
    for chunk in rids.chunks(1000) {
        let stub = encode_lookup_ids(&dom.domain, chunk);
        let resp = pipe
            .call(ext_opnum::LOOKUP_IDS, &stub)
            .await
            .map_err(|e| anyhow!("SamrLookupIdsInDomain failed: {e}"))?;
        let st = tail_status(&resp)?;
        if st == STATUS_NONE_MAPPED {
            continue; // none of this chunk resolved
        }
        if st != 0 && st != STATUS_SOME_NOT_MAPPED {
            bail!("SamrLookupIdsInDomain failed (NTSTATUS 0x{st:08x})");
        }
        let resolved = decode_lookup_ids(&resp, chunk)?;
        for (rid, name, use_val) in resolved {
            if name.is_empty() || use_val == 8 || use_val == 7 {
                continue; // Unknown / Invalid
            }
            out.push(UserInfo {
                rid,
                name: format!("{}\\{}", dom.domain_name, name),
                description: Some(sid_name_use(use_val).to_string()),
                full_name: None,
            });
        }
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
