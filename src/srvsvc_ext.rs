//! Extended SRVSVC: NetrServerGetInfo (level 101) for OS / server details,
//! not exposed by the high-level `dcerpc::srvsvc` client.
//!
//! ⚠️ Raw NDR; the decoder is validated against live Samba output.

use crate::output::OsInfo;
use anyhow::{Result, anyhow, bail};
use dcerpc::ndr::{NdrDecoder, NdrEncoder};
use dcerpc::srvsvc::srvsvc_syntax;
use dcerpc::transport::SmbPipe;

const OPNUM_NET_SERVER_GET_INFO: u16 = 21;

fn tail_status(stub: &[u8]) -> Result<u32> {
    let n = stub.len();
    if n < 4 {
        bail!("response too short ({n} bytes)");
    }
    Ok(u32::from_le_bytes([
        stub[n - 4],
        stub[n - 3],
        stub[n - 2],
        stub[n - 1],
    ]))
}

/// Map the SERVER_INFO_101 platform id to a label.
fn platform(id: u32) -> &'static str {
    match id {
        300 => "DOS",
        400 => "OS/2",
        500 => "Windows NT",
        600 => "OSF",
        700 => "VMS",
        _ => "Unknown",
    }
}

/// Call NetrServerGetInfo(level=101) on an already-bound SRVSVC pipe is not
/// required; this binds srvsvc itself.
pub async fn server_info(pipe: &mut SmbPipe<'_>) -> Result<OsInfo> {
    pipe.bind(srvsvc_syntax())
        .await
        .map_err(|e| anyhow!("SRVSVC bind failed: {e}"))?;

    // Request: ServerName [in,unique,string] = NULL, Level = 101.
    let mut e = NdrEncoder::new();
    e.null_ptr();
    e.u32(101);
    let resp = pipe
        .call(OPNUM_NET_SERVER_GET_INFO, &e.into_bytes())
        .await
        .map_err(|e| anyhow!("NetrServerGetInfo failed: {e}"))?;
    if std::env::var("ENUM4ALL_DEBUG").is_ok() {
        eprintln!(
            "[debug] NetrServerGetInfo resp ({} bytes): {:02x?}",
            resp.len(),
            resp
        );
    }
    let st = tail_status(&resp)?;
    if st != 0 {
        bail!("NetrServerGetInfo failed (NTSTATUS 0x{st:08x})");
    }
    decode_server_info_101(&resp)
}

/// Decode SERVER_INFO union (level 101).
///
/// Wire (verified against Samba): switch discriminant (u32=101), Info referent
/// (u32), then SERVER_INFO_101 { platform_id u32, name ptr, version_major u32,
/// version_minor u32, type u32, comment ptr }, then the deferred name and
/// comment conformant-varying wide strings, then the return status.
fn decode_server_info_101(stub: &[u8]) -> Result<OsInfo> {
    let mut d = NdrDecoder::new(stub);
    let level = d.u32().map_err(|e| anyhow!("level: {e}"))?;
    if level != 101 {
        bail!("unexpected info level in response: {level}");
    }
    let info_ref = d.u32().map_err(|e| anyhow!("info ref: {e}"))?;
    if info_ref == 0 {
        bail!("NetrServerGetInfo returned a null info buffer");
    }
    let platform_id = d.u32().map_err(|e| anyhow!("platform id: {e}"))?;
    let name_ref = d.u32().map_err(|e| anyhow!("name ref: {e}"))?;
    let version_major = d.u32().map_err(|e| anyhow!("version major: {e}"))?;
    let version_minor = d.u32().map_err(|e| anyhow!("version minor: {e}"))?;
    let _type = d.u32().map_err(|e| anyhow!("server type: {e}"))?;
    let comment_ref = d.u32().map_err(|e| anyhow!("comment ref: {e}"))?;

    let name = if name_ref != 0 {
        d.conformant_varying_wstr()
            .map_err(|e| anyhow!("name str: {e}"))?
    } else {
        String::new()
    };
    let comment = if comment_ref != 0 {
        d.conformant_varying_wstr()
            .map_err(|e| anyhow!("comment str: {e}"))?
    } else {
        String::new()
    };

    Ok(OsInfo {
        dialect: None,
        server_os: Some(format!(
            "{} {version_major}.{version_minor}",
            platform(platform_id)
        )),
        server_version: Some(format!("{version_major}.{version_minor}")),
        domain: None,
        computer_name: if name.is_empty() { None } else { Some(name) },
        signing: None,
    })
    .map(|mut os| {
        if !comment.is_empty() {
            os.server_os = Some(format!(
                "{} ({comment})",
                os.server_os.take().unwrap_or_default()
            ));
        }
        os
    })
}
