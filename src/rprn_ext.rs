//! Printer enumeration via MS-RPRN `RpcEnumPrinters` (opnum 0), level 1.
//!
//! Uses the classic two-phase buffer-size negotiation: call once with a
//! zero-length buffer to learn the required size, then again with a buffer of
//! that size. The returned buffer is spoolss "custom" marshaling — an array of
//! fixed PRINTER_INFO_1 structs at the front whose string fields are byte
//! offsets into the same buffer.
//!
//! Verified against a live Samba `testprinter`.

use crate::output::PrinterInfo;
use anyhow::{Result, anyhow, bail};
use dcerpc::ndr::{NdrDecoder, NdrEncoder};
use dcerpc::rprn::rprn_syntax;
use dcerpc::transport::SmbPipe;

const OPNUM_ENUM_PRINTERS: u16 = 0;
const PRINTER_ENUM_LOCAL: u32 = 0x0000_0002;
const ERROR_INSUFFICIENT_BUFFER: u32 = 0x0000_007A;

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

/// Enumerate local printers (level 1).
pub async fn enum_printers(pipe: &mut SmbPipe<'_>) -> Result<Vec<PrinterInfo>> {
    pipe.bind(rprn_syntax())
        .await
        .map_err(|e| anyhow!("RPRN bind failed: {e}"))?;

    // Phase 1: size query (null buffer, cbBuf = 0).
    let resp = pipe
        .call(
            OPNUM_ENUM_PRINTERS,
            &encode_enum(PRINTER_ENUM_LOCAL, 1, None),
        )
        .await
        .map_err(|e| anyhow!("RpcEnumPrinters(size) failed: {e}"))?;
    let needed = decode_size(&resp)?;
    if needed == 0 {
        return Ok(Vec::new());
    }

    // Phase 2: fetch with a correctly-sized buffer.
    let resp = pipe
        .call(
            OPNUM_ENUM_PRINTERS,
            &encode_enum(PRINTER_ENUM_LOCAL, 1, Some(needed)),
        )
        .await
        .map_err(|e| anyhow!("RpcEnumPrinters(data) failed: {e}"))?;
    if std::env::var("ENUM4ALL_DEBUG").is_ok() {
        eprintln!(
            "[debug] EnumPrinters resp ({} bytes): {:02x?}",
            resp.len(),
            resp
        );
    }
    let st = tail_status(&resp)?;
    if st != 0 {
        bail!("RpcEnumPrinters failed (WERROR 0x{st:08x})");
    }
    let (buf, count) = decode_data(&resp)?;
    Ok(decode_printer_info_1(&buf, count))
}

/// Encode an RpcEnumPrinters request. `buf` is `None` for the size query, or
/// `Some(n)` to send an n-byte output buffer.
fn encode_enum(flags: u32, level: u32, buf: Option<u32>) -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.u32(flags);
    e.null_ptr(); // Name [in,string,unique] = NULL
    e.u32(level);
    match buf {
        None => {
            e.null_ptr(); // pPrinterEnum = NULL
            e.u32(0); // cbBuf = 0
        }
        Some(n) => {
            e.referent(); // pPrinterEnum non-null unique ptr
            e.u32(n); // conformant max_count = cbBuf
            e.bytes(&vec![0u8; n as usize]); // [in] buffer content (ignored by server)
            e.u32(n); // cbBuf
        }
    }
    e.into_bytes()
}

/// Decode the phase-1 (size query) response → required byte count.
fn decode_size(stub: &[u8]) -> Result<u32> {
    let st = tail_status(stub)?;
    if st != 0 && st != ERROR_INSUFFICIENT_BUFFER {
        bail!("RpcEnumPrinters size query failed (WERROR 0x{st:08x})");
    }
    let mut d = NdrDecoder::new(stub);
    let buf_ref = d.u32().map_err(|e| anyhow!("buffer ref: {e}"))?;
    if buf_ref != 0 {
        // Unexpected for a null-buffer request, but skip a conformant array if present.
        let max = d.u32().map_err(|e| anyhow!("buffer max: {e}"))? as usize;
        let _ = d.read_bytes(max);
        d.align(4);
    }
    let needed = d.u32().map_err(|e| anyhow!("pcbNeeded: {e}"))?;
    Ok(needed)
}

/// Decode the phase-2 response → (printer buffer, printer count).
fn decode_data(stub: &[u8]) -> Result<(Vec<u8>, usize)> {
    let mut d = NdrDecoder::new(stub);
    let buf_ref = d.u32().map_err(|e| anyhow!("buffer ref: {e}"))?;
    if buf_ref == 0 {
        return Ok((Vec::new(), 0));
    }
    let max = d.u32().map_err(|e| anyhow!("buffer max: {e}"))? as usize;
    let buf = d
        .read_bytes(max)
        .map_err(|e| anyhow!("buffer body: {e}"))?
        .to_vec();
    d.align(4);
    let _needed = d.u32().map_err(|e| anyhow!("pcbNeeded: {e}"))?;
    let count = d.u32().map_err(|e| anyhow!("pcReturned: {e}"))? as usize;
    Ok((buf, count))
}

/// Parse an array of PRINTER_INFO_1 from the spoolss flat buffer. Each fixed
/// record is 16 bytes (Flags + 3 string offsets); the offsets are relative to
/// the start of `buf`.
fn decode_printer_info_1(buf: &[u8], count: usize) -> Vec<PrinterInfo> {
    let mut out = Vec::new();
    for i in 0..count {
        let base = i * 16;
        if base + 16 > buf.len() {
            break;
        }
        let flags = u32::from_le_bytes(buf[base..base + 4].try_into().unwrap());
        let desc_off = u32::from_le_bytes(buf[base + 4..base + 8].try_into().unwrap()) as usize;
        let name_off = u32::from_le_bytes(buf[base + 8..base + 12].try_into().unwrap()) as usize;
        let comment_off =
            u32::from_le_bytes(buf[base + 12..base + 16].try_into().unwrap()) as usize;
        out.push(PrinterInfo {
            name: read_wstr_at(buf, name_off),
            description: read_wstr_at(buf, desc_off),
            comment: read_wstr_at(buf, comment_off),
            flags,
        });
    }
    out
}

/// Read a NUL-terminated UTF-16LE string at `offset` within `buf`.
fn read_wstr_at(buf: &[u8], offset: usize) -> String {
    let mut units = Vec::new();
    let mut p = offset;
    while p + 2 <= buf.len() {
        let u = u16::from_le_bytes([buf[p], buf[p + 1]]);
        if u == 0 {
            break;
        }
        units.push(u);
        p += 2;
    }
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_one_printer() {
        // One PRINTER_INFO_1: fixed record (16 bytes) then two strings.
        let name = "HP-LaserJet";
        let comment = "Front desk";
        let mut buf = Vec::new();
        // fixed record: flags, descOff, nameOff, commentOff
        let name_off = 16u32;
        let name_bytes: Vec<u8> = name
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .chain([0, 0])
            .collect();
        let comment_off = 16 + name_bytes.len() as u32;
        buf.extend_from_slice(&0x1u32.to_le_bytes()); // flags
        buf.extend_from_slice(&name_off.to_le_bytes()); // description → reuse name offset
        buf.extend_from_slice(&name_off.to_le_bytes()); // name
        buf.extend_from_slice(&comment_off.to_le_bytes()); // comment
        buf.extend_from_slice(&name_bytes);
        let comment_bytes: Vec<u8> = comment
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .chain([0, 0])
            .collect();
        buf.extend_from_slice(&comment_bytes);

        let printers = decode_printer_info_1(&buf, 1);
        assert_eq!(printers.len(), 1);
        assert_eq!(printers[0].name, "HP-LaserJet");
        assert_eq!(printers[0].comment, "Front desk");
    }
}
