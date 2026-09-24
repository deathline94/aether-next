//! The binary-trust witness: one open of a file, and both facts the trust anchor
//! compares taken out of the bytes that single open produced.
//!
//! `trust.rs` declares this as `#[path = "trust_reader.rs"] mod reader;` and
//! re-exports it, and `tests/witness_reader_test.rs` compiles the **same file** into
//! its own target. That duplication of purpose is deliberate and it is about the
//! linker, not about style: rustc groups a crate's items into codegen units without
//! regard for module boundaries, so any function here that shares a unit with one of
//! `trust.rs`'s `CommandError` users drags `error.rs`'s `impl From<tauri::Error>`
//! with it, which drags in the whole Tauri runtime (`comctl32!TaskDialogIndirect`,
//! `WebView2Loader`, the tray, the dialog and named-pipe imports). A `cargo test
//! --lib` binary gets no common-controls v6 manifest, so that import set has nothing
//! to resolve against and the exe dies at load with `0xc0000139
//! STATUS_ENTRYPOINT_NOT_FOUND` — before a single test runs, with clippy and
//! `cargo check` both clean. Measured here, not theorised.
//!
//! So: nothing in this file may name `CommandError`, `tauri`, or anything else from
//! the parent module, and its tests live in their own target, where the Tauri
//! surface is already linked and does load.
use std::fs;
use std::path::Path;

/* ------------------------- why this reads the signature out of the bytes ---- */
/*
 * `WinVerifyTrust` answers "is this signature valid, and does it chain". It does
 * not answer "which certificate signed *these* bytes", and the anchor's
 * `cert_sha256` needs that answer. Asking a *second* reader of the path for it —
 * which is what the `powershell.exe Get-AuthenticodeSignature` call that used to
 * live here did, one process launch after the digest had already been taken — is
 * the defect T060 names: digest and signer then describe two opens of a name, and
 * a swap in between makes the pair describe a file that never existed.
 *
 * So the signer is taken out of the bytes themselves. An Authenticode signature is
 * a PKCS#7 `SignedData` sitting in the PE's certificate table, which is offsets and
 * lengths, not cryptography: nothing is *verified* by this reader, it only follows
 * DER far enough to find the one certificate the signature is attributed to and
 * hand its bytes to `sha2`. That keeps the reader pure — testable against a
 * fixture, and against `packaging/wintun.dll` on any Windows host — and keeps
 * crypt32 out of it deliberately: the DPAPI history in this crate is that a new
 * crypt32 import costs the test binary its ability to *load* (0xc0000139), and
 * clippy is blind to that.
 */

/// Lowercase hex: the shape every digest in this file, and in the anchor, uses.
pub fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// sha256 over a buffer, lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex_lower(&Sha256::digest(bytes))
}

/// Both facts the anchor compares, from one buffer.
///
/// The fields are private and there is one constructor, [`witness_bytes`], on
/// purpose: a type that could be built field by field could be built from two
/// reads, which is the shape of the bug this replaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryWitness {
    file_sha256: String,
    signer: Option<SignerObservation>,
}

impl BinaryWitness {
    /// sha256 over every byte — what the anchor's `file_sha256` is compared with.
    pub fn file_sha256(&self) -> &str {
        &self.file_sha256
    }

    /// Who signed those bytes, according to the certificate table inside them, or
    /// `None` when they carry no signature at all.
    pub fn signer(&self) -> Option<&SignerObservation> {
        self.signer.as_ref()
    }
}

/// The signing certificate an Authenticode signature is attributed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerObservation {
    leaf_sha256: String,
    subject: String,
}

impl SignerObservation {
    /// sha256 over the leaf's DER — the anchor's `cert_sha256`, and *not* the SHA-1
    /// store thumbprint `Get-AuthenticodeSignature` prints as `Thumbprint`.
    pub fn leaf_sha256(&self) -> &str {
        &self.leaf_sha256
    }

    /// The leaf's subject as a distinguished name, for
    /// [`subject_names_common_name`].
    pub fn subject(&self) -> &str {
        &self.subject
    }
}

/// Read both witnessed facts out of **one** slice.
///
/// There is no path in this signature. A caller that has the bytes has the
/// signature; a caller that does not has neither, and cannot get one alone.
///
/// Errs when the buffer *claims* a signature it cannot follow, which is a refusal,
/// not a question to ask somebody else about.
pub fn witness_bytes(bytes: &[u8]) -> Result<BinaryWitness, String> {
    let signer = authenticode_signer(bytes)?;
    Ok(BinaryWitness {
        file_sha256: sha256_hex(bytes),
        signer,
    })
}

/// The Authenticode signer of a PE image, from its bytes.
///
/// `Ok(None)` means "nothing here claims a signature": no MS-DOS magic, no
/// certificate directory, or a zero-length one. `Err` means a certificate table is
/// named and this reader could not follow it.
pub fn authenticode_signer(bytes: &[u8]) -> Result<Option<SignerObservation>, String> {
    let Some(table) = pe_certificate_table(bytes)? else {
        return Ok(None);
    };
    let Some(pkcs7) = pkcs7_from_certificate_table(table)? else {
        return Ok(None);
    };
    authenticated_signer(pkcs7).map(Some)
}

/* ---------------------------------------------------- the PE certificate table */

/// `WIN_CERTIFICATE`'s fixed part: `dwLength`, `wRevision`, `wCertificateType`.
pub const WIN_CERTIFICATE_HEADER: usize = 8;
/// `WIN_CERT_TYPE_PKCS_SIGNED_DATA` from `wintrust.h`: the Authenticode blob type.
pub const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

fn span(bytes: &[u8], start: usize, len: usize) -> Option<&[u8]> {
    bytes.get(start..start.checked_add(len)?)
}

fn read_u16_le(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(span(bytes, at, 2)?.try_into().ok()?))
}

fn read_u32_le(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(span(bytes, at, 4)?.try_into().ok()?))
}

/// The bytes of the `WIN_CERTIFICATE` a PE image names as its certificate table.
fn pe_certificate_table(bytes: &[u8]) -> Result<Option<&[u8]>, String> {
    if !bytes.starts_with(b"MZ") {
        return Ok(None);
    }
    let lfanew =
        usize::try_from(read_u32_le(bytes, 0x3c).der("the MS-DOS header is truncated")?)
            .map_err(|_| "Authenticode: the PE header offset does not fit this file".to_string())?;
    let signature =
        span(bytes, lfanew, 4).der("the PE header offset is past the end of the file")?;
    if signature != *b"PE\0\0" {
        return Err("Authenticode: the MS-DOS header does not point at a PE signature".to_string());
    }
    let coff = lfanew + 4;
    let optional_len =
        usize::from(read_u16_le(bytes, coff + 16).der("the COFF header is truncated")?);
    let optional_start = coff
        .checked_add(20)
        .der("the optional header offset overflows")?;
    let optional = span(bytes, optional_start, optional_len)
        .der("the optional header is not inside the image")?;
    let magic = read_u16_le(optional, 0).der("the optional header is empty")?;
    // Data directories start at offset 96 of a PE32 optional header and at 112 of a
    // PE32+ one; entry 4 is the certificate table, whose "RVA" is a raw file offset.
    let (count_at, directories_at) = match magic {
        0x10b => (92usize, 96usize),
        0x20b => (108, 112),
        other => {
            return Err(format!(
                "Authenticode: unknown optional header magic 0x{other:04x}"
            ))
        }
    };
    let directories = read_u32_le(optional, count_at).der("the data directory count is missing")?;
    if directories <= 4 {
        return Ok(None);
    }
    let entry = span(optional, directories_at + 4 * 8, 8)
        .der("the certificate directory is not inside the optional header")?;
    let offset = usize::try_from(read_u32_le(entry, 0).der("truncated certificate directory")?)
        .map_err(|_| "Authenticode: the certificate offset does not fit".to_string())?;
    let length = usize::try_from(read_u32_le(entry, 4).der("truncated certificate directory")?)
        .map_err(|_| "Authenticode: the certificate length does not fit".to_string())?;
    if length == 0 {
        return Ok(None);
    }
    span(bytes, offset, length)
        .der("the certificate table lies outside the image")
        .map(Some)
}

/// The PKCS#7 blob inside a `WIN_CERTIFICATE`.
fn pkcs7_from_certificate_table(table: &[u8]) -> Result<Option<&[u8]>, String> {
    if table.is_empty() {
        return Ok(None);
    }
    let length =
        usize::try_from(read_u32_le(table, 0).der("the WIN_CERTIFICATE header is truncated")?)
            .map_err(|_| "Authenticode: the WIN_CERTIFICATE length does not fit".to_string())?;
    let revision = read_u16_le(table, 4).der("the WIN_CERTIFICATE header is truncated")?;
    let kind = read_u16_le(table, 6).der("the WIN_CERTIFICATE header is truncated")?;
    if length < WIN_CERTIFICATE_HEADER || length > table.len() {
        return Err(format!(
            "Authenticode: the WIN_CERTIFICATE header claims {length} bytes, the certificate \
             table holds {}",
            table.len()
        ));
    }
    if revision != 0x0100 && revision != 0x0200 {
        return Err(format!(
            "Authenticode: unexpected certificate revision 0x{revision:04x}"
        ));
    }
    if kind != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
        return Err(format!(
            "Authenticode: certificate type 0x{kind:04x} is not a PKCS#7 signed-data blob \
             (0x{WIN_CERT_TYPE_PKCS_SIGNED_DATA:04x})"
        ));
    }
    Ok(Some(&table[WIN_CERTIFICATE_HEADER..length]))
}

/* --------------------------------------------------------------- the DER reader */

pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_BIT_STRING: u8 = 0x03;
// No TAG_UTF8_STRING (0x0c) here on purpose: `dn_value_text` decodes BMPString as
// UTF-16BE and every other string choice - UTF8String included, which is what a
// modern CN uses - through the lossy-byte path, so naming it here would only let a
// future edit treat it differently from the ASCII-compatible legacy types.
pub const TAG_BMP_STRING: u8 = 0x1e;
pub const TAG_SEQUENCE: u8 = 0x30;
pub const TAG_SET: u8 = 0x31;
pub const TAG_CONTEXT_0: u8 = 0xa0;
pub const TAG_CONTEXT_1: u8 = 0xa1;
/// `signedData`, the only `ContentInfo` type Authenticode uses.
const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";

/// One DER element: its tag, its own encoding, and its content.
///
/// `bytes` is kept because a certificate's *own* encoding is what the anchor's
/// `cert_sha256` is a digest of — re-encoding it would change the value.
#[derive(Clone, Copy)]
struct Der<'a> {
    tag: u8,
    bytes: &'a [u8],
    value: &'a [u8],
}

/// Attach the step that gave out to a parse failure, so a refusal is diagnosable
/// from the log line rather than from the source.
trait DerContext<T> {
    fn der(self, what: &'static str) -> Result<T, String>;
}

impl<T> DerContext<T> for Option<T> {
    fn der(self, what: &'static str) -> Result<T, String> {
        self.ok_or_else(|| format!("Authenticode: {what}"))
    }
}

/// Read one DER element and return whatever follows it.
///
/// DER only, and deliberately unforgiving: indefinite lengths, non-minimal length
/// encodings and multi-byte tag numbers stop the parse instead of being guessed
/// at, because a reader that guesses about a signature container is a reader an
/// attacker gets to choose the reading of.
fn read_der(input: &[u8]) -> Option<(Der<'_>, &[u8])> {
    if input.len() < 2 {
        return None;
    }
    let tag = input[0];
    if tag & 0x1f == 0x1f {
        return None;
    }
    let first = input[1];
    let (length, body_start) = if first & 0x80 == 0 {
        (usize::from(first), 2usize)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let raw = span(input, 2, count)?;
        if raw[0] == 0 {
            return None;
        }
        let mut acc: usize = 0;
        for byte in raw {
            acc = (acc << 8) | usize::from(*byte);
        }
        (acc, 2 + count)
    };
    let body_end = body_start.checked_add(length)?;
    let value = input.get(body_start..body_end)?;
    Some((
        Der {
            tag,
            bytes: &input[..body_end],
            value,
        },
        &input[body_end..],
    ))
}

/// Every element inside a constructed value; `None` unless they all parse.
fn der_children(value: &[u8]) -> Option<Vec<Der<'_>>> {
    let mut out = Vec::new();
    let mut rest = value;
    while !rest.is_empty() {
        let (child, tail) = read_der(rest)?;
        out.push(child);
        rest = tail;
    }
    Some(out)
}

/// The dotted form of an OBJECT IDENTIFIER value, e.g. `2.5.4.3` for a CN.
fn oid_dotted(value: &[u8]) -> Option<String> {
    let (first, rest) = value.split_first()?;
    let first = u64::from(*first);
    let mut arcs = vec![first / 40, first % 40];
    let mut current: u64 = 0;
    for byte in rest {
        current = (current << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            arcs.push(current);
            current = 0;
        }
    }
    if rest.last().is_some_and(|last| last & 0x80 != 0) {
        return None;
    }
    Some(
        arcs.iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join("."),
    )
}

/// The short names a code-signing subject actually uses. Anything else is printed
/// by its dotted OID, which is what .NET's `X500Name.Format` does, so the text here
/// and the anchor's `issued_cn` read the same way.
fn attribute_name(dotted: &str) -> String {
    match dotted {
        "2.5.4.3" => "CN",
        "2.5.4.5" => "SERIALNUMBER",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "1.2.840.113549.1.9.1" => "EMAILADDRESS",
        other => return format!("OID.{other}"),
    }
    .to_string()
}

/// RFC 4514 escaping: the characters that separate RDNs and ATVs, a leading `#`,
/// and the spaces a reader would otherwise trim.
fn escape_dn_text(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for (index, ch) in value.char_indices() {
        let boundary = matches!(ch, ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=');
        let edge_space = ch == ' ' && (index == 0 || index + ch.len_utf8() == value.len());
        if boundary || edge_space || (ch == '#' && index == 0) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// The text of one attribute value, for the two string encodings a subject uses.
fn dn_value_text(element: &Der<'_>) -> String {
    let decoded = if element.tag == TAG_BMP_STRING {
        let units: Vec<u16> = element
            .value
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(element.value).into_owned()
    };
    escape_dn_text(&decoded)
}

/// A DER `Name` (an RDNSequence) as text.
fn dn_text(name: &Der<'_>) -> Result<String, String> {
    if name.tag != TAG_SEQUENCE {
        return Err("Authenticode: a distinguished name is not a SEQUENCE".to_string());
    }
    let mut rdns = Vec::new();
    for rdn in der_children(name.value).der("a distinguished name does not parse")? {
        if rdn.tag != TAG_SET {
            return Err("Authenticode: an RDN is not a SET".to_string());
        }
        let mut atvs = Vec::new();
        for atv in der_children(rdn.value).der("an RDN does not parse")? {
            let fields =
                der_children(atv.value).der("an attribute type and value does not parse")?;
            if fields.len() != 2 || fields[0].tag != 0x06 {
                return Err(
                    "Authenticode: an attribute type and value is not OID-plus-value".to_string(),
                );
            }
            let dotted = oid_dotted(fields[0].value)
                .der("an attribute's object identifier does not parse")?;
            atvs.push(format!(
                "{}={}",
                attribute_name(&dotted),
                dn_value_text(&fields[1])
            ));
        }
        if atvs.is_empty() {
            return Err("Authenticode: an RDN holds no attribute".to_string());
        }
        rdns.push(atvs.join("+"));
    }
    if rdns.is_empty() {
        return Err("Authenticode: the subject is an empty name".to_string());
    }
    Ok(rdns.join(", "))
}

/* --------------------------------------------- the PKCS#7, and who it was signed by */

/// The parts of a certificate this reader needs, by DER element.
struct CertificateParts<'a> {
    serial: Der<'a>,
    issuer: Der<'a>,
    subject: Der<'a>,
}

/// Follow `Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }`.
fn certificate_parts<'a>(cert: &Der<'a>) -> Result<CertificateParts<'a>, String> {
    if cert.tag != TAG_SEQUENCE {
        return Err("Authenticode: a certificate is not a SEQUENCE".to_string());
    }
    let top = der_children(cert.value).der("a certificate does not parse")?;
    if top.len() != 3 || top[2].tag != TAG_BIT_STRING {
        return Err(
            "Authenticode: a certificate is not tbs/signature-algorithm/signature".to_string(),
        );
    }
    if top[1].tag != TAG_SEQUENCE {
        return Err("Authenticode: a certificate's signature algorithm is missing".to_string());
    }
    let tbs = &top[0];
    if tbs.tag != TAG_SEQUENCE {
        return Err("Authenticode: a certificate's TBSCertificate is not a SEQUENCE".to_string());
    }
    let mut fields = der_children(tbs.value).der("a TBSCertificate does not parse")?;
    // `version` is the optional `[0] EXPLICIT` first field.
    if fields
        .first()
        .is_some_and(|field| field.tag == TAG_CONTEXT_0)
    {
        fields.remove(0);
    }
    // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, …
    if fields.len() < 6 {
        return Err(format!(
            "Authenticode: a TBSCertificate holds {} fields, six are required",
            fields.len()
        ));
    }
    let (serial, signature, issuer, validity, subject) =
        (fields[0], fields[1], fields[2], fields[3], fields[4]);
    if serial.tag != TAG_INTEGER
        || signature.tag != TAG_SEQUENCE
        || issuer.tag != TAG_SEQUENCE
        || validity.tag != TAG_SEQUENCE
        || subject.tag != TAG_SEQUENCE
    {
        return Err(
            "Authenticode: a TBSCertificate's fields are not in the order DER defines".to_string(),
        );
    }
    Ok(CertificateParts {
        serial,
        issuer,
        subject,
    })
}

/// The certificates inside a `certificates [0]` bag.
///
/// Two shapes occur: the elements are the certificates' own `SEQUENCE`s, or each is
/// wrapped in the `CHOICE`'s context tag. Both end up as the `SEQUENCE` that *is*
/// the certificate, since that encoding is the digest being pinned.
fn certificate_bag(container: &[u8]) -> Result<Vec<Der<'_>>, String> {
    let mut out = Vec::new();
    for element in der_children(container).der("the certificate bag does not parse")? {
        let mut candidate = element;
        match candidate.tag {
            // `CertificateOrCRL ::= CHOICE { cert [0] …, crl [1] … }`
            TAG_CONTEXT_0 => {
                let inner =
                    der_children(candidate.value).der("a wrapped certificate does not parse")?;
                if inner.len() != 1 {
                    return Err(
                        "Authenticode: a wrapped certificate holds more than one element"
                            .to_string(),
                    );
                }
                candidate = inner[0];
            }
            TAG_CONTEXT_1 => continue,
            TAG_SEQUENCE => {}
            other => {
                return Err(format!(
                    "Authenticode: an element of the certificate bag has tag 0x{other:02x}"
                ))
            }
        }
        if candidate.tag != TAG_SEQUENCE {
            return Err(
                "Authenticode: the certificate bag holds something that is not a certificate"
                    .to_string(),
            );
        }
        certificate_parts(&candidate)?;
        out.push(candidate);
    }
    Ok(out)
}

/// The certificate an Authenticode `ContentInfo`'s signature is attributed to.
///
/// The certificate *bag* is not authenticated: whoever writes the file chooses what
/// else sits in it alongside the signer. So the signer may not be "the bag member
/// whose digest matches the pin" — that rule accepts this project's genuine leaf
/// wrapped into somebody else's signature — it is the certificate `signerInfos[0]`
/// names by issuer *and* serial number, which is the one the signature covers.
fn authenticated_signer(content: &[u8]) -> Result<SignerObservation, String> {
    let (info, rest) = read_der(content).der("the ContentInfo does not parse")?;
    if !rest.is_empty() || info.tag != TAG_SEQUENCE {
        return Err(
            "Authenticode: the certificate table is not one DER-encoded ContentInfo".to_string(),
        );
    }
    let fields = der_children(info.value).der("the ContentInfo's children do not parse")?;
    if fields.len() != 2 || fields[0].tag != 0x06 {
        return Err("Authenticode: the ContentInfo is not OID-plus-content".to_string());
    }
    let kind = oid_dotted(fields[0].value).der("the ContentInfo's OID does not parse")?;
    if kind != OID_SIGNED_DATA {
        return Err(format!(
            "Authenticode: the certificate table carries {kind}, not signedData \
             ({OID_SIGNED_DATA})"
        ));
    }
    if fields[1].tag != TAG_CONTEXT_0 {
        return Err("Authenticode: the signedData content is not explicitly tagged".to_string());
    }
    let wrapped = der_children(fields[1].value).der("the signedData wrapper does not parse")?;
    let signed_data = wrapped.first().der("the signedData wrapper is empty")?;
    if signed_data.tag != TAG_SEQUENCE {
        return Err("Authenticode: SignedData is not a SEQUENCE".to_string());
    }
    let mut parts = der_children(signed_data.value).der("SignedData does not parse")?;
    // version, digestAlgorithms and encapContentInfo are mandatory and unused here;
    // what follows is the optional bag, the optional CRLs and then the signerInfos.
    if parts.len() < 4 {
        return Err(format!(
            "Authenticode: SignedData holds {} fields; version, digestAlgorithms, \
             encapContentInfo and signerInfos are mandatory",
            parts.len()
        ));
    }
    let tail = parts.split_off(3);
    let mut certificates = None;
    let mut signer_infos = None;
    for part in tail {
        match part.tag {
            TAG_CONTEXT_0 if certificates.is_none() => certificates = Some(part),
            TAG_CONTEXT_1 => {}
            TAG_SET if signer_infos.is_none() => signer_infos = Some(part),
            other => {
                return Err(format!(
                    "Authenticode: unexpected tag 0x{other:02x} in the SignedData"
                ))
            }
        }
    }
    let signer_infos = der_children(signer_infos.der("SignedData has no signerInfos")?.value)
        .der("signerInfos does not parse")?;
    let signer_info = signer_infos.first().der("signerInfos is empty")?;
    if signer_infos.len() != 1 {
        return Err(format!(
            "Authenticode: {} top-level signers cannot be attributed to one certificate; a \
             timestamp counter-signature is not one of them",
            signer_infos.len()
        ));
    }
    let signer_fields = der_children(signer_info.value).der("a SignerInfo does not parse")?;
    if signer_fields.len() < 3 || signer_fields[0].tag != TAG_INTEGER {
        return Err("Authenticode: a SignerInfo does not start with its version".to_string());
    }
    let ids = &signer_fields[1];
    if ids.tag != TAG_SEQUENCE {
        return Err(
            "Authenticode: the signer is named by a subject key identifier rather than by \
             issuer and serial number, and this reader does not guess which certificate was meant"
                .to_string(),
        );
    }
    let wanted = der_children(ids.value).der("IssuerAndSerialNumber does not parse")?;
    if wanted.len() != 2 || wanted[0].tag != TAG_SEQUENCE || wanted[1].tag != TAG_INTEGER {
        return Err("Authenticode: IssuerAndSerialNumber is not issuer-plus-serial".to_string());
    }
    let mut matches = Vec::new();
    for cert in certificate_bag(
        certificates
            .der("SignedData carries no certificates")?
            .value,
    )? {
        let parts = certificate_parts(&cert)?;
        if parts.issuer.bytes == wanted[0].bytes && parts.serial.bytes == wanted[1].bytes {
            matches.push((cert, parts));
        }
    }
    let candidates = matches.len();
    let (cert, parts) = match (matches.into_iter().next(), candidates) {
        (Some(one), 1) => one,
        (None, _) => {
            return Err(
                "Authenticode: the certificate the signature is attributed to is not in the \
                 message"
                    .to_string(),
            )
        }
        (Some(_), count) => {
            return Err(format!(
                "Authenticode: {count} certificates in the message carry the same issuer and \
                 serial number"
            ))
        }
    };
    Ok(SignerObservation {
        leaf_sha256: sha256_hex(cert.bytes),
        subject: dn_text(&parts.subject)?,
    })
}

/// What [`open_for_verification`] holds: the file, and the bytes it read.
struct Opened {
    file: fs::File,
    bytes: Vec<u8>,
}

/// Open once and keep a read-only handle that denies writes and delete/rename.
/// The caller must retain the returned handle until process creation completes.
pub fn open_for_verification(path: &Path) -> Result<(fs::File, Vec<u8>), String> {
    #[cfg(windows)]
    let file = open_locked_windows(path)?;
    #[cfg(not(windows))]
    let file = fs::File::open(path).map_err(|e| cannot_open(path, e))?;
    let opened = Opened::read(file, path)?;
    Ok((opened.file, opened.bytes))
}

#[cfg(windows)]
fn open_locked_windows(path: &Path) -> Result<fs::File, String> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    // Resolve only CreateFileW at runtime so this witness adds no new
    // load-time API import to the desktop or its isolated test image.
    type CreateFileFn = unsafe extern "system" fn(
        *const u16,
        u32,
        u32,
        *const std::ffi::c_void,
        u32,
        u32,
        HANDLE,
    ) -> HANDLE;
    let kernel32: Vec<u16> = "kernel32.dll".encode_utf16().chain(Some(0)).collect();
    let module = unsafe { GetModuleHandleW(kernel32.as_ptr()) };
    if module.is_null() {
        return Err(cannot_open(path, std::io::Error::last_os_error()));
    }
    let address = unsafe { GetProcAddress(module, c"CreateFileW".as_ptr().cast()) }
        .ok_or_else(|| cannot_open(path, std::io::Error::last_os_error()))?;
    let create_file: CreateFileFn = unsafe { std::mem::transmute(address) };
    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let handle = unsafe {
        create_file(
            wide_path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(cannot_open(path, std::io::Error::last_os_error()));
    }
    // SAFETY: CreateFileW returned a valid owned handle; File closes it on drop.
    Ok(unsafe { fs::File::from_raw_handle(handle) })
}

/// A refusal from the witnessing step itself.
///
/// A `String` rather than `CommandError` on purpose: `CommandError` carries an
/// `impl From<tauri::Error>` in `error.rs`, and anything that reaches for it drags the
/// whole Tauri runtime — `comctl32`, `user32`, the webview loader, the async runtime —
/// into the binary that references it, which then dies at load with `0xc0000139`
/// before a single test runs. See this file's header.
fn cannot_open(path: &Path, why: impl std::fmt::Display) -> String {
    format!("cannot witness {} for verification: {why}", path.display())
}

impl Opened {
    fn read(mut file: fs::File, path: &Path) -> Result<Self, String> {
        use std::io::Read;
        let mut bytes = Vec::new();
        if let Ok(meta) = file.metadata() {
            // A reservation sized to the file, capped so a sparse or lying size cannot
            // ask for a huge allocation up front; `read_to_end` grows as it needs to.
            let hint = usize::try_from(meta.len()).unwrap_or(0).min(16 << 20);
            bytes.reserve(hint);
        }
        file.read_to_end(&mut bytes)
            .map_err(|e| cannot_open(path, e))?;
        Ok(Self { file, bytes })
    }
}
