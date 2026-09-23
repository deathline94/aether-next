//! The witness, tested on bytes.
//!
//! This target compiles `src/trust_reader.rs` directly (`#[path]`), rather than
//! reaching through `aether_desktop_lib`, for the linker reason written at the top of
//! that file: this test must not link the Tauri runtime, whose common-controls
//! import prevents a plain test executable from loading on Windows.
//!
//! Same source file as the one the release binary compiles — this is not a copy that
//! can drift into agreeing with itself.
#![allow(dead_code)] // the reader is compiled whole; this target uses parts of it

#[path = "../src/trust_reader.rs"]
mod reader;

use reader::{
    authenticode_signer, open_for_verification, sha256_hex, witness_bytes, BinaryWitness,
    WIN_CERTIFICATE_HEADER, WIN_CERT_TYPE_PKCS_SIGNED_DATA,
};
use std::fs;
use std::path::Path;

fn subject_names_common_name(subject: &str, expected_cn: &str) -> bool {
    subject
        .split(", ")
        .any(|part| part == format!("CN={expected_cn}"))
}

fn committed_wintun_cert_pin() -> String {
    let anchor: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../packaging/trust/engine-trust.json"
    ))
    .expect("parse committed anchor");
    anchor["files"]
        .as_array()
        .and_then(|files| files.iter().find(|file| file["name"] == "wintun.dll"))
        .and_then(|file| file["cert_sha256"].as_str())
        .expect("the anchor pins wintun.dll's leaf")
        .to_string()
}

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_UTF8_STRING: u8 = 0x0c;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_CONTEXT_0: u8 = 0xa0;

// Small DER/PE builders, enough of each format to be a real parse target. The
// fixtures are *assembled* from tag-length-value bytes rather than decoded with the
// reader, so a reader that agreed with itself but not with DER still fails here —
// and `packaging/wintun.dll`, below, is the case that catches it.
const FAKE_PE_LFANEW: usize = 0x40;
const FAKE_PE_OPTIONAL: usize = 0x58;
const FAKE_PE_CERT_OFFSET: usize = 0x200;

fn der(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = value.len();
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let mut bytes = Vec::new();
        let mut rest = length;
        while rest > 0 {
            bytes.push((rest & 0xff) as u8);
            rest >>= 8;
        }
        bytes.reverse();
        out.push(0x80 | bytes.len() as u8);
        out.extend_from_slice(&bytes);
    }
    out.extend_from_slice(value);
    out
}

/// Several already-encoded elements, one after another: how a SEQUENCE of them is
/// actually written.
fn flatten(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.iter().flatten().copied().collect()
}

/// An OBJECT IDENTIFIER's full TLV, with the first two arcs packed into one byte and
/// the rest in base-128.
fn oid(arcs: &[u64]) -> Vec<u8> {
    let first = arcs.first().copied().unwrap_or(0);
    let second = arcs.get(1).copied().unwrap_or(0);
    let mut value = vec![(first * 40 + second) as u8];
    for arc in arcs.iter().skip(2) {
        let mut chunk = vec![(arc & 0x7f) as u8];
        let mut rest = arc >> 7;
        while rest > 0 {
            chunk.insert(0, ((rest & 0x7f) | 0x80) as u8);
            rest >>= 7;
        }
        value.extend_from_slice(&chunk);
    }
    der(0x06, &value)
}

/// One `AttributeTypeAndValue`: an OID and a UTF8String value.
fn atv(arcs: &[u64], value: &str) -> Vec<u8> {
    der(
        TAG_SEQUENCE,
        &flatten(&[oid(arcs), der(TAG_UTF8_STRING, value.as_bytes())]),
    )
}

/// A single-RDN distinguished name, `CN=<value>`, as a DER `Name`.
fn name(cn: &str) -> Vec<u8> {
    der(TAG_SEQUENCE, &der(TAG_SET, &atv(&[2, 5, 4, 3], cn)))
}

/// A stand-in signing leaf: a real `Certificate` shape, with the subject and serial
/// number the caller names, and the two elements a `SignerInfo` uses to identify it.
struct FakeCert {
    der: Vec<u8>,
    issuer: Vec<u8>,
    serial: Vec<u8>,
    cn: String,
}

fn fake_certificate(cn: &str, serial: u8) -> FakeCert {
    let issuer = name("Fake Code Signing CA");
    let serial_tlv = der(TAG_INTEGER, &[0x00, serial]);
    let algorithm = der(TAG_SEQUENCE, &oid(&[1, 2, 840, 113549, 1, 1, 11]));
    let validity = der(
        TAG_SEQUENCE,
        &flatten(&[der(0x17, b"260101000000Z"), der(0x17, b"291231235959Z")]),
    );
    let subject = name(cn);
    let spki = der(
        TAG_SEQUENCE,
        &flatten(&[algorithm.clone(), der(TAG_BIT_STRING, &[0x00, 0x01, 0x02])]),
    );
    let tbs = der(
        TAG_SEQUENCE,
        &flatten(&[
            // `version` is the optional `[0] EXPLICIT INTEGER` first field: keeping it
            // present is what exercises the reader's skip.
            der(TAG_CONTEXT_0, &der(TAG_INTEGER, &[2])),
            serial_tlv.clone(),
            algorithm.clone(),
            issuer.clone(),
            validity,
            subject,
            spki,
        ]),
    );
    FakeCert {
        der: der(
            TAG_SEQUENCE,
            &flatten(&[tbs, algorithm, der(TAG_BIT_STRING, &[0x00, 0x04, 0x05])]),
        ),
        issuer,
        serial: serial_tlv,
        cn: cn.to_string(),
    }
}

/// A PKCS#7 `ContentInfo` whose one `SignerInfo` names `signer` by issuer *and*
/// serial number, carrying every certificate in `bag`.
fn fake_pkcs7(signer: &FakeCert, bag: &[&FakeCert]) -> Vec<u8> {
    let digest_algorithm = der(TAG_SEQUENCE, &oid(&[1, 2, 840, 113549, 1, 7, 1]));
    let mut certificates = Vec::new();
    for cert in bag {
        certificates.extend_from_slice(&cert.der);
    }
    let signer_info = flatten(&[
        der(TAG_INTEGER, &[1]), // version
        der(
            TAG_SEQUENCE,
            &flatten(&[signer.issuer.clone(), signer.serial.clone()]),
        ), // issuerAndSerialNumber
        digest_algorithm.clone(),
        der(TAG_SEQUENCE, &oid(&[1, 2, 840, 113549, 1, 1, 1])), // digestEncryptionAlgorithm
        der(0x04, b"this fixture carries no real signature"),   // encryptedDigest
    ]);
    let signed_data = der(
        TAG_SEQUENCE,
        &flatten(&[
            der(TAG_INTEGER, &[1]),                                 // version
            der(TAG_SET, &digest_algorithm),                        // digestAlgorithms
            der(TAG_SEQUENCE, &oid(&[1, 2, 840, 113549, 1, 7, 1])), // encapContentInfo
            der(TAG_CONTEXT_0, &certificates),                      // certificates
            der(TAG_SET, &der(TAG_SEQUENCE, &signer_info)),         // signerInfos
        ]),
    );
    der(
        TAG_SEQUENCE,
        &flatten(&[
            oid(&[1, 2, 840, 113549, 1, 7, 2]), // signedData
            der(TAG_CONTEXT_0, &signed_data),
        ]),
    )
}

/// A PE image whose certificate table holds `pkcs7`: MS-DOS magic, a real
/// `e_lfanew`, a PE32+ optional header with five data directories, and a
/// `WIN_CERTIFICATE` padded out to the eight bytes the format asks for.
fn fake_signed_pe(pkcs7: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; FAKE_PE_CERT_OFFSET];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&(FAKE_PE_LFANEW as u32).to_le_bytes());
    bytes[FAKE_PE_LFANEW..FAKE_PE_LFANEW + 4].copy_from_slice(b"PE\0\0");
    bytes[FAKE_PE_LFANEW + 4..FAKE_PE_LFANEW + 6].copy_from_slice(&0x8664u16.to_le_bytes());
    // SizeOfOptionalHeader sits 16 bytes into the COFF file header, which starts four
    // bytes after the PE signature.
    bytes[FAKE_PE_OPTIONAL - 4..FAKE_PE_OPTIONAL - 2].copy_from_slice(&240u16.to_le_bytes());
    bytes[FAKE_PE_OPTIONAL..FAKE_PE_OPTIONAL + 2].copy_from_slice(&0x20bu16.to_le_bytes());
    bytes[FAKE_PE_OPTIONAL + 108..FAKE_PE_OPTIONAL + 112].copy_from_slice(&5u32.to_le_bytes());

    let claimed = (WIN_CERTIFICATE_HEADER + pkcs7.len()) as u32;
    let padded = (claimed as usize).div_ceil(8) * 8;
    bytes.resize(FAKE_PE_CERT_OFFSET + padded, 0);
    bytes[FAKE_PE_CERT_OFFSET..FAKE_PE_CERT_OFFSET + 4].copy_from_slice(&claimed.to_le_bytes());
    bytes[FAKE_PE_CERT_OFFSET + 4..FAKE_PE_CERT_OFFSET + 6]
        .copy_from_slice(&0x0200u16.to_le_bytes());
    bytes[FAKE_PE_CERT_OFFSET + 6..FAKE_PE_CERT_OFFSET + 8]
        .copy_from_slice(&WIN_CERT_TYPE_PKCS_SIGNED_DATA.to_le_bytes());
    let payload = FAKE_PE_CERT_OFFSET + WIN_CERTIFICATE_HEADER;
    bytes[payload..payload + pkcs7.len()].copy_from_slice(pkcs7);

    // The certificate directory's "RVA" is a raw file offset, and its entry is index 4.
    let directory = FAKE_PE_OPTIONAL + 112 + 4 * 8;
    bytes[directory..directory + 4].copy_from_slice(&(FAKE_PE_CERT_OFFSET as u32).to_le_bytes());
    bytes[directory + 4..directory + 8].copy_from_slice(&(padded as u32).to_le_bytes());
    bytes
}

/// Both facts, taken the way the pipeline takes them.
fn witness_of(bytes: &[u8]) -> BinaryWitness {
    witness_bytes(bytes).expect("the fixture is followable")
}

/// The gap this closes, stated as the pair that used to be reachable: the digest of
/// one read and the signer of another.
///
/// `verify_authenticode_signature` used to ask `powershell.exe
/// Get-AuthenticodeSignature` who signed the *path*, after `file_sha256_hex` had
/// already hashed it and closed its handle. A writer who replaced the file in between
/// handed the gate `(good bytes' digest, bad bytes' signer)` — a verdict about a file
/// that never existed. `witness_bytes` takes one slice, so the two facts move
/// together and the mixed pair cannot be assembled by anything in the pipeline.
#[test]
fn a_witness_cannot_pair_one_buffers_digest_with_another_buffers_signer() {
    let witnessed = fake_certificate("witnessed-signer", 0x11);
    let swapped_in = fake_certificate("witnessed-signer", 0x22);
    // Same subject, same length, different certificate: the swap a writer makes does
    // not have to change the file's size for the digest to move.
    assert_eq!(
        witnessed.der.len(),
        swapped_in.der.len(),
        "fixture leaves must be the same size"
    );

    let good = fake_signed_pe(&fake_pkcs7(&witnessed, &[&witnessed]));
    let bad = fake_signed_pe(&fake_pkcs7(&swapped_in, &[&swapped_in]));
    assert_ne!(good, bad);
    assert_eq!(good.len(), bad.len(), "only bytes moved, not the layout");

    let wg = witness_of(&good);
    let wb = witness_of(&bad);
    assert_eq!(wg.file_sha256(), sha256_hex(&good));
    assert_eq!(wb.file_sha256(), sha256_hex(&bad));
    assert_ne!(
        wg.file_sha256(),
        wb.file_sha256(),
        "the two buffers must hash apart, or this proves nothing"
    );
    let good_leaf = wg.signer().expect("signed").leaf_sha256().to_string();
    let bad_leaf = wb.signer().expect("signed").leaf_sha256().to_string();
    assert_ne!(
        good_leaf, bad_leaf,
        "and the signer must move with the digest, not stay behind on the first read"
    );
    // The only pairs the gate can ever see: (good, good-leaf) and (bad, bad-leaf).
    assert_eq!(good_leaf, sha256_hex(&witnessed.der));
    assert_eq!(bad_leaf, sha256_hex(&swapped_in.der));
    assert_ne!(
        wb.file_sha256(),
        good_leaf,
        "a digest and a leaf are not interchangeable values"
    );
}

/// A PKCS#7's certificate *bag* is not authenticated: whoever writes the file chooses
/// what else sits in it. So the signer may not be "the bag member whose digest matches
/// the pin" — that rule accepts this project's genuine leaf wrapped into somebody
/// else's signature — it must be the certificate `signerInfos[0]` names, by issuer and
/// serial number.
#[test]
fn the_signer_is_the_one_the_signature_names_not_the_pinned_looking_one_in_the_bag() {
    let genuine = fake_certificate("deathline94", 0x33);
    let attacker = fake_certificate("witnessed-signer", 0x44);
    let genuine_leaf = sha256_hex(&genuine.der);

    // Signed by `attacker`, with the *genuine* leaf bundled alongside it: the pin under
    // test is present in the message, and choosing by pin would take it.
    let wrapped = fake_signed_pe(&fake_pkcs7(&attacker, &[&attacker, &genuine]));
    let found = witness_of(&wrapped)
        .signer()
        .expect("and names a signer")
        .clone();
    assert_eq!(
        found.leaf_sha256(),
        sha256_hex(&attacker.der),
        "the reader must follow signerInfos[0], not the pinned-looking digest"
    );
    assert_ne!(found.leaf_sha256(), genuine_leaf);
    assert!(
        subject_names_common_name(found.subject(), "witnessed-signer"),
        "the reported subject is {:?}",
        found.subject()
    );
    assert!(
        !subject_names_common_name(found.subject(), "deathline94"),
        "a wrapped-in certificate must not become the publisher"
    );
}

/// The property that makes the refusal worth having: a signature this reader cannot
/// follow is never read as "unsigned", because "unsigned" is a state a development
/// build waves through.
#[test]
fn a_claimed_signature_that_cannot_be_followed_refuses_rather_than_passing() {
    let cert = fake_certificate("witnessed-signer", 0x55);
    let intact = fake_signed_pe(&fake_pkcs7(&cert, &[&cert]));
    assert!(authenticode_signer(&intact)
        .expect("the intact fixture is followable")
        .is_some());

    let mut not_pkcs7 = intact.clone();
    not_pkcs7[FAKE_PE_CERT_OFFSET + WIN_CERTIFICATE_HEADER] = 0x05; // SEQUENCE -> NULL
    let err = authenticode_signer(&not_pkcs7)
        .expect_err("a certificate table that is not a ContentInfo must refuse");
    assert!(err.contains("ContentInfo"), "{err}");

    let mut wrong_type = intact.clone();
    wrong_type[FAKE_PE_CERT_OFFSET + 6..FAKE_PE_CERT_OFFSET + 8]
        .copy_from_slice(&0x0001u16.to_le_bytes());
    let err = authenticode_signer(&wrong_type).expect_err("a non-Authenticode blob refuses");
    assert!(err.contains("0x0001"), "{err}");

    // A zero-length table, and a file that is not a PE at all: both honestly "nothing
    // here claims a signature", which the digest still witnesses.
    let mut unsigned = intact.clone();
    let directory = FAKE_PE_OPTIONAL + 112 + 4 * 8;
    unsigned[directory..directory + 8].copy_from_slice(&0u64.to_le_bytes());
    assert!(authenticode_signer(&unsigned).expect("no table").is_none());
    assert!(authenticode_signer(b"ELF\x02\x01\x01 not a PE")
        .expect("no PE header")
        .is_none());
    assert_eq!(
        witness_of(&unsigned).file_sha256(),
        sha256_hex(&unsigned),
        "an unsigned file is still witnessed"
    );
}

/// The reader is only worth trusting if it agrees with a real one about a real
/// artifact. `packaging/wintun.dll` is committed, genuinely Authenticode-signed by
/// WireGuard LLC over a DigiCert chain, and the anchor pins its leaf — so the pinned
/// digest *is* the expected value, and this is the test that says the DER walk finds
/// that certificate rather than the CA bundled beside it.
#[test]
fn the_committed_wintun_leaf_is_the_one_the_reader_finds() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packaging/wintun.dll");
    let bytes = fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let witness = witness_of(&bytes);
    let signer = witness
        .signer()
        .expect("packaging/wintun.dll is Authenticode-signed")
        .clone();
    let pinned = committed_wintun_cert_pin();
    assert_eq!(
        signer.leaf_sha256(),
        pinned,
        "the reader and the anchor disagree about who signed wintun.dll"
    );
    assert!(
        subject_names_common_name(signer.subject(), "WireGuard LLC"),
        "the subject the reader reports is {:?}, which does not name WireGuard LLC",
        signer.subject()
    );
    assert!(
        !subject_names_common_name(signer.subject(), "DigiCert Inc"),
        "the reader reported the issuing CA rather than the signing leaf: {:?}",
        signer.subject()
    );
    assert_eq!(
        witness.file_sha256(),
        sha256_hex(&fs::read(&path).expect("re-readable")),
        "the digested bytes are not the file"
    );
}

/// No second reader of the path — the load-bearing property, and one a single call
/// cannot show on a machine where nobody is racing the check. So the test is on the
/// shape of the code, the way this repository's node gates test it elsewhere: the
/// witnessing code must not start a child process, and must not ask another program
/// who signed a file.
///
/// The pre-fix `trust.rs` fails this test: `verify_authenticode_signature` spawned
/// `powershell.exe Get-AuthenticodeSignature` after the digest had been taken.
#[test]
fn no_second_reader_of_the_path_survives_in_the_witnessing_code() {
    let trust = include_str!("../src/trust.rs");
    let reader_src = include_str!("../src/trust_reader.rs");
    // Only the code, never the tests under it: the list names the things it forbids.
    let production = trust
        .split("#[cfg(test)]")
        .next()
        .expect("trust.rs has tests");
    let all = format!("{production}{reader_src}");
    for forbidden in [
        "Command::new",
        "process::Command",
        "file_sha256_hex(&verified_path",
    ] {
        assert!(
            !all.contains(forbidden),
            "the signer is being asked of somebody else again: {forbidden:?} appears in the \
             witnessing code"
        );
    }
    assert!(
        production.contains("WinVerifyTrust"),
        "the chain still has to be verified by Windows, in trust.rs itself"
    );
}

/// The witness's handle must exclude concurrent writers until process creation.
#[cfg(windows)]
#[test]
fn witnessing_a_binary_holds_it_against_writers() {
    let dir = std::env::temp_dir().join(format!(
        "aether-witness-share-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("subject.exe");
    let cert = fake_certificate("witnessed-signer", 0x66);
    let fixture = fake_signed_pe(&fake_pkcs7(&cert, &[&cert]));
    fs::write(&path, &fixture).expect("write the fixture");

    let (source, bytes) = open_for_verification(&path).expect("one open");
    assert_eq!(bytes, fixture, "the open read the whole file");
    let mut writer = fs::OpenOptions::new();
    writer.write(true);
    writer
        .open(&path)
        .expect_err("a writer must not be able to move the bytes mid-verification");
    fs::rename(&path, dir.join("replacement.exe"))
        .expect_err("the held handle must also prevent replacing the verified name");
    drop(source);
    fs::rename(&path, dir.join("replacement.exe"))
        .expect("replacement must become possible after the guard is released");
    let _ = fs::remove_dir_all(&dir);
}
