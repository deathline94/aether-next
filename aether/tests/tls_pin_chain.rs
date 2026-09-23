//! T056 / T058 — a pinned SPKI is necessary, never sufficient.
//!
//! The verify callback used to be `move |_ok, ctx| { …pin match… }`, discarding
//! BoringSSL's precomputed result. In BoringSSL the callback's return value
//! *replaces* verification, so the handshake checked nothing but a hash: a leaf
//! that had expired years earlier authenticated, a not-yet-valid leaf
//! authenticated, and any copy of a pinned key authenticated anything. The pin was
//! the whole trust decision, which makes it a long-lived bearer token.
//!
//! These run against certificates generated in-process, so they exercise the real
//! decision — validity window, then pin, then expiry of the pin — without needing
//! an edge to point at.

use aether::tls::accept_pinned_leaf;
use boring::asn1::Asn1Time;
use boring::bn::BigNum;
use boring::hash::MessageDigest;
use boring::pkey::{PKey, Private};
use boring::rsa::Rsa;
use boring::x509::X509Builder;
use boring::x509::{X509NameBuilder, X509};

const HOST: &str = "api.cloudflareclient.com";
const DAY: i64 = 86_400;

fn key() -> PKey<Private> {
    let rsa = Rsa::generate(2048).expect("rsa");
    PKey::from_rsa(rsa).expect("pkey")
}

/// A self-signed leaf whose validity window is `not_before_days .. not_after_days`
/// from today.
fn leaf(key: &PKey<Private>, not_before_days: i64, not_after_days: i64) -> X509 {
    let mut name = X509NameBuilder::new().expect("name builder");
    name.append_entry_by_text("CN", HOST).expect("cn");
    let name = name.build();
    let mut b = X509Builder::new().expect("cert builder");
    b.set_version(2).expect("version");
    let serial = BigNum::from_u32(0x1337)
        .expect("serial")
        .to_asn1_integer()
        .expect("int");
    b.set_serial_number(&serial).expect("serial");
    b.set_subject_name(&name).expect("subject");
    b.set_issuer_name(&name).expect("issuer");
    b.set_pubkey(key).expect("pubkey");
    let at = now() as i64;
    b.set_not_before(&Asn1Time::from_unix(at + not_before_days * DAY).expect("not-before asn1"))
        .expect("not before");
    b.set_not_after(&Asn1Time::from_unix(at + not_after_days * DAY).expect("not-after asn1"))
        .expect("not after");
    b.sign(key, MessageDigest::sha256()).expect("sign");
    b.build()
}

fn spki_sha256(cert: &X509) -> [u8; 32] {
    let der = cert
        .public_key()
        .expect("pubkey")
        .public_key_to_der()
        .expect("spki der");
    let hash = ring::digest::digest(&ring::digest::SHA256, &der);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_ref());
    out
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn accepts(cert: &X509, pins: &[([u8; 32], u64)], at: u64) -> bool {
    accept_pinned_leaf(cert, pins, at, HOST)
}

/// The happy path, so the failures below mean something.
#[test]
fn a_current_leaf_with_a_current_pin_is_accepted() {
    let key = key();
    let cert = leaf(&key, -1, 365);
    let pin = spki_sha256(&cert);
    let at = now();
    assert!(accepts(&cert, &[(pin, at + 86_400)], at));
}

/// The defect this replaces: a pinned key authenticated its leaf forever, because
/// nothing looked at the validity period.
#[test]
fn an_expired_leaf_is_rejected_even_when_its_pin_matches() {
    let key = key();
    let cert = leaf(&key, -400, -1);
    let pin = spki_sha256(&cert);
    let at = now();
    assert!(
        !accepts(&cert, &[(pin, at + 86_400)], at),
        "a matching SPKI must not resurrect a certificate whose window has closed"
    );
}

#[test]
fn a_not_yet_valid_leaf_is_rejected() {
    let key = key();
    let cert = leaf(&key, 5, 365);
    let pin = spki_sha256(&cert);
    let at = now();
    assert!(
        !accepts(&cert, &[(pin, at + 86_400)], at),
        "a misprovisioned or clock-skewed deployment must not be trusted"
    );
}

/// Pin expiry is the rotation deadline. Past it the connection must fail loudly so
/// `masque-pins.json` gets refreshed, rather than silently falling back to no
/// verification.
#[test]
fn an_expired_pin_stops_authenticating() {
    let key = key();
    let cert = leaf(&key, -1, 365);
    let pin = spki_sha256(&cert);
    let at = now();
    assert!(!accepts(&cert, &[(pin, at - 1)], at));
    assert!(accepts(&cert, &[(pin, at + 1)], at));
}

#[test]
fn an_unpinned_key_is_rejected() {
    let honest = key();
    let attacker = key();
    let cert = leaf(&attacker, -1, 365);
    let at = now();
    let pinned = spki_sha256(&leaf(&honest, -1, 365));
    assert!(!accepts(&cert, &[(pinned, at + 86_400)], at));
}

/// One pin set must not authenticate a different host: with a global digest list,
/// whatever edge you happened to pin for became valid for every name the tunnel
/// dialled.
#[test]
fn a_pin_set_only_covers_the_host_it_is_recorded_under() {
    use aether::trust::PinSet;
    let key = key();
    let cert = leaf(&key, -1, 365);
    let pin = spki_sha256(&cert);
    let set = PinSet {
        host: "api.cloudflareclient.com".into(),
        pins: vec![aether::trust::Pin {
            spki_sha256: pin.iter().map(|b| format!("{b:02x}")).collect(),
            expires_unix: now() + 86_400,
            cert_sha256: None,
            note: None,
        }],
        require_hostname: false,
        require_chain: false,
    };
    let mut builder =
        boring::ssl::SslContextBuilder::new(boring::ssl::SslMethod::tls()).expect("ctx");
    assert!(
        aether::tls::install_pin_verification(&mut builder, std::slice::from_ref(&set), HOST)
            .is_ok()
    );
    assert!(
        aether::tls::install_pin_verification(
            &mut builder,
            std::slice::from_ref(&set),
            "mask.cloudflare.com"
        )
        .is_err(),
        "a host with no pin set must be refused outright, not verified by another host's pins"
    );
    assert!(
        aether::tls::install_pin_verification(&mut builder, &[], HOST).is_err(),
        "an absent pin set must not mean an unverified connection"
    );
}

// ─── the `require_chain` arm, driven through a real handshake ───────────────
//
// Every fixture above calls `accept_pinned_leaf` directly, which is the pin half
// of the callback. The other half — `if require_chain && !(ok && ctx.verify_cert())`
// — only ever runs inside a BoringSSL handshake, and until now no test in this
// file built a pin set with `require_chain: true`, so the branch that decides
// whether the shipped trust file means anything has never executed.

use aether::trust::PinSet;
use boring::ssl::{Ssl, SslContextBuilder, SslMethod, SslVerifyMode};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

fn pin_set(cert: &X509, require_chain: bool) -> PinSet {
    let spki = spki_sha256(cert);
    PinSet {
        host: HOST.into(),
        pins: vec![aether::trust::Pin {
            spki_sha256: spki.iter().map(|b| format!("{b:02x}")).collect(),
            expires_unix: now() + 86_400,
            cert_sha256: None,
            note: None,
        }],
        require_hostname: false,
        require_chain,
    }
}

/// Run one real loopback TLS handshake with `install_pin_verification` on the
/// client, and report whether it completed.
fn handshake(leaf: &X509, leaf_key: &PKey<Private>, sets: &[PinSet]) -> Result<(), String> {
    const TIMEOUT: Duration = Duration::from_secs(15);

    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();

    let server_leaf = leaf.clone();
    let server_key = leaf_key.clone();
    let server = std::thread::spawn(move || -> Result<(), String> {
        let mut b = SslContextBuilder::new(SslMethod::tls()).map_err(|e| e.to_string())?;
        b.set_certificate(&server_leaf).map_err(|e| e.to_string())?;
        b.set_private_key(&server_key).map_err(|e| e.to_string())?;
        b.set_verify(SslVerifyMode::NONE);
        let ctx = b.build();
        let (sock, _) = listener.accept().map_err(|e| e.to_string())?;
        let _ = sock.set_read_timeout(Some(TIMEOUT));
        let _ = sock.set_write_timeout(Some(TIMEOUT));
        let stream = Ssl::new(&ctx)
            .map_err(|e| e.to_string())?
            .accept(sock)
            .map_err(|e| format!("server side: {e}"))?;
        drop(stream);
        Ok(())
    });

    let mut b = SslContextBuilder::new(SslMethod::tls()).map_err(|e| e.to_string())?;
    aether::tls::install_pin_verification(&mut b, sets, HOST)
        .map_err(|e| format!("pin installation: {e}"))?;
    let ctx = b.build();

    let sock = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    let _ = sock.set_read_timeout(Some(TIMEOUT));
    let _ = sock.set_write_timeout(Some(TIMEOUT));
    let connected = Ssl::new(&ctx)
        .map_err(|e| e.to_string())?
        .connect(sock)
        .map(|_| ())
        .map_err(|e| format!("client side: {e}"));

    let _ = server.join();
    connected
}

/// A self-signed leaf is exactly the case `require_chain` exists to refuse: it is
/// in no root store, so BoringSSL's own verdict is "fail", and only a
/// `require_chain=false` file lets the pinned digest carry the connection alone.
#[test]
fn require_chain_honours_boringssls_verdict_and_false_pins_only() {
    let key = key();
    let cert = leaf(&key, -1, 365);

    // The shipped configuration, restated as a fixture: pin matches, no chain.
    handshake(&cert, &key, std::slice::from_ref(&pin_set(&cert, false)))
        .expect("pins-only must accept the leaf it pins");

    // The branch no earlier test in this file reached.
    let err = handshake(&cert, &key, std::slice::from_ref(&pin_set(&cert, true)))
        .expect_err("require_chain must not accept a leaf with no chain to validate");
    assert!(
        err.contains("client side"),
        "the handshake must fail on the client's verification, not somewhere else: {err}"
    );
}

// The positive half of `require_chain` — a leaf whose chain *does* validate — was
// not asserted here for a while on the grounds that it needs a fixture CA written
// to a trust store and that only a live CA-issued edge really answers the
// question. Both halves are now below: the live pass was run on 2026-09-23 and
// `masque-pins.json` records what it found (a Let's Encrypt YE2-issued leaf with
// a chain that verifies on the anycast edges, a self-signed leaf with none on the
// MASQUE VIPs), and a fixture CA reproduces the verifying case deterministically.

/// The host names the shipped file is written about, so a regression here is a
/// regression against the thing that ships.
const MASQUE_SNI: &str = "consumer-masque.cloudflareclient.com";
const MASQUE_PROXY_SNI: &str = "consumer-masque-proxy.cloudflareclient.com";

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// [`pin_set`] with the host and the two knobs spelled out, because the tests
/// below are about *which host* a digest is recorded under.
fn pin_for(host: &str, cert: &X509, require_chain: bool, require_hostname: bool) -> PinSet {
    let spki = spki_sha256(cert);
    PinSet {
        host: host.into(),
        pins: vec![aether::trust::Pin {
            spki_sha256: hex32(&spki),
            expires_unix: now() + 86_400,
            cert_sha256: None,
            note: None,
        }],
        require_hostname,
        require_chain,
    }
}

/// A leaf for `name`, issued by `ca` (so a chain exists), with `name` in the SAN.
fn issued_leaf(name: &str, ca: &X509, ca_key: &PKey<Private>, key: &PKey<Private>) -> X509 {
    let mut subject = X509NameBuilder::new().expect("name builder");
    subject.append_entry_by_text("CN", name).expect("cn");
    let subject = subject.build();

    let mut b = X509Builder::new().expect("cert builder");
    b.set_version(2).expect("version");
    let serial = BigNum::from_u32(0x1338)
        .expect("serial")
        .to_asn1_integer()
        .expect("int");
    b.set_serial_number(&serial).expect("serial");
    b.set_subject_name(&subject).expect("subject");
    b.set_issuer_name(ca.subject_name()).expect("issuer");
    b.set_pubkey(key).expect("pubkey");
    let at = now() as i64;
    b.set_not_before(&Asn1Time::from_unix(at - DAY).expect("not-before asn1"))
        .expect("not before");
    b.set_not_after(&Asn1Time::from_unix(at + 90 * DAY).expect("not-after asn1"))
        .expect("not after");
    // The extension the measurement recorded on the live CA-issued leaf, and the
    // one a name check is decided by. `x509v3_context` is borrowed inline for the
    // duration of the `build` call only, exactly as boring's own tests do it; the
    // issuer argument is `None` because a SAN does not consult it.
    let san = boring::x509::extension::SubjectAlternativeName::new()
        .dns(name)
        .build(&b.x509v3_context(None, None))
        .expect("san");
    b.append_extension(san).expect("san extension");
    b.sign(ca_key, MessageDigest::sha256()).expect("sign");
    b.build()
}

/// A self-signed CA, trusted by nothing except the client that is told about it.
fn fixture_ca() -> (X509, PKey<Private>) {
    let key = key();
    let mut name = X509NameBuilder::new().expect("name builder");
    name.append_entry_by_text("CN", "Aether fixture CA")
        .expect("cn");
    let name = name.build();

    let mut b = X509Builder::new().expect("cert builder");
    b.set_version(2).expect("version");
    let serial = BigNum::from_u32(0x1339)
        .expect("serial")
        .to_asn1_integer()
        .expect("int");
    b.set_serial_number(&serial).expect("serial");
    b.set_subject_name(&name).expect("subject");
    b.set_issuer_name(&name).expect("issuer");
    b.set_pubkey(&key).expect("pubkey");
    let at = now() as i64;
    b.set_not_before(&Asn1Time::from_unix(at - DAY).expect("not-before asn1"))
        .expect("not before");
    b.set_not_after(&Asn1Time::from_unix(at + 3650 * DAY).expect("not-after asn1"))
        .expect("not after");
    let bc = boring::x509::extension::BasicConstraints::new()
        .critical()
        .ca()
        .build()
        .expect("basic constraints");
    b.append_extension(bc).expect("bc extension");
    let ku = boring::x509::extension::KeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .build()
        .expect("key usage");
    b.append_extension(ku).expect("ku extension");
    b.sign(&key, MessageDigest::sha256()).expect("sign");
    (b.build(), key)
}

/// [`handshake`] with the two things the shipped file's knobs turn on: the client
/// puts `name` in the ClientHello *and* registers it as the verification subject
/// (`param_mut().set_host`, which is what boring's `setup_verify_hostname` does
/// behind `ConnectConfiguration::set_verify_hostname(true)` — the exact call
/// `masque_h2.rs` gates on `PinSet::require_hostname`), and it is given a trust
/// anchor for the chain arm.
///
/// `handshake` above is left untouched so the pin-only cases keep running through
/// exactly the path that is green today.
fn handshake_with_name(
    pin_host: &str,
    name: &str,
    leaf: &X509,
    leaf_key: &PKey<Private>,
    sets: &[PinSet],
    anchor: Option<&X509>,
) -> Result<(), String> {
    const TIMEOUT: Duration = Duration::from_secs(15);

    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();

    let server_leaf = leaf.clone();
    let server_key = leaf_key.clone();
    let server = std::thread::spawn(move || -> Result<(), String> {
        let mut b = SslContextBuilder::new(SslMethod::tls()).map_err(|e| e.to_string())?;
        b.set_certificate(&server_leaf).map_err(|e| e.to_string())?;
        b.set_private_key(&server_key).map_err(|e| e.to_string())?;
        b.set_verify(SslVerifyMode::NONE);
        let ctx = b.build();
        let (sock, _) = listener.accept().map_err(|e| e.to_string())?;
        let _ = sock.set_read_timeout(Some(TIMEOUT));
        let _ = sock.set_write_timeout(Some(TIMEOUT));
        let stream = Ssl::new(&ctx)
            .map_err(|e| e.to_string())?
            .accept(sock)
            .map_err(|e| format!("server side: {e}"))?;
        drop(stream);
        Ok(())
    });

    let mut b = SslContextBuilder::new(SslMethod::tls()).map_err(|e| e.to_string())?;
    aether::tls::install_pin_verification(&mut b, sets, pin_host)
        .map_err(|e| format!("pin installation: {e}"))?;
    if let Some(ca) = anchor {
        // The store the precomputed chain verdict is built against.
        b.cert_store_mut()
            .add_cert(ca.clone())
            .map_err(|e| format!("trust anchor: {e}"))?;
    }
    let ctx = b.build();

    let sock = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    let _ = sock.set_read_timeout(Some(TIMEOUT));
    let _ = sock.set_write_timeout(Some(TIMEOUT));
    let mut ssl = Ssl::new(&ctx).map_err(|e| e.to_string())?;
    ssl.set_hostname(name).map_err(|e| format!("sni: {e}"))?;
    ssl.param_mut()
        .set_host(name)
        .map_err(|e| format!("verify hostname: {e}"))?;
    let connected = ssl
        .connect(sock)
        .map(|_| ())
        .map_err(|e| format!("client side: {e}"));

    let _ = server.join();
    connected
}

/// ITEM 12, the failure mode the pre-measurement file was one step from: both
/// hosts carried both digests, so whichever edge answered looked authenticated —
/// and the moment the digests were split by guesswork instead of by observation,
/// a host would be credited with a key it never presents.
///
/// Both directions are asserted. A rejection that also rejects the correct
/// assignment proves nothing.
#[test]
fn a_host_credited_with_a_key_it_does_not_present_is_rejected() {
    let masque_key = key();
    let masque_leaf = leaf(&masque_key, -1, 365);
    let proxy_key = key();
    let proxy_leaf = leaf(&proxy_key, -1, 365);

    // Cross-assigned: each host pins the *other* host's key.
    let crossed = vec![
        pin_for(MASQUE_SNI, &proxy_leaf, false, false),
        pin_for(MASQUE_PROXY_SNI, &masque_leaf, false, false),
    ];
    let err = handshake_with_name(
        MASQUE_SNI,
        MASQUE_SNI,
        &masque_leaf,
        &masque_key,
        &crossed,
        None,
    )
    .expect_err("a pin the presenting peer does not hold must not authenticate it");
    assert!(
        err.contains("client side"),
        "the failure must be the verification, not the wiring: {err}"
    );

    // Each digest under the host that actually presents it.
    let measured = vec![
        pin_for(MASQUE_SNI, &masque_leaf, false, false),
        pin_for(MASQUE_PROXY_SNI, &proxy_leaf, false, false),
    ];
    handshake_with_name(
        MASQUE_SNI,
        MASQUE_SNI,
        &masque_leaf,
        &masque_key,
        &measured,
        None,
    )
    .expect("the same handshake must pass once the digest sits under its own host");

    // …and the other host keeps its own decision: one host's key cannot be spent
    // on the other, which is what a single global digest list allowed.
    let err = handshake_with_name(
        MASQUE_PROXY_SNI,
        MASQUE_PROXY_SNI,
        &masque_leaf,
        &masque_key,
        &measured,
        None,
    )
    .expect_err("masque's key must not authenticate the proxy host");
    assert!(err.contains("client side"), "{err}");
}

/// The positive arm `require_chain` exists for, and the reason it stays `false`
/// for the MASQUE VIPs in `masque-pins.json`: a CA-issued peer whose chain
/// verifies and whose SAN covers the dialled name is accepted by name, and the
/// same peer with a name it did not ask for is refused.
///
/// This is the shape measured on 2026-09-23 on the anycast edges (leaf issued by
/// Let's Encrypt YE2, `SAN DNS:*.cloudflareclient.com`, `Verify return code: 0`),
/// reproduced with a fixture CA so it does not need a network or a live rotation.
#[test]
fn a_chain_checked_host_accepts_its_real_name_and_rejects_a_wrong_one() {
    let (ca, ca_key) = fixture_ca();
    let leaf_key = key();
    let cert = issued_leaf(MASQUE_SNI, &ca, &ca_key, &leaf_key);
    let sets = vec![pin_for(MASQUE_SNI, &cert, true, true)];

    handshake_with_name(MASQUE_SNI, MASQUE_SNI, &cert, &leaf_key, &sets, Some(&ca))
        .expect("a CA-issued leaf that chains and names the host must be accepted");

    // The same honest certificate, asked about under a name it is not valid for.
    let err = handshake_with_name(
        MASQUE_SNI,
        "not-the-edge.example.com",
        &cert,
        &leaf_key,
        &sets,
        Some(&ca),
    )
    .expect_err("a chain-verifying host must not answer to some other name");
    assert!(
        err.contains("client side"),
        "the refusal must come from verification: {err}"
    );

    // And the self-signed case the shipped file really describes: chain demanded,
    // no chain available, so the connection is refused even though the pin fits.
    let lone_key = key();
    let lone = leaf(&lone_key, -1, 365);
    let err = handshake_with_name(
        MASQUE_SNI,
        MASQUE_SNI,
        &lone,
        &lone_key,
        &[pin_for(MASQUE_SNI, &lone, true, true)],
        Some(&ca),
    )
    .expect_err("require_chain must refuse the self-signed MASQUE leaf");
    assert!(
        err.contains("client side"),
        "the refusal must come from verification: {err}"
    );
}
