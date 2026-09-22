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

// The positive half of `require_chain` — a leaf whose chain *does* validate — is
// not asserted here on purpose: it needs a fixture CA written to a trust store,
// and the only witness that really answers the question is a live WE1-issued
// edge. That is the measured pass `masque-pins.json` records as still pending,
// so `require_chain` is false in the shipped file today.
