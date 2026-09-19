use aether::http_proxy::{read_header, MAX_HEADER};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn test_read_header_valid() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let header = read_header(&mut socket).await.expect("read header");
        assert!(header.ends_with(b"\r\n\r\n"));
    });

    let mut client = TcpStream::connect(addr).await.expect("connect");
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
    client.write_all(req).await.expect("write req");
}

#[tokio::test]
async fn test_read_header_rejects_oversized_boundary() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        read_header(&mut socket).await
    });

    let mut client = TcpStream::connect(addr).await.expect("connect");
    // Send oversized header (17 KiB of headers without termination)
    let payload = vec![b'A'; MAX_HEADER + 1024];
    let _ = client.write_all(&payload).await;

    let res = server_task.await.expect("server join");
    assert!(res.is_err(), "Oversized header must be rejected");
    let err_str = res.unwrap_err().to_string();
    assert!(err_str.contains("HTTP header too large"), "Expected 'HTTP header too large', got: {err_str}");
}

#[tokio::test]
async fn test_read_header_rejects_late_terminator_past_16k() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        read_header(&mut socket).await
    });

    let mut client = TcpStream::connect(addr).await.expect("connect");
    // Send MAX_HEADER bytes followed by \r\n\r\n
    let mut payload = vec![b'H'; MAX_HEADER];
    payload.extend_from_slice(b"\r\n\r\n");
    let _ = client.write_all(&payload).await;

    let res = server_task.await.expect("server join");
    assert!(res.is_err(), "Terminator past MAX_HEADER must be rejected");
}
