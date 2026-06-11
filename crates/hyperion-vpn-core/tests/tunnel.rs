use hyperion_vpn_core::keys::Keypair;
use hyperion_vpn_core::mux;
use hyperion_vpn_core::noise::{accept, connect, ClientHandshake, ServerHandshake};
use hyperion_vpn_core::protocol::{
    read_connect_request, read_connect_response, write_connect_request, write_connect_response,
    ConnectRequest, ConnectResponse,
};
use hyperion_vpn_core::psk::Psk;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn full_stack_noise_plus_yamux_forward() {
    let admin = Keypair::generate();
    let server_kp = Keypair::generate();
    let psk_client = Psk::from_bytes([42u8; 32]);
    let psk_server = Psk::from_bytes([42u8; 32]);
    let allowed = [admin.public];

    let (client_io, server_io) = tokio::io::duplex(256 * 1024);

    let server_pub = server_kp.public;
    let server_side = async move {
        let hs = ServerHandshake {
            static_secret: &server_kp.secret,
            psk: &psk_server,
            allowed_admins: &allowed,
        };
        let (noise, admin_key) = accept(server_io, &hs).await.unwrap();
        assert_eq!(admin_key, admin.public);

        let (mut acceptor, driver) = mux::server(noise, mux::config());
        tokio::spawn(driver);

        let mut stream = acceptor.accept().await.unwrap();
        let req = read_connect_request(&mut stream).await.unwrap();
        assert_eq!(req, ConnectRequest { port: 22 });
        write_connect_response(&mut stream, ConnectResponse::Ok)
            .await
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        stream.write_all(&buf).await.unwrap();
        stream.shutdown().await.unwrap();
    };

    let client_side = async move {
        let hs = ClientHandshake {
            static_secret: &admin.secret,
            server_pubkey: &server_pub,
            psk: &psk_client,
        };
        let noise = connect(client_io, &hs).await.unwrap();

        let (control, driver) = mux::client(noise, mux::config());
        tokio::spawn(driver);

        let mut stream = control.open().await.unwrap();
        write_connect_request(&mut stream, &ConnectRequest { port: 22 })
            .await
            .unwrap();
        let resp = read_connect_response(&mut stream).await.unwrap();
        assert_eq!(resp, ConnectResponse::Ok);

        stream.write_all(b"ssh-handshake-bytes").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"ssh-handshake-bytes");
    };

    tokio::join!(server_side, client_side);
}
