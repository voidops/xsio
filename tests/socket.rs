#[cfg(test)]
mod tests {
    use std::net::SocketAddrV4;
    use xsio::*;
    
    #[test]
    fn socket_creation_closing() {
        let sock = Socket::new(AfInet, SockDgram, IpProtoUdp).unwrap();
        sock.close().unwrap();
    }

    #[test]
    fn socket_bind_address() {
        let sock = Socket::new(AfInet, SockDgram, IpProtoUdp).unwrap();
        sock.bind("127.0.0.1:44001").unwrap();
        sock.close().unwrap();
    }

    #[test]
    fn socket_option_reuseaddr() {
        let addr = "127.0.0.1:45001";
    
        let sock1 = Socket::new(AfInet, SockStream, IpProtoTcp).unwrap();
        sock1.set_socket_option(SoReuseAddr, true).unwrap();
        sock1.bind(addr).unwrap();
    
        let sock2 = Socket::new(AfInet, SockStream, IpProtoTcp).unwrap();
        sock2.set_socket_option(SoReuseAddr, true).unwrap();
        sock2.bind(addr).unwrap();
    
        sock1.close().unwrap();
        sock2.close().unwrap();
    }
    
    #[test]
    fn socket_udp_send_to_recv_from() {
        let server_addr = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 44005);
        let test_packet = "Hello Cross-platform Sockets from UDP!";

        let server = Socket::new(AfInet, SockDgram, IpProtoUdp).unwrap();
        server.bind(server_addr).unwrap();

        let addr: SockAddrV4Buffer = server_addr.into_sockaddrv4();
        {
            let client = Socket::new(AfInet, SockDgram, IpProtoUdp).unwrap();
            client.send_to(test_packet.as_bytes(), &addr, 0).unwrap();
        }

        let mut buf = [0u8; 42];
        let mut addr_buf = SockAddrV4Buffer::new();
        let len = server.recv_from(&mut buf, &mut addr_buf, 0).unwrap();

        println!("[IpProtoUdp Test] Successfully received {}/{} bytes from {}: {:?}", len, buf.len(), addr_buf.to_socket_addr(), std::str::from_utf8(&buf).unwrap());

        assert_eq!(&buf[..len], test_packet.as_bytes());
    }

    #[test]
    fn socket_tcp_listen_accept_send_recv() {
        let server_addr = "127.0.0.1:44003";
        let test_packet = "Hello Cross-platform Sockets from TCP!";
        let server = Socket::new(AfInet, SockStream, IpProtoTcp).unwrap();
        server.set_socket_option(SoReuseAddr, true).unwrap(); // Linux does not immediately close TCP sockets due to TIME_WAIT, so we need to reuse the address in case "cargo test" is ran multiple times in succession.
        server.bind(server_addr).unwrap();
        server.listen(1024).unwrap();

        {
            let client = Socket::new(AfInet, SockStream, IpProtoTcp).unwrap();
            client.connect(server_addr).unwrap();
            client.send(test_packet.as_bytes(), 0).unwrap();
        }

        let client = server.accept().unwrap();
        let mut buf = [0u8; 42];
        let len = client.recv(&mut buf, 0).unwrap();

        let mut addr_buf = SockAddrV4Buffer::new();
        client.peer_name(&mut addr_buf).unwrap();

        println!("[IpProtoTcp Test] Successfully received {}/{} bytes from {}: {:?}", len, buf.len(), addr_buf.to_socket_addr(), std::str::from_utf8(&buf).unwrap());

        assert_eq!(&buf[..len], test_packet.as_bytes());

        client.close().unwrap();
        server.close().unwrap();
    }

    #[test]
    fn socket_option_timeout() {
        let server_addr = SocketAddrV4::new("127.0.0.1".parse().unwrap(), 44006);

        let server = Socket::new(AfInet, SockDgram, IpProtoUdp).unwrap();
        server.bind(server_addr).unwrap();
        
        server.set_socket_option(SoRecvTimeout, std::time::Duration::from_secs(1)).unwrap();

        let mut buf = [0u8; 42];
        let mut addr_buf = SockAddrV4Buffer::new();
        let result = server.recv_from(&mut buf, &mut addr_buf, 0);

        match result {
            Ok(_) => panic!("Test failed: Expected timeout but data was received"),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                println!("[IpProtoUdp Timeout Test] Successfully timed out after 1 second");
            }
            Err(e) => panic!("Unexpected error occurred: {:?}", e),
        }

        server.close().unwrap();
    }
}
