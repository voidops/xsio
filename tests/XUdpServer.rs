#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use xsio::*;
    
    #[test]
    fn xudpserver_test () {
        std::thread::sleep(std::time::Duration::from_millis(1));
        let address = "127.0.0.1:42070".parse().unwrap();
        let mut server = XUdpServer::new(address);
        server
            .worker(move |worker| {
                worker.on_ipv4(move |src, data| {
                    let addr = src.to_socket_addr_v4();
                    if addr.ip() != &Ipv4Addr::new(127, 0, 0, 1) || addr.port() != 42070 && !data.starts_with(b"Hello, world!") {
                        println!("Received packet from unexpected address: {} with data: {:?}", addr, String::from_utf8_lossy(data));
                        return;
                    }
                });
            })
        .debug(true);
        server.start(2).unwrap();
        assert!(server.is_running());
        server.floodtest(42070)
            .with_threads(8)
            .with_payload_size(64)
            .with_duration(std::time::Duration::from_secs(3))
            .with_logs(true)
            .start();
        server.stop();
        server.wait(None);
        assert!(!server.is_running());
    }
}
