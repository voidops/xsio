#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::{atomic::{AtomicUsize, Ordering}, Arc}};
    use xsio::{server::XUdpServer, *};
    
    #[test]
    fn xudpserver_running_test () {
        //let mut server = XUdpServer::new("127.0.0.1:42060".parse().unwrap());
        //assert!(!server.is_running());
        //server.start(1).unwrap();
        //assert!(server.is_running());
    }
    
    #[test]
    fn xudpserver_test () {
        std::thread::sleep(std::time::Duration::from_millis(1));
        let total_requests = Arc::new(AtomicUsize::new(0));
        let counter = total_requests.clone();
        let address = "127.0.0.1:42070".parse().unwrap();
        let mut server = XUdpServer::new(address);
        server.worker(move |worker| {
            let mut worker_counter = 0;
            let global_counter = total_requests.clone();
            worker.set_drain_capacity(2);
            worker.on_ipv4(move |src, data| {
                let addr = src.to_socket_addr_v4();
                if addr.ip() != &Ipv4Addr::new(127, 0, 0, 1) || addr.port() != 42070 && !data.starts_with(b"Hello, world!") {
                    println!("Received packet from unexpected address: {} with data: {:?}", addr, String::from_utf8_lossy(data));
                    return;
                }
                worker_counter += 1;
                if worker_counter % 100_000 == 0 {
                    global_counter.fetch_add(worker_counter, Ordering::Relaxed);
                    worker_counter = 0;
                }
            });
        });
        server.debug(true);
        server.start(1).unwrap();
        assert!(server.is_running());
        // Send 1 million packets to the server
        server.floodtest(42070)
            .with_threads(8)
            .with_payload_size(64)
            .with_duration(std::time::Duration::from_secs(5))
            .with_logs(true)
            .start();
        server.stop();
        server.wait(None);
        assert!(!server.is_running());
    }
}
