use std::net::SocketAddrV4;

use crate::{AfInet, SockDgram, Socket, SocketAddrV4IntoSockAddrV4Buffer, XUdpServer};

pub struct UdpFloodTest<'a> {
    pub(crate) target_server: &'a XUdpServer,
    port: u16,
    thread_count: usize,
    payload_size: usize,
    duration: std::time::Duration,
    logging: bool,
}

impl<'a> UdpFloodTest<'a> {
    pub fn new(server: &'a XUdpServer, port: u16) -> Self {
        UdpFloodTest {
            target_server: server,
            port,
            thread_count: 1,
            payload_size: 64,
            duration: std::time::Duration::from_secs(5),
            logging: false,
        }
    }
    pub fn with_threads(&mut self, thread_count: usize) -> &mut Self {
        self.thread_count = thread_count;
        self
    }
    pub fn with_payload_size(&mut self, payload_size: usize) -> &mut Self {
        self.payload_size = payload_size;
        self
    }
    pub fn with_duration(&mut self, duration: std::time::Duration) -> &mut Self {
        self.duration = duration;
        self
    }
    pub fn with_logs(&mut self, logs: bool) -> &mut Self {
        self.logging = logs;
        self
    }
    pub fn start(&self) {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;
        const TOTAL_PACKETS: usize = 100_000_000;
        const BATCH_SIZE: usize = 1024;
        let per_thread: usize = TOTAL_PACKETS / self.thread_count;
        {
            let server_addr = self.target_server.get_address().to_string();
            let ip_string = server_addr.split(':').next().unwrap_or_else(|| {
                panic!("Invalid IP address format: {}", server_addr);
            });
            let ip_addr = ip_string.parse::<std::net::Ipv4Addr>().unwrap_or_else(|_| {
                panic!("Invalid IP address: {}", ip_string);
            });
            let sockaddr = SocketAddrV4::new(ip_addr, self.port).into_sockaddrv4();
            let global_counter = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::with_capacity(self.thread_count);

            for thread_id in 0..self.thread_count {
                let sockaddr = sockaddr.clone();
                let counter = global_counter.clone();

                handles.push(thread::spawn(move || {
                    let sock = Socket::new(AfInet, SockDgram, crate::IpProtoUdp).unwrap();
                    let mut payloads = Vec::with_capacity(BATCH_SIZE);
                    let mut batch = Vec::with_capacity(BATCH_SIZE);

                    let start = thread_id * per_thread + 1;
                    let end = start + per_thread;

                    for i in start..end {
                        let msg = format!("Hello, world! {}", i).into_bytes();
                        let ptr = msg.as_slice() as *const [u8];
                        payloads.push(msg);
                        batch.push((unsafe { &*ptr }, &sockaddr));

                        if batch.len() == BATCH_SIZE {
                            sock.sendmmsg(&batch, 0).unwrap();
                            batch.clear();
                            payloads.clear();

                            let total = counter.fetch_add(BATCH_SIZE, Ordering::Relaxed) + BATCH_SIZE;
                            if total % 1_000_000 == 0 {
                                //println!("{}, Sent {} packets", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis(), total);
                            }
                        }
                    }

                    if !batch.is_empty() {
                        sock.sendmmsg(&batch, 0).unwrap();
                        let total = counter.fetch_add(batch.len(), Ordering::Relaxed) + batch.len();
                        if total % 1_000_000 == 0 {
                            //println!("{}, Sent {} packets", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis(), total);
                        }
                    }
                }));
            }
        }
        let is_server_running = self.target_server.running.clone();
        let logging = self.logging;
        let duration = self.duration;
        let total = self.target_server.total_processed_packets.clone();

        loop {
            std::thread::sleep(std::time::Duration::from_millis(10));
            if is_server_running.load(Ordering::Relaxed) {
                break;
            }
        }
        let start = std::time::Instant::now();
        while is_server_running.load(Ordering::Relaxed) {
            if start.elapsed() >= duration {
                break;
            }
            if logging {
                println!(
                    "[UdpFloodTest] {}: Target Server received {} packets",
                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis(),
                    total.load(Ordering::Relaxed)
                );
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        if logging {
            println!(
                "[UdpFloodTest] {}: Flood test completed. Total packets server received: {}",
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis(),
                self.target_server.total_processed_packets.load(Ordering::Relaxed)
            );
        }
    }
}