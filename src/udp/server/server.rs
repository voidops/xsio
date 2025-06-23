use std::{
    net::SocketAddr, sync::{atomic::{AtomicBool, AtomicU64, Ordering}, mpsc, Arc}, time::Duration
};
use crate::*;

pub struct XUdpServer {
    pub(crate) running: Arc<AtomicBool>,
    address: SocketAddr,
    threads: Vec<std::thread::JoinHandle<()>>,
    worker_setup_handler: Option<Box<dyn FnMut(&mut XUdpServerWorker) + Send + 'static>>,
    debug_mode: bool,
    pub(crate) processed_packets: Vec<Arc<AtomicU64>>,
    pub total_processed_packets: Arc<AtomicU64>,
}

impl XUdpServer {
    pub fn new(address: SocketAddr) -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            address,
            threads: Vec::new(),
            worker_setup_handler: None,
            debug_mode: false,
            processed_packets: Vec::new(),
            total_processed_packets: Arc::new(AtomicU64::new(0)),
        }
    }
    
    pub fn start(&mut self, num_workers: usize) -> std::io::Result<&mut Self> {
        if self.worker_setup_handler.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "No worker handler set",
            ));
        }
        dprintln!(self, "[XUdpServer] Starting at {}", self.address);
        let (ready_tx, ready_rx) = mpsc::channel();
        for id in 0..num_workers {
            if id > 0 {
                ready_rx.recv().unwrap();
            }
            let counter = Arc::new(AtomicU64::new(0));
            let running = self.running.clone();
            let address = self.address;
            let debug = self.debug_mode;
            let name = format!("XUdpServer->XUdpServerWorker-{id}");
            let mut worker = XUdpServerWorker::new(id, name.clone(), address, ready_tx.clone());
            if let Some(setup) = self.worker_setup_handler.as_mut() {
                setup(&mut worker);
            }
            worker.processed_counter = counter.clone();
            worker.running = running.clone();
            worker.debug_mode = debug;
            let thread = std::thread::Builder::new()
                .name(name.clone())
                .spawn(move || {
                    if let Err(e) = worker.run() {
                        panic!("[{name} LAST ERROR] {e}");
                    }
                })?;
            self.threads.push(thread);
            self.processed_packets.push(counter);
        }
        ready_rx.recv().unwrap();
        self.running.store(true, Ordering::Relaxed);
        // Statistics thread
        let processed_packets = self.processed_packets.clone();
        let total = self.total_processed_packets.clone();
        std::thread::Builder::new()
            .name("XUdpServer->Stats".to_string())
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                    total.store(processed_packets.iter().map(|c| c.load(Ordering::Relaxed)).sum(), Ordering::Relaxed);
                }
            })?;
        drop(ready_tx);
        Ok(self)
    }
    
    pub fn set_address(&mut self, address: SocketAddr) {
        self.address = address;
    }

    pub fn get_address(&self) -> SocketAddr {
        self.address
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn worker<WorkerSetupHandler>(&mut self, handler: WorkerSetupHandler) -> &mut Self
    where
        WorkerSetupHandler: FnMut(&mut XUdpServerWorker) + Send + 'static,{
        self.worker_setup_handler = Some(Box::new(handler));
        self
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
    
    pub fn debug(&mut self, debug: bool) -> &mut Self {
        self.debug_mode = debug;
        self
    }

    pub fn wait(&mut self, interval: Option<Duration>) {
        let iv = interval.unwrap_or(Duration::from_millis(10));
        while self.running.load(Ordering::Relaxed) {
            std::thread::sleep(iv);
        }
    }

    pub fn worker_count(&self) -> usize {
        self.threads.len()
    }

    pub fn floodtest(&'_ self, local_port: u16) -> UdpFloodTest<'_> {
        UdpFloodTest::new(&self, local_port)
    }
}
unsafe impl Sync for XUdpServer {}
