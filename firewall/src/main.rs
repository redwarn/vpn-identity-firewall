use nfq::{Queue, Verdict};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::error::Error;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use libc::{SIGINT, SIGTERM};
use std::sync::mpsc;

fn main() -> Result<(), Box<dyn Error>> {
    // 创建一个队列，编号为0
    let mut queue = Queue::open(0)?;

    // 设置队列的最大包长度
    queue.set_max_packet_len(0xFFFF)?;

    // 设置队列的最大队列长度
    queue.set_max_queue_len(0xFFFF)?;

    // 设置拷贝模式
    queue.set_copy_mode(nfq::CopyMode::CopyPacket)?;

    // 创建一个标志，用于控制循环
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    // 创建一个通道，用于接收信号
    let (tx, rx) = mpsc::channel();

    // 处理信号的线程
    thread::spawn(move || {
        unsafe {
            libc::signal(SIGINT, handle_signal as libc::sighandler_t);
            libc::signal(SIGTERM, handle_signal as libc::sighandler_t);
        }
        tx.send(()).unwrap();
    });

    // 主循环，处理数据包
    while running.load(Ordering::Relaxed) {
        if let Ok(msg) = queue.recv_timeout(Duration::from_millis(100)) {
            handle_packet(&msg);
            queue.set_verdict(msg.id, Verdict::Accept)?;
        }

        // 检查是否有信号
        if let Ok(_) = rx.try_recv() {
            r.store(false, Ordering::Relaxed);
        }
    }

    Ok(())
}

// 处理数据包的回调函数
fn handle_packet(msg: &nfq::Message) {
    let payload = msg.payload;

    // 解析以太网层
    if let Some(ethernet) = EthernetPacket::new(payload) {
        log::info!("Ethernet Layer: {:?}", ethernet);

        // 解析IPv4层
        if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
            log::info!("IPv4 Layer: {:?}", ipv4);

            // 解析TCP层
            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                log::info!("TCP Layer: {:?}", tcp);
                log::info!("Destination Port: {}", tcp.get_destination());
            }
        }
    }
}

// 处理信号的函数
extern "C" fn handle_signal(_: libc::c_int) {
    log::info!("Received signal, exiting...");
}