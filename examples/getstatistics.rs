use pcap_on_demand;

fn main() {
    unsafe { pcap_on_demand::load_pcap_library().unwrap() };
    // get the default Device
    let mut cap = pcap_on_demand::Device::lookup().unwrap().open().unwrap();

    // get 10 packets
    for _ in 0..10 {
        cap.next().ok();
    }
    let stats = cap.stats().unwrap();
    println!("Received: {}, dropped: {}, if_dropped: {}", stats.received, stats.dropped, stats.if_dropped);
}
