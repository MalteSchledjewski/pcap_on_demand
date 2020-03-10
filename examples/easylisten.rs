use pcap_on_demand;

fn main() {
    unsafe { pcap_on_demand::load_pcap_library().unwrap() };
    // get the default Device
    let mut cap = pcap_on_demand::Device::lookup().unwrap().open().unwrap();

    // get a packet and print its bytes
    println!("{:?}", cap.next());
}
