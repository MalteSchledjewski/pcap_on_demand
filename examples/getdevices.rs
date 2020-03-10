use pcap_on_demand;

fn main() {
    unsafe { pcap_on_demand::load_pcap_library().unwrap() };
    // list all of the devices pcap tells us are available
    for device in pcap_on_demand::Device::list().unwrap() {
        println!("Found device! {:?}", device);

        // now you can create a Capture with this Device if you want.
        let mut cap = device.open().unwrap();

        // get a packet from this capture
        let packet = cap.next();

        println!("got a packet! {:?}", packet);
    }
}
