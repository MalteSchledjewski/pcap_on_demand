use pcap_on_demand;

use pcap_on_demand::*;

fn main() {
    unsafe { pcap_on_demand::load_pcap_library().unwrap() };
    {
        // open capture from default device
        let mut cap = Capture::from_device(Device::lookup().unwrap()).unwrap().open().unwrap();

        // open savefile using the capture
        let mut savefile = cap.savefile("test.pcap").unwrap();

        // get a packet from the interface
        let p = cap.next().unwrap();

        // print the packet out
        println!("packet received on network: {:?}", p);

        // write the packet to the savefile
        savefile.write(&p);
    }

    // open a new capture from the test.pcap file we wrote to above
    let mut cap = Capture::from_file("test.pcap").unwrap();

    // get a packet
    let p = cap.next().unwrap();

    // print that packet out -- it should be the same as the one we printed above
    println!("packet obtained from file: {:?}", p);
}
