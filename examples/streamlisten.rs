use futures::stream::Stream;
use pcap_on_demand::tokio::PacketCodec;
use pcap_on_demand::{Capture, Device, Error, Packet};
use tokio_core::reactor::Core;

pub struct SimpleDumpCodec;

impl PacketCodec for SimpleDumpCodec {
    type Type = String;

    fn decode<'p>(&mut self, packet: Packet<'p>) -> Result<Self::Type, Error> {
        Ok(format!("{:?}", packet))
    }
}

fn ma1n() -> Result<(), Error> {
    unsafe { pcap_on_demand::load_pcap_library() }?;
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let cap = Capture::from_device(Device::lookup()?)?.open()?.setnonblock()?;
    let s = cap.stream(&handle, SimpleDumpCodec {})?;
    let done = s.for_each(move |s| {
        println!("{:?}", s);
        Ok(())
    });
    core.run(done).unwrap();
    Ok(())
}

fn main() {
    match ma1n() {
        Ok(()) => (),
        Err(e) => println!("{:?}", e),
    }
}
