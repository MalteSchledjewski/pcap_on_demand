#![allow(dead_code)]
#![allow(non_camel_case_types)]

use libc::{c_char, c_int, c_uchar, c_uint, c_ushort, sockaddr, timeval, FILE};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_program {
    pub bf_len: c_uint,
    pub bf_insns: *mut bpf_insn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_insn {
    pub code: c_ushort,
    pub jt: c_uchar,
    pub jf: c_uchar,
    pub k: c_uint,
}

pub enum pcap_t {}

pub enum pcap_dumper_t {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_file_header {
    pub magic: c_uint,
    pub version_major: c_ushort,
    pub version_minor: c_ushort,
    pub thiszone: c_int,
    pub sigfigs: c_uint,
    pub snaplen: c_uint,
    pub linktype: c_uint,
}

pub type pcap_direction_t = c_uint;

pub const PCAP_D_INOUT: pcap_direction_t = 0;
pub const PCAP_D_IN: pcap_direction_t = 1;
pub const PCAP_D_OUT: pcap_direction_t = 2;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_pkthdr {
    pub ts: timeval,
    pub caplen: c_uint,
    pub len: c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_stat {
    pub ps_recv: c_uint,
    pub ps_drop: c_uint,
    pub ps_ifdrop: c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_if_t {
    pub next: *mut pcap_if_t,
    pub name: *mut c_char,
    pub description: *mut c_char,
    pub addresses: *mut pcap_addr_t,
    pub flags: c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_addr_t {
    pub next: *mut pcap_addr_t,
    pub addr: *mut sockaddr,
    pub netmask: *mut sockaddr,
    pub broadaddr: *mut sockaddr,
    pub dstaddr: *mut sockaddr,
}

pub type pcap_handler =
    Option<extern "C" fn(arg1: *mut c_uchar, arg2: *const pcap_pkthdr, arg3: *const c_uchar) -> ()>;
pub(crate) static mut pcap_create_symbol: Option<
    fn(arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t,
> = None;
pub(crate) static mut pcap_lookupdev_symbol: Option<fn(arg1: *mut c_char) -> *mut c_char> = None;
pub(crate) static mut pcap_set_snaplen_symbol: Option<fn(arg1: *mut pcap_t, arg2: c_int) -> c_int> =
    None;
pub(crate) static mut pcap_set_promisc_symbol: Option<fn(arg1: *mut pcap_t, arg2: c_int) -> c_int> =
    None;
pub(crate) static mut pcap_set_timeout_symbol: Option<fn(arg1: *mut pcap_t, arg2: c_int) -> c_int> =
    None;
pub(crate) static mut pcap_set_buffer_size_symbol: Option<
    fn(arg1: *mut pcap_t, arg2: c_int) -> c_int,
> = None;
pub(crate) static mut pcap_activate_symbol: Option<fn(arg1: *mut pcap_t) -> c_int> = None;
pub(crate) static mut pcap_open_dead_symbol: Option<fn(arg1: c_int, arg2: c_int) -> *mut pcap_t> =
    None;
#[cfg(feature = "pcap-fopen-offline-precision")]
pub(crate) static mut pcap_open_dead_with_tstamp_precision_symbol: Option<
    fn(arg1: c_int, arg2: c_int, arg3: c_uint) -> *mut pcap_t,
> = None;
#[cfg(feature = "pcap-fopen-offline-precision")]
pub(crate) static mut pcap_open_offline_with_tstamp_precision_symbol: Option<
    fn(arg1: *const c_char, arg2: c_uint, arg3: *mut c_char) -> *mut pcap_t,
> = None;
pub(crate) static mut pcap_open_offline_symbol: Option<
    fn(arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t,
> = None;
#[cfg(not(windows))]
pub(crate) static mut pcap_fopen_offline_symbol: Option<
    fn(arg1: *mut FILE, arg2: *mut c_char) -> *mut pcap_t,
> = None;
pub(crate) static mut pcap_close_symbol: Option<fn(arg1: *mut pcap_t) -> ()> = None;
pub(crate) static mut pcap_next_ex_symbol: Option<
    fn(arg1: *mut pcap_t, arg2: *mut *mut pcap_pkthdr, arg3: *mut *const c_uchar) -> c_int,
> = None;
pub(crate) static mut pcap_stats_symbol: Option<
    fn(arg1: *mut pcap_t, arg2: *mut pcap_stat) -> c_int,
> = None;
pub(crate) static mut pcap_setfilter_symbol: Option<
    fn(arg1: *mut pcap_t, arg2: *mut bpf_program) -> c_int,
> = None;
pub(crate) static mut pcap_setdirection_symbol: Option<
    fn(arg1: *mut pcap_t, arg2: pcap_direction_t) -> c_int,
> = None;
pub(crate) static mut pcap_setnonblock_symbol: Option<
    fn(arg1: *mut pcap_t, arg2: c_int, arg3: *mut c_char) -> c_int,
> = None;
pub(crate) static mut pcap_sendpacket_symbol: Option<
    fn(arg1: *mut pcap_t, arg2: *const c_uchar, arg3: c_int) -> c_int,
> = None;
pub(crate) static mut pcap_geterr_symbol: Option<fn(arg1: *mut pcap_t) -> *mut c_char> = None;
pub(crate) static mut pcap_compile_symbol: Option<
    fn(
        arg1: *mut pcap_t,
        arg2: *mut bpf_program,
        arg3: *const c_char,
        arg4: c_int,
        arg5: c_uint,
    ) -> c_int,
> = None;
pub(crate) static mut pcap_freecode_symbol: Option<fn(arg1: *mut bpf_program) -> ()> = None;
pub(crate) static mut pcap_datalink_symbol: Option<fn(arg1: *mut pcap_t) -> c_int> = None;
pub(crate) static mut pcap_list_datalinks_symbol: Option<
    fn(arg1: *mut pcap_t, arg2: *mut *mut c_int) -> c_int,
> = None;
pub(crate) static mut pcap_set_datalink_symbol: Option<
    fn(arg1: *mut pcap_t, arg2: c_int) -> c_int,
> = None;
pub(crate) static mut pcap_free_datalinks_symbol: Option<fn(arg1: *mut c_int) -> ()> = None;
pub(crate) static mut pcap_datalink_val_to_name_symbol: Option<fn(arg1: c_int) -> *const c_char> =
    None;
pub(crate) static mut pcap_datalink_val_to_description_symbol: Option<
    fn(arg1: c_int) -> *const c_char,
> = None;
pub(crate) static mut pcap_fileno_symbol: Option<fn(arg1: *mut pcap_t) -> c_int> = None;
pub(crate) static mut pcap_dump_open_symbol: Option<
    fn(arg1: *mut pcap_t, arg2: *const c_char) -> *mut pcap_dumper_t,
> = None;
#[cfg(not(windows))]
pub(crate) static mut pcap_dump_fopen_symbol: Option<
    fn(arg1: *mut pcap_t, fp: *mut FILE) -> *mut pcap_dumper_t,
> = None;
pub(crate) static mut pcap_dump_close_symbol: Option<fn(arg1: *mut pcap_dumper_t) -> ()> = None;
pub(crate) static mut pcap_dump_symbol: Option<
    fn(arg1: *mut c_uchar, arg2: *const pcap_pkthdr, arg3: *const c_uchar) -> (),
> = None;
pub(crate) static mut pcap_findalldevs_symbol: Option<
    fn(arg1: *mut *mut pcap_if_t, arg2: *mut c_char) -> c_int,
> = None;
pub(crate) static mut pcap_freealldevs_symbol: Option<fn(arg1: *mut pcap_if_t) -> ()> = None;
//pub(crate) static mut pcap_get_selectable_fd_symbol :  Option<fn(arg1: *mut pcap_t) -> c_int> = None;
#[cfg(feature = "pcap-fopen-offline-precision")]
pub(crate) static mut pcap_fopen_offline_with_tstamp_precision_symbol: Option<
    fn(arg1: *mut FILE, arg2: c_uint, arg3: *mut c_char) -> *mut pcap_t,
> = None;
#[cfg(feature = "pcap-savefile-append")]
pub(crate) static mut pcap_dump_open_append_symbol: Option<
    fn(arg1: *mut pcap_t, arg2: *const c_char) -> *mut pcap_dumper_t,
> = None;
#[cfg(not(windows))]
pub(crate) static mut pcap_set_tstamp_type_symbol: Option<
    fn(arg1: *mut pcap_t, arg2: c_int) -> c_int,
> = None;

#[cfg(not(windows))]
pub(crate) static mut pcap_set_tstamp_precision_symbol: Option<
    fn(arg1: *mut pcap_t, arg2: c_int) -> c_int,
> = None;

#[cfg(not(windows))]
pub(crate) static mut pcap_set_rfmon_symbol: Option<fn(arg1: *mut pcap_t, arg2: c_int) -> c_int> =
    None;

extern "C" {
    // pub fn pcap_lookupnet(arg1: *const c_char, arg2: *mut c_uint, arg3: *mut c_uint,
    //                       arg4: *mut c_char) -> c_int;
    // pub fn pcap_can_set_rfmon(arg1: *mut pcap_t) -> c_int;
    // pub fn pcap_set_immediate_mode(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    // pub fn pcap_get_tstamp_precision(arg1: *mut pcap_t) -> c_int;
    // pub fn pcap_list_tstamp_types(arg1: *mut pcap_t, arg2: *mut *mut c_int) -> c_int;
    // pub fn pcap_free_tstamp_types(arg1: *mut c_int) -> ();
    // pub fn pcap_tstamp_type_name_to_val(arg1: *const c_char) -> c_int;
    // pub fn pcap_tstamp_type_val_to_name(arg1: c_int) -> *const c_char;
    // pub fn pcap_tstamp_type_val_to_description(arg1: c_int) -> *const c_char;
    // pub fn pcap_open_live(arg1: *const c_char, arg2: c_int, arg3: c_int, arg4: c_int,
    //                       arg5: *mut c_char) -> *mut pcap_t;
    // pub fn pcap_loop(arg1: *mut pcap_t, arg2: c_int,
    //                  arg3: pcap_handler, arg4: *mut c_uchar) -> c_int;
    // pub fn pcap_dispatch(arg1: *mut pcap_t, arg2: c_int, arg3: pcap_handler,
    //                      arg4: *mut c_uchar)-> c_int;
    // pub fn pcap_next(arg1: *mut pcap_t, arg2: *mut pcap_pkthdr) -> *const c_uchar;
    // pub fn pcap_breakloop(arg1: *mut pcap_t) -> ();
    // pub fn pcap_getnonblock(arg1: *mut pcap_t, arg2: *mut c_char) -> c_int;
    // pub fn pcap_statustostr(arg1: c_int) -> *const c_char;
    // pub fn pcap_strerror(arg1: c_int) -> *const c_char;
    // pub fn pcap_perror(arg1: *mut pcap_t, arg2: *mut c_char) -> ();
    // pub fn pcap_compile_nopcap(arg1: c_int, arg2: c_int, arg3: *mut bpf_program,
    //                            arg4: *const c_char, arg5: c_int, arg6: c_uint) -> c_int;
    // pub fn pcap_offline_filter(arg1: *const bpf_program, arg2: *const pcap_pkthdr,
    //                            arg3: *const c_uchar) -> c_int;
    // pub fn pcap_datalink_ext(arg1: *mut pcap_t) -> c_int;
    // pub fn pcap_datalink_name_to_val(arg1: *const c_char) -> c_int;
    // pub fn pcap_snapshot(arg1: *mut pcap_t) -> c_int;
    // pub fn pcap_is_swapped(arg1: *mut pcap_t) -> c_int;
    // pub fn pcap_major_version(arg1: *mut pcap_t) -> c_int;
    // pub fn pcap_minor_version(arg1: *mut pcap_t) -> c_int;
    // pub fn pcap_file(arg1: *mut pcap_t) -> *mut FILE;
    // pub fn pcap_dump_file(arg1: *mut pcap_dumper_t) -> *mut FILE;
    // pub fn pcap_dump_ftell(arg1: *mut pcap_dumper_t) -> c_long;
    // pub fn pcap_dump_flush(arg1: *mut pcap_dumper_t) -> c_int;
    // pub fn pcap_lib_version() -> *const c_char;
    // pub fn bpf_image(arg1: *const bpf_insn, arg2: c_int) -> *mut c_char;
    // pub fn bpf_dump(arg1: *const bpf_program, arg2: c_int) -> ();
}

#[cfg(not(windows))]
extern "C" {
    // pub fn pcap_inject(arg1: *mut pcap_t, arg2: *const c_void, arg3: size_t) -> c_int;
}
