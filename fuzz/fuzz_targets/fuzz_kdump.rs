#![no_main]
use libfuzzer_sys::fuzz_target;
use memf_format::kdump::KdumpProvider;

fuzz_target!(|data: &[u8]| {
    let _ = KdumpProvider::from_bytes(data);
});
