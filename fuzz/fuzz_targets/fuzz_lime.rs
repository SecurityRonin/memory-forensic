#![no_main]
use libfuzzer_sys::fuzz_target;
use memf_format::lime::LimeProvider;

fuzz_target!(|data: &[u8]| {
    let _ = LimeProvider::from_bytes(data);
});
