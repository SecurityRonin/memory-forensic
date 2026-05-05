#![no_main]
use libfuzzer_sys::fuzz_target;
use memf_format::hiberfil::HiberfilProvider;

fuzz_target!(|data: &[u8]| {
    let _ = HiberfilProvider::from_bytes(data);
});
