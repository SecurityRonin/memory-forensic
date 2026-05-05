#![no_main]
use libfuzzer_sys::fuzz_target;
use memf_format::win_crashdump::CrashDumpProvider;

fuzz_target!(|data: &[u8]| {
    // Must never panic — only return Ok or Err.
    let _ = CrashDumpProvider::from_bytes(data);
});
