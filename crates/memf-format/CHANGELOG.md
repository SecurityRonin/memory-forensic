# Changelog

All notable changes to `memf-format` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.

## [0.3.0]

### Added

- `open_source(Box<dyn DumpReader>)` reader seam — opens a memory dump from any
  `Read + Seek + Send` byte source, decoupled from `forensic-vfs`, so a caller can
  drive it with a raw stream peeled out of a recursive archive/container detour
  (ADR 0011). `open_dump(path)` is unchanged.
- `open_source_with_raw_fallback` for callers that want the raw-page fallback path.

## [0.2.1]

- Baseline prior to the `open_source` seam (published by hand before release-plz
  adoption).
