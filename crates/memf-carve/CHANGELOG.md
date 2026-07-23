# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/SecurityRonin/memory-forensic/releases/tag/memf-carve-v0.1.0) - 2026-07-23

### Added

- *(memf-carve)* GREEN — carve_dump multi-process Plane-V driver
- *(memf-carve)* GREEN — carve_process drives the sweep, forces MemoryCarve
- *(memf-carve)* GREEN — process_regions maps VADs to tagged regions
- *(memf-carve)* GREEN — VaRegionSource delegates read_at to read_virt

### Fixed

- *(deps)* use published forensic-carve 0.1 + make memf-carve publishable
